use crate::config::Config;
use crate::harvester::plot_manager::PlotManager;
use crate::Peer;
use async_trait::async_trait;
use blst::min_pk::{PublicKey, SecretKey};
use dg_xch_utils::clients::protocols::harvester::{
    HarvesterHandshake, NewProofOfSpace, NewSignagePointHarvester, RequestSignatures,
    RespondSignatures,
};
use dg_xch_utils::clients::protocols::shared::{Handshake, CAPABILITIES, PROTOCOL_VERSION};
use dg_xch_utils::clients::protocols::ProtocolMessageTypes;
use dg_xch_utils::clients::websocket::{ChiaMessage, Client, MessageHandler, NodeType, Websocket};
use dg_xch_utils::clvm::bls_bindings::sign_prepend;
use dg_xch_utils::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_utils::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters,
};
use dg_xch_utils::keys::master_sk_to_local_sk;
use dg_xch_utils::types::blockchain::proof_of_space::{
    calculate_pos_challenge, generate_plot_public_key, passes_plot_filter, ProofOfSpace,
};
use dg_xch_utils::types::blockchain::sized_bytes::{Bytes32, UnsizedBytes};
use dg_xch_utils::types::ChiaSerialize;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use hex::encode;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, info, trace};
use rayon::prelude::*;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct HandshakeHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
    pub peer_id: Arc<Bytes32>,
}
#[async_trait]
impl MessageHandler for HandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let handshake = Handshake::from_bytes(&msg.data)?;
        //Todo Block old clients?
        if let Some(peer) = self.peers.lock().await.get_mut(&self.peer_id) {
            peer.node_type = Some(NodeType::from(handshake.node_type));
            peer.websocket
                .lock()
                .await
                .send(Message::Binary(
                    ChiaMessage::new(
                        ProtocolMessageTypes::Handshake,
                        &Handshake {
                            network_id: self.config.selected_network.clone(),
                            protocol_version: PROTOCOL_VERSION.to_string(),
                            software_version: "evg-lite-harvester".to_string(),
                            server_port: self.config.harvester.port,
                            node_type: NodeType::Harvester as u8,
                            capabilities: CAPABILITIES
                                .iter()
                                .map(|e| (e.0, e.1.to_string()))
                                .collect(),
                        },
                    )
                    .to_bytes(),
                ))
                .await
        } else {
            Err(Error::new(ErrorKind::NotFound, "Failed to find peer"))
        }
    }
}

pub struct HarvesterHandshakeHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub plot_manager: Arc<Mutex<PlotManager>>,
}
#[async_trait]
impl MessageHandler for HarvesterHandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let handshake = HarvesterHandshake::from_bytes(&msg.data)?;
        debug!("{:?}", handshake);
        self.plot_manager
            .lock()
            .await
            .set_public_keys(handshake.farmer_public_keys, handshake.pool_public_keys);
        debug!("Set Key... Loading Plots");
        self.plot_manager.lock().await.load_plots().await?;
        debug!("Done Loading Plots");
        Ok(())
    }
}

pub struct NewSignagePointHarvesterHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub plot_manager: Arc<Mutex<PlotManager>>,
    pub client: Arc<Mutex<Client>>,
}
#[async_trait]
impl MessageHandler for NewSignagePointHarvesterHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let harvester_point = NewSignagePointHarvester::from_bytes(&msg.data)?;
        trace!("{}", &harvester_point);
        let plot_manager = self.plot_manager.lock().await;
        let og_total = Arc::new(AtomicUsize::new(0));
        let pool_total = Arc::new(AtomicUsize::new(0));
        let pool_passed = Arc::new(AtomicUsize::new(0));
        let og_passed = Arc::new(AtomicUsize::new(0));
        let harvester_point = Arc::new(harvester_point);
        let constants = Arc::new(
            CONSENSUS_CONSTANTS_MAP
                .get(&self.config.selected_network)
                .cloned()
                .unwrap_or_default(),
        );
        let mut jobs = FuturesUnordered::new();
        plot_manager.plots.par_iter().for_each(|(path, plot_info)| {
            let data_arc = harvester_point.clone();
            let constants_arc = constants.clone();
            let plot_id = &plot_info.prover.header.id;
            let mut responses = vec![];
            if plot_info.pool_public_key.is_some(){
                og_total.fetch_add(1, Ordering::Relaxed);
            } else {
                pool_total.fetch_add(1, Ordering::Relaxed);
            }
            if passes_plot_filter(
                constants_arc.as_ref(),
                plot_id,
                &data_arc.challenge_hash,
                &data_arc.sp_hash,
            ) {
                if plot_info.pool_public_key.is_some(){
                    og_passed.fetch_add(1, Ordering::Relaxed);
                } else {
                    pool_passed.fetch_add(1, Ordering::Relaxed);
                }
                jobs.push(async move {
                    let sp_challenge_hash = calculate_pos_challenge(
                        plot_id,
                        &data_arc.challenge_hash,
                        &data_arc.sp_hash,
                    );

                    let qualities = plot_info
                        .prover
                        .get_qualities_for_challenge(&sp_challenge_hash)
                        .unwrap_or_default();
                    if !qualities.is_empty() {
                        trace!("Qualities Found: {}", qualities.len());
                        let mut dif = data_arc.difficulty;
                        let mut sub_slot_iters = data_arc.sub_slot_iters;
                        let mut is_partial = false;
                        if let Some(pool_contract_puzzle_hash) =
                            &plot_info.prover.header.memo.pool_contract_puzzle_hash
                        {
                            for p_dif in &data_arc.pool_difficulties {
                                if p_dif.pool_contract_puzzle_hash
                                    == *pool_contract_puzzle_hash
                                {
                                    debug!("Setting Difficulty for pool: {}", dif);
                                    dif = p_dif.difficulty;
                                    sub_slot_iters = p_dif.sub_slot_iters;
                                    is_partial = true;
                                } else {
                                    debug!("{} != {}", p_dif.pool_contract_puzzle_hash, pool_contract_puzzle_hash);
                                }
                            }
                        }
                        for (index, quality) in qualities.into_iter().enumerate() {
                            let required_iters = calculate_iterations_quality(
                                constants_arc.difficulty_constant_factor,
                                &Bytes32::from(quality.to_bytes()),
                                plot_info.prover.header.k,
                                dif,
                                &data_arc.sp_hash,
                            );
                            if let Ok(sp_interval_iters) =
                                calculate_sp_interval_iters(&constants_arc, sub_slot_iters)
                            {
                                if required_iters < sp_interval_iters {
                                    match plot_info.prover.get_full_proof(
                                        &sp_challenge_hash,
                                        index,
                                        true,
                                    ) {
                                        Ok(proof_xs) => {
                                            debug!("File: {:?} Plot ID: {plot_id}, challenge: {sp_challenge_hash}, plot_info: {:?}, Quality Str: {}, proof_xs: {}", path, plot_info, encode(quality.to_bytes()), encode(proof_xs.to_bytes())
                                            );
                                            responses.push((
                                                quality,
                                                ProofOfSpace {
                                                    challenge: sp_challenge_hash.clone(),
                                                    pool_contract_puzzle_hash: plot_info
                                                        .pool_contract_puzzle_hash
                                                        .clone(),
                                                    plot_public_key: plot_info
                                                        .plot_public_key
                                                        .clone(),
                                                    pool_public_key: plot_info
                                                        .pool_public_key
                                                        .clone(),
                                                    proof: UnsizedBytes::from(proof_xs.to_bytes()),
                                                    size: plot_info.prover.header.k,
                                                },
                                                is_partial
                                            ));
                                        }
                                        Err(e) => {
                                            debug!("Failed to read Proof: {:?}", e);
                                        }
                                    }
                                } else {
                                    trace!(
                                        "Not Enough Iterations: {} > {}",
                                        required_iters, sp_interval_iters
                                    );
                                }
                            }
                        }
                    }
                    (path.clone(), responses)
                });
            }
        });
        let proofs = AtomicU64::new(0);
        let partials = AtomicU64::new(0);
        while let Some((path, responses)) = jobs.next().await {
            for (quality, proof, is_partial) in responses {
                let _ = self
                    .client
                    .lock()
                    .await
                    .send(Message::Binary(
                        ChiaMessage::new(
                            ProtocolMessageTypes::NewProofOfSpace,
                            &NewProofOfSpace {
                                challenge_hash: harvester_point.challenge_hash.clone(),
                                sp_hash: harvester_point.sp_hash.clone(),
                                plot_identifier: encode(quality.to_bytes()) + path.as_str(),
                                proof,
                                signage_point_index: harvester_point.signage_point_index,
                            },
                        )
                        .to_bytes(),
                    ))
                    .await;
                if is_partial {
                    partials.fetch_add(1, Ordering::Relaxed);
                } else {
                    proofs.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        info!(
            "OG Passed Filter: {}/{}. Pool Passed Filter: {}/{}. Proofs Found: {}. Partials Found: {}",
            og_passed.load(Ordering::Relaxed),
            og_total.load(Ordering::Relaxed),
            pool_passed.load(Ordering::Relaxed),
            pool_total.load(Ordering::Relaxed),
            proofs.load(Ordering::Relaxed),
            partials.load(Ordering::Relaxed),
        );
        Ok(())
    }
}

pub struct RequestSignaturesHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub plot_manager: Arc<Mutex<PlotManager>>,
    pub client: Arc<Mutex<Client>>,
}
#[async_trait]
impl MessageHandler for RequestSignaturesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        debug!("{:?}", msg.msg_type);
        let request_signatures = RequestSignatures::from_bytes(&msg.data)?;
        let filename = request_signatures.plot_identifier.split_at(64).1;
        let memo = match self.plot_manager.lock().await.plots.get(filename).cloned() {
            None => {
                debug!("Failed to fine plot info for plot: {}", filename);
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("Failed to fine plot info for plot: {}", filename),
                ));
            }
            Some(info) => info.prover.header.memo.clone(),
        };
        let local_master_secret = SecretKey::from_bytes(memo.local_master_secret_key.as_ref())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?;
        let local_sk = master_sk_to_local_sk(&local_master_secret)?;
        let agg_pk = generate_plot_public_key(
            &local_sk.sk_to_pk(),
            &PublicKey::from_bytes(memo.farmer_public_key.as_ref())
                .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?,
            memo.pool_contract_puzzle_hash.is_some(),
        )?;
        let mut message_signatures = vec![];
        for msg in request_signatures.messages {
            let sig = sign_prepend(&local_sk, msg.as_ref(), &agg_pk);
            message_signatures.push((msg, sig.to_bytes().into()));
        }
        let _ = self
            .client
            .lock()
            .await
            .send(Message::Binary(
                ChiaMessage::new(
                    ProtocolMessageTypes::RespondSignatures,
                    &RespondSignatures {
                        plot_identifier: request_signatures.plot_identifier,
                        challenge_hash: request_signatures.challenge_hash,
                        sp_hash: request_signatures.sp_hash,
                        local_pk: local_sk.sk_to_pk().to_bytes().into(),
                        farmer_pk: memo.farmer_public_key,
                        message_signatures,
                    },
                )
                .to_bytes(),
            ))
            .await;
        Ok(())
    }
}

pub struct RequestPlotsHandle {
    pub id: Uuid,
}
#[async_trait]
impl MessageHandler for RequestPlotsHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        debug!("{:?}", msg.msg_type);
        Ok(())
    }
}

pub struct PlotSyncResponseHandle {
    pub id: Uuid,
}
#[async_trait]
impl MessageHandler for PlotSyncResponseHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        debug!("{:?}", msg.msg_type);
        Ok(())
    }
}
