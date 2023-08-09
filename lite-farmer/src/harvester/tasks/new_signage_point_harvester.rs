use crate::config::Config;
use crate::harvester::tasks::plot_manager::PlotManager;
use async_trait::async_trait;
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, NewSignagePointHarvester};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, Client, MessageHandler, Websocket};
use dg_xch_core::blockchain::proof_of_space::{
    calculate_pos_challenge, passes_plot_filter, ProofBytes, ProofOfSpace,
};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_core::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters,
};
use dg_xch_serialize::ChiaSerialize;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use hex::encode;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, error, info, trace};
use std::io::{Cursor, Error};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct NewSignagePointHarvesterHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub plot_manager: Arc<Mutex<PlotManager>>,
    pub client: Arc<Mutex<Client>>,
}
#[async_trait]
impl MessageHandler for NewSignagePointHarvesterHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(msg.data.clone());
        let harvester_point = NewSignagePointHarvester::from_bytes(&mut cursor)?;
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
        plot_manager.plots.iter().for_each(|(path, info)| {
            let data_arc = harvester_point.clone();
            let constants_arc = constants.clone();
            let plot_info = info.clone();
            let path = path.clone();
            let og_total = og_total.clone();
            let pool_total = pool_total.clone();
            let og_passed = og_passed.clone();
            let pool_passed = pool_passed.clone();
            let mut responses = vec![];
            jobs.push(tokio::task::spawn_blocking(move || {
                if plot_info.pool_public_key.is_some(){
                    og_total.fetch_add(1, Ordering::Relaxed);
                } else {
                    pool_total.fetch_add(1, Ordering::Relaxed);
                }
                if passes_plot_filter(
                    constants_arc.as_ref(),
                    &plot_info.prover.header.id,
                    &data_arc.challenge_hash,
                    &data_arc.sp_hash,
                ) {
                    if plot_info.pool_public_key.is_some() {
                        og_passed.fetch_add(1, Ordering::Relaxed);
                    } else {
                        pool_passed.fetch_add(1, Ordering::Relaxed);
                    }
                    let sp_challenge_hash = calculate_pos_challenge(
                        &plot_info.prover.header.id,
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
                            if let Some(p_dif) = data_arc.pool_difficulties.iter().find(|p| {
                                p.pool_contract_puzzle_hash == *pool_contract_puzzle_hash
                            }) {
                                debug!("Setting Difficulty for pool: {}", dif);
                                dif = p_dif.difficulty;
                                sub_slot_iters = p_dif.sub_slot_iters;
                                is_partial = true;
                            } else if plot_info.prover.header.memo.pool_contract_puzzle_hash.is_some() {
                                debug!("Failed to find Pool Contract Difficulties for PH: {} ", pool_contract_puzzle_hash);
                            }
                        }
                        for (index, quality) in qualities.into_iter().enumerate() {
                            let required_iters = calculate_iterations_quality(
                                constants_arc.difficulty_constant_factor,
                                &Bytes32::new(&quality.to_bytes()),
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
                                            debug!("File: {:?} Plot ID: {}, challenge: {sp_challenge_hash}, plot_info: {:?}, Quality Str: {}, proof_xs: {}", path, &plot_info.prover.header.id, plot_info.as_ref(), encode(quality.to_bytes()), encode(proof_xs.to_bytes())
                                            );
                                            responses.push((
                                                quality,
                                                ProofOfSpace {
                                                    challenge: sp_challenge_hash,
                                                    pool_contract_puzzle_hash: plot_info
                                                        .pool_contract_puzzle_hash,
                                                    plot_public_key: plot_info
                                                        .plot_public_key,
                                                    pool_public_key: plot_info
                                                        .pool_public_key,
                                                    proof: ProofBytes::from(proof_xs),
                                                    size: plot_info.prover.header.k,
                                                },
                                                is_partial
                                            ));
                                        }
                                        Err(e) => {
                                            error!("Failed to read Proof: {:?}", e);
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
                }
                (path.clone(), responses)
            }));
        });
        let proofs = AtomicU64::new(0);
        let partials = AtomicU64::new(0);
        while let Some(Ok((path, responses))) = jobs.next().await {
            for (quality, proof, is_partial) in responses {
                let _ = self
                    .client
                    .lock()
                    .await
                    .send(Message::Binary(
                        ChiaMessage::new(
                            ProtocolMessageTypes::NewProofOfSpace,
                            &NewProofOfSpace {
                                challenge_hash: harvester_point.challenge_hash,
                                sp_hash: harvester_point.sp_hash,
                                plot_identifier: encode(quality.to_bytes()) + path.as_str(),
                                proof,
                                signage_point_index: harvester_point.signage_point_index,
                            },
                            None,
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
