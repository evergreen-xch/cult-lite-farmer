use crate::farmer::{Farmer, FarmerIdentifier, FarmerPoolState};
use crate::Peer;
use async_trait::async_trait;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use blst::BLST_ERROR;
use dg_xch_utils::clients::protocols::farmer::{
    DeclareProofOfSpace, NewSignagePoint, RequestSignedValues, SignedValues,
};
use dg_xch_utils::clients::protocols::harvester::{
    HarvesterHandshake, NewProofOfSpace, NewSignagePointHarvester, PoolDifficulty,
    RequestSignatures, RespondSignatures,
};
use dg_xch_utils::clients::protocols::pool::{
    get_current_authentication_token, PoolErrorCode, PostPartialPayload, PostPartialRequest,
};
use dg_xch_utils::clients::protocols::shared::{Handshake, CAPABILITIES, PROTOCOL_VERSION};
use dg_xch_utils::clients::protocols::ProtocolMessageTypes;
use dg_xch_utils::clients::websocket::{oneshot, ChiaMessage, MessageHandler, NodeType, Websocket};
use dg_xch_utils::clvm::bls_bindings::{sign, sign_prepend, AUG_SCHEME_DST};
use dg_xch_utils::clvm::utils::hash_256;
use dg_xch_utils::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_utils::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters, POOL_SUB_SLOT_ITERS,
};
use dg_xch_utils::types::blockchain::pool_target::PoolTarget;
use dg_xch_utils::types::blockchain::proof_of_space::{
    generate_plot_public_key, generate_taproot_sk, verify_and_get_quality_string,
};
use dg_xch_utils::types::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_utils::types::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct RespondSignaturesHandle {
    pub id: Uuid,
    pub farmer: Arc<Farmer>,
}
#[async_trait]
impl MessageHandler for RespondSignaturesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let response = RespondSignatures::from_bytes(&msg.data)?;
        if let Some(sps) = self
            .farmer
            .signage_points
            .lock()
            .await
            .get(&response.sp_hash)
        {
            if sps.is_empty() {
                error!("Missing Signage Points for {}", &response.sp_hash);
            } else {
                let sp_index = sps
                    .first()
                    .expect("Sps was empty, Should have been caught above")
                    .signage_point_index;
                let mut is_sp_signatures = false;
                let mut found_sp_hash_debug = false;
                for sp_candidate in sps {
                    if response.sp_hash == response.message_signatures[0].0 {
                        found_sp_hash_debug = true;
                        if sp_candidate.reward_chain_sp == response.message_signatures[1].0 {
                            is_sp_signatures = true;
                        }
                    }
                }
                if found_sp_hash_debug {
                    assert!(is_sp_signatures);
                }
                let mut pospace = None;
                {
                    let locked = self.farmer.proofs_of_space.lock().await;
                    let proofs = locked.get(&response.sp_hash);
                    if let Some(proofs) = proofs {
                        for (plot_identifier, candidate_pospace) in proofs {
                            if *plot_identifier == response.plot_identifier {
                                pospace = Some(candidate_pospace.clone());
                            }
                        }
                    } else {
                        warn!("Failed to load farmer proofs for {}", &response.sp_hash);
                        return Ok(());
                    }
                }
                if let Some(pospace) = pospace {
                    let include_taproot = pospace.pool_contract_puzzle_hash.is_some();
                    let constants = CONSENSUS_CONSTANTS_MAP
                        .get(&self.farmer.config.lock().await.selected_network)
                        .unwrap_or(&MAINNET);
                    if let Some(computed_quality_string) = verify_and_get_quality_string(
                        &pospace,
                        constants,
                        &response.challenge_hash,
                        &response.sp_hash,
                    ) {
                        if is_sp_signatures {
                            let (challenge_chain_sp, challenge_chain_sp_harv_sig) =
                                &response.message_signatures[0];
                            let challenge_chain_sp_harv_sig =
                                challenge_chain_sp_harv_sig.try_into()?;
                            let (reward_chain_sp, reward_chain_sp_harv_sig) =
                                &response.message_signatures[1];
                            let reward_chain_sp_harv_sig = reward_chain_sp_harv_sig.try_into()?;
                            let local_pk = response.local_pk.into();
                            for sk in self.farmer.farmer_private_keys.lock().await.iter() {
                                let pk = sk.sk_to_pk();
                                if pk.to_bytes() == response.farmer_pk.to_sized_bytes() {
                                    let agg_pk =
                                        generate_plot_public_key(&local_pk, &pk, include_taproot)?;
                                    if agg_pk.to_bytes() != pospace.plot_public_key.to_sized_bytes()
                                    {
                                        warn!(
                                            "Key Mismatch {:?} != {:?}",
                                            pospace.plot_public_key, agg_pk
                                        );
                                        return Ok(());
                                    }
                                    let (taproot_share_cc_sp, taproot_share_rc_sp) =
                                        if include_taproot {
                                            let taproot_sk = generate_taproot_sk(&local_pk, &pk)?;
                                            (
                                                Some(sign_prepend(
                                                    &taproot_sk,
                                                    challenge_chain_sp.as_ref(),
                                                    &agg_pk,
                                                )),
                                                Some(sign_prepend(
                                                    &taproot_sk,
                                                    reward_chain_sp.as_ref(),
                                                    &agg_pk,
                                                )),
                                            )
                                        } else {
                                            (None, None)
                                        };
                                    let farmer_share_cc_sp =
                                        sign_prepend(sk, challenge_chain_sp.as_ref(), &agg_pk);
                                    let cc_sigs_to_agg =
                                        if let Some(taproot_share_cc_sp) = &taproot_share_cc_sp {
                                            vec![
                                                &challenge_chain_sp_harv_sig,
                                                &farmer_share_cc_sp,
                                                taproot_share_cc_sp,
                                            ]
                                        } else {
                                            vec![&challenge_chain_sp_harv_sig, &farmer_share_cc_sp]
                                        };
                                    let agg_sig_cc_sp =
                                        AggregateSignature::aggregate(&cc_sigs_to_agg, true)
                                            .map_err(|e| {
                                                Error::new(
                                                    ErrorKind::InvalidInput,
                                                    format!("{:?}", e),
                                                )
                                            })?;
                                    if agg_sig_cc_sp.to_signature().verify(
                                        true,
                                        challenge_chain_sp.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate cc signature {:?}",
                                            agg_sig_cc_sp.to_signature()
                                        );
                                        return Ok(());
                                    }

                                    let farmer_share_rc_sp =
                                        sign_prepend(sk, reward_chain_sp.as_ref(), &agg_pk);
                                    let rc_sigs_to_agg =
                                        if let Some(taproot_share_rc_sp) = &taproot_share_rc_sp {
                                            vec![
                                                &reward_chain_sp_harv_sig,
                                                &farmer_share_rc_sp,
                                                taproot_share_rc_sp,
                                            ]
                                        } else {
                                            vec![&reward_chain_sp_harv_sig, &farmer_share_rc_sp]
                                        };
                                    let agg_sig_rc_sp =
                                        AggregateSignature::aggregate(&rc_sigs_to_agg, true)
                                            .map_err(|e| {
                                                Error::new(
                                                    ErrorKind::InvalidInput,
                                                    format!("{:?}", e),
                                                )
                                            })?;
                                    if agg_sig_rc_sp.to_signature().verify(
                                        true,
                                        reward_chain_sp.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate rc signature {:?}",
                                            agg_sig_rc_sp.to_signature()
                                        );
                                        return Ok(());
                                    }
                                    let (pool_target, pool_target_signature) = if let Some(
                                        pool_public_key,
                                    ) =
                                        &pospace.pool_public_key
                                    {
                                        if let Some(sk) = self
                                            .farmer
                                            .pool_public_keys
                                            .lock()
                                            .await
                                            .get(pool_public_key)
                                        {
                                            let pool_target = PoolTarget {
                                                max_height: 0,
                                                puzzle_hash: self
                                                    .farmer
                                                    .pool_target
                                                    .as_ref()
                                                    .clone(),
                                            };
                                            let pool_target_signature =
                                                sign(sk, &pool_target.to_bytes());
                                            (Some(pool_target), Some(pool_target_signature))
                                        } else {
                                            error!("Don't have the private key for the pool key used by harvester: {pool_public_key}");
                                            return Ok(());
                                        }
                                    } else {
                                        (None, None)
                                    };
                                    let request = DeclareProofOfSpace {
                                        challenge_hash: response.challenge_hash.clone(),
                                        challenge_chain_sp: challenge_chain_sp.clone(),
                                        signage_point_index: sp_index,
                                        reward_chain_sp: reward_chain_sp.clone(),
                                        proof_of_space: pospace.clone(),
                                        challenge_chain_sp_signature: agg_sig_cc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        reward_chain_sp_signature: agg_sig_rc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        farmer_puzzle_hash: self
                                            .farmer
                                            .farmer_target
                                            .as_ref()
                                            .clone(),
                                        pool_target,
                                        pool_signature: pool_target_signature
                                            .map(|s| s.to_bytes().into()),
                                    };
                                    if let Some(client) =
                                        self.farmer.full_node_client.lock().await.as_mut()
                                    {
                                        let _ = client
                                            .client
                                            .lock()
                                            .await
                                            .send(Message::Binary(
                                                ChiaMessage::new(
                                                    ProtocolMessageTypes::DeclareProofOfSpace,
                                                    &request,
                                                )
                                                .to_bytes(),
                                            ))
                                            .await;
                                        info!("Declaring Proof of Space: {:?}", request);
                                    } else {
                                        error!(
                                            "Failed to declare Proof of Space: {:?} No Client",
                                            request
                                        );
                                    }
                                }
                            }
                        } else {
                            let (foliage_block_data_hash, foliage_sig_harvester) =
                                &response.message_signatures[0];
                            let foliage_sig_harvester = foliage_sig_harvester.try_into()?;
                            let (
                                foliage_transaction_block_hash,
                                foliage_transaction_block_sig_harvester,
                            ) = &response.message_signatures[1];
                            let foliage_transaction_block_sig_harvester =
                                foliage_transaction_block_sig_harvester.try_into()?;
                            let local_pk = response.local_pk.into();
                            for sk in self.farmer.farmer_private_keys.lock().await.iter() {
                                let pk = sk.sk_to_pk();
                                if pk.to_bytes() == response.farmer_pk.to_sized_bytes() {
                                    let agg_pk =
                                        generate_plot_public_key(&local_pk, &pk, include_taproot)?;
                                    let (
                                        foliage_sig_taproot,
                                        foliage_transaction_block_sig_taproot,
                                    ) = if include_taproot {
                                        let taproot_sk = generate_taproot_sk(&local_pk, &pk)?;
                                        (
                                            Some(sign_prepend(
                                                &taproot_sk,
                                                foliage_block_data_hash.as_ref(),
                                                &agg_pk,
                                            )),
                                            Some(sign_prepend(
                                                &taproot_sk,
                                                foliage_transaction_block_hash.as_ref(),
                                                &agg_pk,
                                            )),
                                        )
                                    } else {
                                        (None, None)
                                    };
                                    let foliage_sig_farmer =
                                        sign_prepend(sk, foliage_block_data_hash.as_ref(), &agg_pk);
                                    let foliage_transaction_block_sig_farmer = sign_prepend(
                                        sk,
                                        foliage_transaction_block_hash.as_ref(),
                                        &agg_pk,
                                    );
                                    let foliage_sigs_to_agg =
                                        if let Some(foliage_sig_taproot) = &foliage_sig_taproot {
                                            vec![
                                                &foliage_sig_harvester,
                                                &foliage_sig_farmer,
                                                foliage_sig_taproot,
                                            ]
                                        } else {
                                            vec![&foliage_sig_harvester, &foliage_sig_farmer]
                                        };
                                    let foliage_agg_sig =
                                        AggregateSignature::aggregate(&foliage_sigs_to_agg, true)
                                            .map_err(|e| {
                                            Error::new(ErrorKind::InvalidInput, format!("{:?}", e))
                                        })?;

                                    let foliage_block_sigs_to_agg =
                                        if let Some(foliage_transaction_block_sig_taproot) =
                                            &foliage_transaction_block_sig_taproot
                                        {
                                            vec![
                                                &foliage_transaction_block_sig_harvester,
                                                &foliage_transaction_block_sig_farmer,
                                                foliage_transaction_block_sig_taproot,
                                            ]
                                        } else {
                                            vec![
                                                &foliage_transaction_block_sig_harvester,
                                                &foliage_transaction_block_sig_farmer,
                                            ]
                                        };
                                    let foliage_block_agg_sig = AggregateSignature::aggregate(
                                        &foliage_block_sigs_to_agg,
                                        true,
                                    )
                                    .map_err(|e| {
                                        Error::new(ErrorKind::InvalidInput, format!("{:?}", e))
                                    })?;
                                    if foliage_agg_sig.to_signature().verify(
                                        true,
                                        foliage_block_data_hash.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate foliage signature {:?}",
                                            foliage_agg_sig.to_signature()
                                        );
                                        return Ok(());
                                    }
                                    if foliage_block_agg_sig.to_signature().verify(
                                        true,
                                        foliage_transaction_block_hash.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate foliage_block signature {:?}",
                                            foliage_block_agg_sig.to_signature()
                                        );
                                        return Ok(());
                                    }
                                    let request = SignedValues {
                                        quality_string: computed_quality_string.clone(),
                                        foliage_block_data_signature: foliage_agg_sig
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        foliage_transaction_block_signature: foliage_block_agg_sig
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                    };

                                    if let Some(client) =
                                        self.farmer.full_node_client.lock().await.as_mut()
                                    {
                                        let _ = client
                                            .client
                                            .lock()
                                            .await
                                            .send(Message::Binary(
                                                ChiaMessage::new(
                                                    ProtocolMessageTypes::SignedValues,
                                                    &request,
                                                )
                                                .to_bytes(),
                                            ))
                                            .await;
                                        info!("Sending Signed Values: {:?}", request);
                                    } else {
                                        error!(
                                            "Failed to Sending Signed Values: {:?} No Client",
                                            request
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        warn!("Have invalid PoSpace {:?}", pospace);
                        return Ok(());
                    }
                } else {
                    debug!("Failed to find Proof for {}", &response.sp_hash);
                    return Ok(());
                }
            }
        } else {
            error!("Do not have challenge hash {}", &response.challenge_hash);
        }
        Ok(())
    }
}

pub struct HandshakeHandle {
    pub id: Uuid,
    pub farmer: Arc<Farmer>,
    pub peer_id: Bytes32,
}
#[async_trait]
impl MessageHandler for HandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let handshake = Handshake::from_bytes(&msg.data)?;
        if let Some(peer) = self.farmer.peers.lock().await.get_mut(&self.peer_id) {
            let (network_id, server_port) = {
                let cfg = self.farmer.config.lock().await;
                (cfg.selected_network.clone(), cfg.farmer.port)
            };
            peer.node_type = Some(NodeType::from(handshake.node_type));
            peer.websocket
                .lock()
                .await
                .send(Message::Binary(
                    ChiaMessage::new(
                        ProtocolMessageTypes::Handshake,
                        &Handshake {
                            network_id,
                            protocol_version: PROTOCOL_VERSION.to_string(),
                            software_version: "evg-lite-farmer".to_string(),
                            server_port,
                            node_type: NodeType::Farmer as u8,
                            capabilities: CAPABILITIES
                                .iter()
                                .map(|e| (e.0, e.1.to_string()))
                                .collect(),
                        },
                    )
                    .to_bytes(),
                ))
                .await
                .unwrap_or_default();
            if NodeType::Harvester as u8 == handshake.node_type {
                peer.websocket
                    .lock()
                    .await
                    .send(Message::Binary(
                        ChiaMessage::new(
                            ProtocolMessageTypes::HarvesterHandshake,
                            &HarvesterHandshake {
                                farmer_public_keys: self
                                    .farmer
                                    .farmer_private_keys
                                    .lock()
                                    .await
                                    .iter()
                                    .map(|k| k.sk_to_pk().to_bytes().into())
                                    .collect(),
                                pool_public_keys: self
                                    .farmer
                                    .pool_public_keys
                                    .lock()
                                    .await
                                    .keys()
                                    .cloned()
                                    .collect(),
                            },
                        )
                        .to_bytes(),
                    ))
                    .await
                    .unwrap_or_default();
            }
        }
        Ok(())
    }
}

pub struct NewProofOfSpaceHandle {
    pub id: Uuid,
    pub farmer: Arc<Farmer>,
    pub peer_id: Arc<Bytes32>,
}
#[async_trait]
impl MessageHandler for NewProofOfSpaceHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let exists;
        {
            exists = self.farmer.peers.lock().await.get(&self.peer_id).is_some();
        }
        if exists {
            let new_pos = NewProofOfSpace::from_bytes(&msg.data)?;
            if let Some(sps) = self
                .farmer
                .signage_points
                .lock()
                .await
                .get(&new_pos.sp_hash)
            {
                let constants = CONSENSUS_CONSTANTS_MAP
                    .get(&self.farmer.config.lock().await.selected_network)
                    .cloned()
                    .unwrap_or_default();
                for sp in sps {
                    if let Some(qs) = verify_and_get_quality_string(
                        &new_pos.proof,
                        &constants,
                        &new_pos.challenge_hash,
                        &new_pos.sp_hash,
                    ) {
                        let required_iters = calculate_iterations_quality(
                            constants.difficulty_constant_factor,
                            &qs,
                            new_pos.proof.size,
                            sp.difficulty,
                            &new_pos.sp_hash,
                        );
                        if required_iters
                            < calculate_sp_interval_iters(&constants, sp.sub_slot_iters)?
                        {
                            let request = RequestSignatures {
                                plot_identifier: new_pos.plot_identifier.clone(),
                                challenge_hash: new_pos.challenge_hash.clone(),
                                sp_hash: new_pos.sp_hash.clone(),
                                messages: vec![
                                    sp.challenge_chain_sp.clone(),
                                    sp.reward_chain_sp.clone(),
                                ],
                            };
                            let mut farmer_pos = self.farmer.proofs_of_space.lock().await;
                            if farmer_pos.get(&new_pos.sp_hash).is_none() {
                                farmer_pos.insert(new_pos.sp_hash.clone(), vec![]);
                            }
                            farmer_pos
                                .get_mut(&new_pos.sp_hash)
                                .expect("Should not happen, item created above")
                                .push((new_pos.plot_identifier.clone(), new_pos.proof.clone()));
                            self.farmer
                                .cache_time
                                .lock()
                                .await
                                .insert(new_pos.sp_hash.clone(), Instant::now());
                            self.farmer.quality_to_identifiers.lock().await.insert(
                                qs.clone(),
                                FarmerIdentifier {
                                    plot_identifier: new_pos.plot_identifier.clone(),
                                    challenge_hash: new_pos.challenge_hash.clone(),
                                    sp_hash: new_pos.sp_hash.clone(),
                                    peer_node_id: self.peer_id.as_ref().clone(),
                                },
                            );
                            self.farmer
                                .cache_time
                                .lock()
                                .await
                                .insert(qs.clone(), Instant::now());
                            if let Some(p) = self.farmer.peers.lock().await.get_mut(&self.peer_id) {
                                let _ = p
                                    .websocket
                                    .lock()
                                    .await
                                    .send(Message::Binary(
                                        ChiaMessage::new(
                                            ProtocolMessageTypes::RequestSignatures,
                                            &request,
                                        )
                                        .to_bytes(),
                                    ))
                                    .await;
                            }
                        }
                        if let Some(p2_singleton_puzzle_hash) =
                            &new_pos.proof.pool_contract_puzzle_hash
                        {
                            if let Some(pool_state) = self
                                .farmer
                                .pool_state
                                .lock()
                                .await
                                .get_mut(p2_singleton_puzzle_hash)
                            {
                                if let Some(pool_config) = pool_state.pool_config.clone() {
                                    let (pool_url, launcher_id) = (
                                        pool_config.pool_url.as_str(),
                                        pool_config.launcher_id.clone(),
                                    );
                                    if pool_url.is_empty() {
                                        return Ok(());
                                    }
                                    if let Some(pool_dif) = pool_state.current_difficulty {
                                        let required_iters = calculate_iterations_quality(
                                            constants.difficulty_constant_factor,
                                            &qs,
                                            new_pos.proof.size,
                                            pool_dif,
                                            &new_pos.sp_hash,
                                        );
                                        if required_iters
                                            >= calculate_sp_interval_iters(
                                                &constants,
                                                constants.pool_sub_slot_iters,
                                            )?
                                        {
                                            info!(
                                                "Proof of space not good enough for pool {}: {:?}",
                                                pool_url, pool_state.current_difficulty
                                            );
                                            return Ok(());
                                        }
                                        if let Some(auth_token_timeout) =
                                            pool_state.authentication_token_timeout
                                        {
                                            let is_eos = new_pos.signage_point_index == 0;
                                            let payload = PostPartialPayload {
                                                launcher_id: launcher_id.clone(),
                                                authentication_token:
                                                    get_current_authentication_token(
                                                        auth_token_timeout,
                                                    ),
                                                proof_of_space: new_pos.proof.clone(),
                                                sp_hash: new_pos.sp_hash.clone(),
                                                end_of_sub_slot: is_eos,
                                                harvester_id: self.peer_id.as_ref().clone(),
                                            };
                                            let to_sign = hash_256(payload.to_bytes());
                                            let request = RequestSignatures {
                                                plot_identifier: new_pos.plot_identifier.clone(),
                                                challenge_hash: new_pos.challenge_hash.clone(),
                                                sp_hash: new_pos.sp_hash.clone(),
                                                messages: vec![Bytes32::new(to_sign.clone())],
                                            };
                                            if let Some(peer) =
                                                self.farmer.peers.lock().await.get(&self.peer_id)
                                            {
                                                let respond_sigs: RespondSignatures = oneshot(
                                                    peer.websocket.clone(),
                                                    ChiaMessage::new(
                                                        ProtocolMessageTypes::RequestSignatures,
                                                        &request,
                                                    ),
                                                    Some(ProtocolMessageTypes::RespondSignatures),
                                                )
                                                .await?;
                                                let response_msg_sig = if let Some(f) =
                                                    respond_sigs.message_signatures.first()
                                                {
                                                    Signature::from_bytes(&f.1.to_sized_bytes())
                                                        .map_err(|e| {
                                                            Error::new(
                                                                ErrorKind::InvalidInput,
                                                                format!("{:?}", e),
                                                            )
                                                        })?
                                                } else {
                                                    return Err(Error::new(
                                                        ErrorKind::InvalidInput,
                                                        "No Signature in Response",
                                                    ));
                                                };
                                                let mut plot_sig = None;
                                                let local_pk = PublicKey::from_bytes(
                                                    &respond_sigs.local_pk.to_sized_bytes(),
                                                )
                                                .map_err(|e| {
                                                    Error::new(
                                                        ErrorKind::InvalidInput,
                                                        format!("{:?}", e),
                                                    )
                                                })?;
                                                for sk in self
                                                    .farmer
                                                    .farmer_private_keys
                                                    .lock()
                                                    .await
                                                    .iter()
                                                {
                                                    let pk = sk.sk_to_pk();
                                                    if pk.to_bytes()
                                                        == respond_sigs.farmer_pk.to_sized_bytes()
                                                    {
                                                        let agg_pk = generate_plot_public_key(
                                                            &local_pk, &pk, true,
                                                        )?;
                                                        if agg_pk.to_bytes()
                                                            != new_pos
                                                                .proof
                                                                .plot_public_key
                                                                .to_sized_bytes()
                                                        {
                                                            return Err(Error::new(
                                                                ErrorKind::InvalidInput,
                                                                "Key Mismatch",
                                                            ));
                                                        }
                                                        let sig_farmer =
                                                            sign_prepend(sk, &to_sign, &agg_pk);
                                                        let taproot_sk =
                                                            generate_taproot_sk(&local_pk, &pk)?;
                                                        let taproot_sig = sign_prepend(
                                                            &taproot_sk,
                                                            &to_sign,
                                                            &agg_pk,
                                                        );

                                                        let p_sig = AggregateSignature::aggregate(
                                                            &[
                                                                &sig_farmer,
                                                                &response_msg_sig,
                                                                &taproot_sig,
                                                            ],
                                                            true,
                                                        )
                                                        .map_err(|e| {
                                                            Error::new(
                                                                ErrorKind::InvalidInput,
                                                                format!("{:?}", e),
                                                            )
                                                        })?;
                                                        if p_sig.to_signature().verify(
                                                            true,
                                                            to_sign.as_ref(),
                                                            AUG_SCHEME_DST,
                                                            &agg_pk.to_bytes(),
                                                            &agg_pk,
                                                            true,
                                                        ) != BLST_ERROR::BLST_SUCCESS
                                                        {
                                                            warn!(
                                                            "Failed to validate partial signature {:?}",
                                                            p_sig.to_signature()
                                                        );
                                                            continue;
                                                        }
                                                        plot_sig = Some(p_sig);
                                                    }
                                                }
                                                if let Some(auth_key) = self
                                                    .farmer
                                                    .auth_secret_keys
                                                    .lock()
                                                    .await
                                                    .get(&pool_config.owner_public_key)
                                                {
                                                    let auth_sig = sign(auth_key, &to_sign);
                                                    if let Some(plot_sig) = plot_sig {
                                                        let agg_sig =
                                                            AggregateSignature::aggregate(
                                                                &[
                                                                    &plot_sig.to_signature(),
                                                                    &auth_sig,
                                                                ],
                                                                true,
                                                            )
                                                            .map_err(|e| {
                                                                Error::new(
                                                                    ErrorKind::InvalidInput,
                                                                    format!("{:?}", e),
                                                                )
                                                            })?;
                                                        let post_request = PostPartialRequest {
                                                            payload,
                                                            aggregate_signature: agg_sig
                                                                .to_signature()
                                                                .to_bytes()
                                                                .into(),
                                                        };
                                                        debug!(
                                                            "Submitting partial for {} to {}",
                                                            post_request
                                                                .payload
                                                                .launcher_id
                                                                .to_string(),
                                                            pool_url
                                                        );
                                                        pool_state.points_found_since_start +=
                                                            pool_state
                                                                .current_difficulty
                                                                .unwrap_or_default();
                                                        pool_state.points_found_24h.push((
                                                            Instant::now(),
                                                            pool_state
                                                                .current_difficulty
                                                                .unwrap_or_default(),
                                                        ));
                                                        debug!(
                                                            "POST /partial request {:?}",
                                                            &post_request
                                                        );
                                                        match self
                                                            .farmer
                                                            .pool_client
                                                            .post_partial(pool_url, post_request)
                                                            .await
                                                        {
                                                            Ok(resp) => {
                                                                pool_state
                                                                    .points_acknowledged_since_start +=
                                                                    resp.new_difficulty;
                                                                pool_state.current_points +=
                                                                    resp.new_difficulty;
                                                                pool_state
                                                                    .points_acknowledged_24h
                                                                    .push((
                                                                        Instant::now(),
                                                                        pool_state
                                                                            .current_difficulty
                                                                            .unwrap_or_default(),
                                                                    ));
                                                                pool_state.current_difficulty =
                                                                    Some(resp.new_difficulty);
                                                                info!(
                                                                    "New Pool Difficulty: {:?} ",
                                                                    pool_state.current_difficulty
                                                                );
                                                                info!(
                                                                    "Current Points: {:?} ",
                                                                    pool_state.current_points
                                                                );
                                                            }
                                                            Err(e) => {
                                                                error!("Error in pooling: {:?}", e);
                                                                pool_state.pool_errors_24h.push((
                                                                    Instant::now(),
                                                                    format!("{:?}", e),
                                                                ));
                                                                if e.error_code
                                                                    == PoolErrorCode::ProofNotGoodEnough as u8
                                                                {
                                                                    error!("Partial not good enough, forcing pool farmer update to get our current difficulty.");
                                                                    pool_state.next_farmer_update = Instant::now();
                                                                    let _ = self
                                                                        .farmer
                                                                        .update_pool_farmer_info(
                                                                            pool_state,
                                                                            &pool_config,
                                                                            auth_token_timeout,
                                                                            auth_key,
                                                                        )
                                                                        .await;
                                                                }
                                                                return Ok(());
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    warn!("No authentication sk for {p2_singleton_puzzle_hash}");
                                                    return Ok(());
                                                }
                                            }
                                        } else {
                                            warn!("No pool specific authentication_token_timeout has been set for {p2_singleton_puzzle_hash}, check communication with the pool.");
                                            return Ok(());
                                        }
                                    } else {
                                        warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this partial to {}.", pool_url);
                                        return Ok(());
                                    }
                                } else {
                                    warn!(" No Pool Config for {p2_singleton_puzzle_hash}");
                                    return Ok(());
                                }
                            } else {
                                warn!("Did not find pool info for {p2_singleton_puzzle_hash}");
                                return Ok(());
                            }
                        } else {
                            debug!("Not a pooling proof of space");
                        }
                    } else {
                        warn!("Invalid proof of space {:?}", new_pos);
                    }
                }
            } else {
                warn!(
                    "Received response for a signage point that we do not have {}",
                    &new_pos.sp_hash
                );
            }
        }
        Ok(())
    }
}

pub struct NewSignagePointHandle {
    pub id: Uuid,
    pub peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
    pub pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
}
#[async_trait]
impl MessageHandler for NewSignagePointHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let sp = NewSignagePoint::from_bytes(&msg.data)?;
        let mut pool_difficulties = vec![];
        for (p2_singleton_puzzle_hash, pool_dict) in self.pool_state.lock().await.iter() {
            if let Some(config) = &pool_dict.pool_config {
                if config.pool_url.is_empty() {
                    //Self Pooling
                    continue;
                }
                if let Some(difficulty) = pool_dict.current_difficulty {
                    debug!(
                        "Setting Difficulty for pool: {:?}",
                        pool_dict.current_difficulty
                    );
                    pool_difficulties.push(PoolDifficulty {
                        difficulty,
                        sub_slot_iters: POOL_SUB_SLOT_ITERS,
                        pool_contract_puzzle_hash: p2_singleton_puzzle_hash.clone(),
                    })
                } else {
                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this signage point, pool: {}", &config.pool_url);
                    continue;
                }
            }
        }
        let harvester_point = NewSignagePointHarvester {
            challenge_hash: sp.challenge_hash.clone(),
            difficulty: sp.difficulty,
            sub_slot_iters: sp.sub_slot_iters,
            signage_point_index: sp.signage_point_index,
            sp_hash: sp.challenge_chain_sp.clone(),
            pool_difficulties,
        };
        let msg = Message::Binary(
            ChiaMessage::new(
                ProtocolMessageTypes::NewSignagePointHarvester,
                &harvester_point,
            )
            .to_bytes(),
        );
        for (_, per) in self.peers.lock().await.iter_mut().filter(|(_, p)| {
            p.node_type.as_ref().unwrap_or(&NodeType::Unknown) == &NodeType::Harvester
        }) {
            let _ = per.websocket.lock().await.send(msg.clone()).await;
        }
        {
            //Lock Scope
            let mut signage_points = self.signage_points.lock().await;
            if signage_points.get(&sp.challenge_chain_sp).is_none() {
                signage_points.insert(sp.challenge_chain_sp.clone(), vec![]);
            }
        }
        let now = Instant::now();
        self.pool_state.lock().await.iter_mut().for_each(|(_, s)| {
            s.points_acknowledged_24h
                .retain(|(i, _)| now.duration_since(*i).as_secs() <= 60 * 60 * 24);
            s.points_found_24h
                .retain(|(i, _)| now.duration_since(*i).as_secs() <= 60 * 60 * 24);
        });
        if let Some(sps) = self
            .signage_points
            .lock()
            .await
            .get_mut(&sp.challenge_chain_sp)
        {
            sps.push(sp.clone());
        }
        self.cache_time
            .lock()
            .await
            .insert(sp.challenge_chain_sp, Instant::now());
        Ok(())
    }
}

pub struct RequestSignedValuesHandle {
    pub id: Uuid,
    pub quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
    pub peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
}
#[async_trait]
impl MessageHandler for RequestSignedValuesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let request = RequestSignedValues::from_bytes(&msg.data)?;
        if let Some(identifier) = self
            .quality_to_identifiers
            .lock()
            .await
            .get(&request.quality_string)
        {
            if let Some(peer) = self.peers.lock().await.get_mut(&identifier.peer_node_id) {
                let _ = peer
                    .websocket
                    .lock()
                    .await
                    .send(Message::Binary(
                        ChiaMessage::new(
                            ProtocolMessageTypes::RequestSignatures,
                            &RequestSignatures {
                                plot_identifier: identifier.plot_identifier.clone(),
                                challenge_hash: identifier.challenge_hash.clone(),
                                sp_hash: identifier.sp_hash.clone(),
                                messages: vec![
                                    request.foliage_block_data_hash.clone(),
                                    request.foliage_transaction_block_hash.clone(),
                                ],
                            },
                        )
                        .to_bytes(),
                    ))
                    .await;
            }
            Ok(())
        } else {
            error!("Do not have quality {}", &request.quality_string);
            Err(Error::new(
                ErrorKind::NotFound,
                format!("Do not have quality {}", &request.quality_string),
            ))
        }
    }
}
