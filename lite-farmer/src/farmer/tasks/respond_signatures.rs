use crate::farmer::{Farmer, FarmerState};
use async_trait::async_trait;
use blst::min_pk::AggregateSignature;
use blst::BLST_ERROR;
use dg_xch_clients::protocols::farmer::{DeclareProofOfSpace, SignedValues};
use dg_xch_clients::protocols::harvester::RespondSignatures;
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler, Websocket};
use dg_xch_core::blockchain::pool_target::PoolTarget;
use dg_xch_core::blockchain::proof_of_space::{generate_plot_public_key, generate_taproot_sk};
use dg_xch_core::clvm::bls_bindings::{sign, sign_prepend, AUG_SCHEME_DST};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, error, info, warn};
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct RespondSignaturesHandle {
    pub id: Uuid,
    pub farmer: Arc<Farmer>,
    pub farmer_state: Arc<Mutex<FarmerState>>,
}
#[async_trait]
impl MessageHandler for RespondSignaturesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let response = RespondSignatures::from_bytes(&mut cursor)?;
        if let Some(sps) = self
            .farmer
            .signage_points
            .lock()
            .await
            .get(&response.sp_hash)
        {
            if sps.is_empty() {
                error!("Missing Signage Points for {}", &response.sp_hash);
                {
                    self.farmer_state
                        .lock()
                        .await
                        .recent_errors
                        .add(format!("Missing Signage Points for {}", &response.sp_hash));
                }
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
                        debug!("Failed to load farmer proofs for {}", &response.sp_hash);
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
                                if pk.to_bytes() == *response.farmer_pk.to_sized_bytes() {
                                    let agg_pk =
                                        generate_plot_public_key(&local_pk, &pk, include_taproot)?;
                                    if agg_pk.to_bytes()
                                        != *pospace.plot_public_key.to_sized_bytes()
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
                                                puzzle_hash: *self.farmer.pool_target,
                                            };
                                            let pool_target_signature =
                                                sign(sk, &pool_target.to_bytes());
                                            (Some(pool_target), Some(pool_target_signature))
                                        } else {
                                            error!("Don't have the private key for the pool key used by harvester: {pool_public_key}");
                                            {
                                                self.farmer_state.lock().await.recent_errors.add(format!("Don't have the private key for the pool key used by harvester: {pool_public_key}"));
                                            }
                                            return Ok(());
                                        }
                                    } else {
                                        (None, None)
                                    };
                                    let request = DeclareProofOfSpace {
                                        challenge_hash: response.challenge_hash,
                                        challenge_chain_sp: *challenge_chain_sp,
                                        signage_point_index: sp_index,
                                        reward_chain_sp: *reward_chain_sp,
                                        proof_of_space: pospace.clone(),
                                        challenge_chain_sp_signature: agg_sig_cc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        reward_chain_sp_signature: agg_sig_rc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        farmer_puzzle_hash: *self.farmer.farmer_target,
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
                                                    None,
                                                )
                                                .to_bytes(),
                                            ))
                                            .await;
                                        info!("Declaring Proof of Space: {:?}", request);
                                        info!(
                                            "
                             +&-
                           _.-^-._     .--.
   Proof Found!          .-'   _   '-. |__|
                       /     |_|     \\|  |
                      /               \\  |
                     /|     _____     |\\ |
                      |    |==|==|    |  |
  |---|---|---|---|---|    |--|--|    |  |
  |---|---|---|---|---|    |==|==|    |  |
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^"
                                        );
                                    } else {
                                        error!(
                                            "Failed to declare Proof of Space: {:?} No Client",
                                            request
                                        );
                                        {
                                            self.farmer_state.lock().await.recent_errors.add(
                                                format!(
                                                "Failed to declare Proof of Space: {:?} No Client",
                                                request
                                            ),
                                            );
                                        }
                                    }
                                }
                            }
                        } else if response.message_signatures.len() > 1 {
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
                                if pk.to_bytes() == *response.farmer_pk.to_sized_bytes() {
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
                                        quality_string: computed_quality_string,
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
                                                    None,
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
                                        {
                                            self.farmer_state.lock().await.recent_errors.add(
                                                format!(
                                                "Failed to Sending Signed Values: {:?} No Client",
                                                request
                                            ),
                                            );
                                        }
                                    }
                                }
                            }
                        } else if msg.id.is_some() {
                            debug!("Detected Partial Signatures Request {:?}", pospace);
                            return Ok(());
                        } else {
                            warn!("Detected Possible invalid PoSpace {:?}", pospace);
                            return Ok(());
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
            {
                self.farmer_state.lock().await.recent_errors.add(format!(
                    "Do not have challenge hash {}",
                    &response.challenge_hash
                ));
            }
        }
        Ok(())
    }
}
