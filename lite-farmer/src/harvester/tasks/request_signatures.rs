use crate::config::Config;
use crate::harvester::tasks::plot_manager::PlotManager;
use async_trait::async_trait;
use blst::min_pk::{PublicKey, SecretKey};
use dg_xch_clients::protocols::harvester::{RequestSignatures, RespondSignatures};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, Client, MessageHandler, Websocket};
use dg_xch_core::blockchain::proof_of_space::generate_plot_public_key;
use dg_xch_core::clvm::bls_bindings::sign_prepend;
use dg_xch_keys::master_sk_to_local_sk;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::debug;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

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
        let mut cursor = Cursor::new(msg.data.clone());
        let request_signatures = RequestSignatures::from_bytes(&mut cursor)?;
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
                    msg.id,
                )
                .to_bytes(),
            ))
            .await;
        Ok(())
    }
}
