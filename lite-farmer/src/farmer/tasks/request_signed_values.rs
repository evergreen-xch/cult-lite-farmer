use crate::farmer::{FarmerIdentifier, FarmerState};
use crate::SocketPeer;
use async_trait::async_trait;
use dg_xch_clients::protocols::farmer::RequestSignedValues;
use dg_xch_clients::protocols::harvester::RequestSignatures;
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler, Websocket};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::error;
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct RequestSignedValuesHandle {
    pub id: Uuid,
    pub quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
    pub peers: Arc<Mutex<HashMap<Bytes32, SocketPeer>>>,
    pub farmer_state: Arc<Mutex<FarmerState>>,
}
#[async_trait]
impl MessageHandler for RequestSignedValuesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let request = RequestSignedValues::from_bytes(&mut cursor)?;
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
                                challenge_hash: identifier.challenge_hash,
                                sp_hash: identifier.sp_hash,
                                messages: vec![
                                    request.foliage_block_data_hash,
                                    request.foliage_transaction_block_hash,
                                ],
                            },
                            None,
                        )
                        .to_bytes(),
                    ))
                    .await;
            }
            Ok(())
        } else {
            error!("Do not have quality {}", &request.quality_string);
            {
                self.farmer_state
                    .lock()
                    .await
                    .recent_errors
                    .add(format!("Do not have quality {}", &request.quality_string));
            }
            Err(Error::new(
                ErrorKind::NotFound,
                format!("Do not have quality {}", &request.quality_string),
            ))
        }
    }
}
