use crate::farmer::{Farmer, FarmerState};
use async_trait::async_trait;
use dg_xch_clients::protocols::harvester::HarvesterHandshake;
use dg_xch_clients::protocols::shared::{Handshake, CAPABILITIES, PROTOCOL_VERSION};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler, NodeType, Websocket};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, info};
use std::io::{Cursor, Error};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct HandshakeHandle {
    pub id: Uuid,
    pub farmer: Arc<Farmer>,
    pub peer_id: Arc<Bytes32>,
    pub farmer_state: Arc<Mutex<FarmerState>>,
}
#[async_trait]
impl MessageHandler for HandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let handshake = Handshake::from_bytes(&mut cursor)?;
        debug!("New Peer: {}", &self.peer_id);
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
                        msg.id,
                    )
                    .to_bytes(),
                ))
                .await
                .unwrap_or_default();
            if NodeType::Harvester as u8 == handshake.node_type {
                let farmer_public_keys = self
                    .farmer
                    .farmer_private_keys
                    .lock()
                    .await
                    .iter()
                    .map(|k| k.sk_to_pk().to_bytes().into())
                    .collect();
                let pool_public_keys = self
                    .farmer
                    .pool_public_keys
                    .lock()
                    .await
                    .keys()
                    .cloned()
                    .collect();
                info! {"Harvester Connected. Sending Keys: ({:?}n {:?})", &farmer_public_keys, &pool_public_keys}
                peer.websocket
                    .lock()
                    .await
                    .send(Message::Binary(
                        ChiaMessage::new(
                            ProtocolMessageTypes::HarvesterHandshake,
                            &HarvesterHandshake {
                                farmer_public_keys,
                                pool_public_keys,
                            },
                            None,
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
