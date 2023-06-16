use crate::config::Config;
use crate::SocketPeer;
use async_trait::async_trait;
use dg_xch_clients::protocols::shared::{Handshake, CAPABILITIES, PROTOCOL_VERSION};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler, NodeType, Websocket};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct HandshakeHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub peers: Arc<Mutex<HashMap<Bytes32, SocketPeer>>>,
    pub peer_id: Arc<Bytes32>,
}
#[async_trait]
impl MessageHandler for HandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let handshake = Handshake::from_bytes(&mut cursor)?;
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
                        msg.id,
                    )
                    .to_bytes(),
                ))
                .await
        } else {
            Err(Error::new(ErrorKind::NotFound, "Failed to find peer"))
        }
    }
}
