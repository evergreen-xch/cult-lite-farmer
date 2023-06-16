use crate::farmer::{FarmerPoolState, FarmerState};
use crate::SocketPeer;
use async_trait::async_trait;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::harvester::{NewSignagePointHarvester, PoolDifficulty};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler, NodeType, Websocket};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::consensus::pot_iterations::POOL_SUB_SLOT_ITERS;
use dg_xch_serialize::ChiaSerialize;
use hyper_tungstenite::tungstenite::Message;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::{Cursor, Error};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct NewSignagePointHandle {
    pub id: Uuid,
    pub peers: Arc<Mutex<HashMap<Bytes32, SocketPeer>>>,
    pub pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub farmer_state: Arc<Mutex<FarmerState>>,
    pub cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
}
#[async_trait]
impl MessageHandler for NewSignagePointHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let sp = NewSignagePoint::from_bytes(&mut cursor)?;
        let mut pool_difficulties = vec![];
        for (p2_singleton_puzzle_hash, pool_dict) in self.pool_state.lock().await.iter() {
            if let Some(config) = &pool_dict.pool_config {
                if config.pool_url.is_empty() {
                    //Self Pooling
                    continue;
                }
                if let Some(difficulty) = pool_dict.current_difficulty {
                    debug!("Setting Difficulty for pool: {}", difficulty);
                    pool_difficulties.push(PoolDifficulty {
                        difficulty,
                        sub_slot_iters: POOL_SUB_SLOT_ITERS,
                        pool_contract_puzzle_hash: *p2_singleton_puzzle_hash,
                    })
                } else {
                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this signage point, pool: {}", &config.pool_url);
                    continue;
                }
            }
        }
        info!(
            "New Signage Point({}): {:?}",
            sp.signage_point_index, sp.challenge_hash
        );
        let harvester_point = NewSignagePointHarvester {
            challenge_hash: sp.challenge_hash,
            difficulty: sp.difficulty,
            sub_slot_iters: sp.sub_slot_iters,
            signage_point_index: sp.signage_point_index,
            sp_hash: sp.challenge_chain_sp,
            pool_difficulties,
        };
        let msg = Message::Binary(
            ChiaMessage::new(
                ProtocolMessageTypes::NewSignagePointHarvester,
                &harvester_point,
                None,
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
                signage_points.insert(sp.challenge_chain_sp, vec![]);
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
        self.farmer_state.lock().await.most_recent_sp =
            (sp.challenge_chain_sp, sp.signage_point_index);
        self.cache_time
            .lock()
            .await
            .insert(sp.challenge_chain_sp, Instant::now());
        Ok(())
    }
}
