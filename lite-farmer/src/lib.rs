use blst::min_pk::SecretKey;
use dg_xch_utils::clients::websocket::{NodeType, Server};
use dg_xch_utils::consensus::constants::ConsensusConstants;
use dg_xch_utils::plots::PlotHeader;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod config;
pub mod farmer;
pub mod harvester;

pub struct State {
    pub headers: Arc<Mutex<HashMap<PathBuf, PlotHeader>>>,
    pub plot_keys: Arc<Mutex<HashMap<PathBuf, SecretKey>>>,
    pub constants: Arc<ConsensusConstants>,
}

pub struct Peer {
    node_type: Option<NodeType>,
    websocket: Arc<Mutex<Server>>,
}
