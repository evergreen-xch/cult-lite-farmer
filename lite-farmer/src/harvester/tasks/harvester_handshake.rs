use crate::config::Config;
use crate::harvester::tasks::plot_manager::PlotManager;
use crate::harvester::HarvesterState;
use async_trait::async_trait;
use dg_xch_clients::protocols::harvester::HarvesterHandshake;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler};
use dg_xch_serialize::ChiaSerialize;
use log::{debug, info};
use std::io::{Cursor, Error};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct HarvesterHandshakeHandle {
    pub id: Uuid,
    pub config: Arc<Config>,
    pub plot_manager: Arc<Mutex<PlotManager>>,
    pub harvester_state: Arc<Mutex<HarvesterState>>,
}
#[async_trait]
impl MessageHandler for HarvesterHandshakeHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(msg.data.clone());
        let handshake = HarvesterHandshake::from_bytes(&mut cursor)?;
        info!("Handshake from farmer: {:?}", handshake);
        self.plot_manager
            .lock()
            .await
            .set_public_keys(handshake.farmer_public_keys, handshake.pool_public_keys);
        debug!("Set Key... Loading Plots");
        match self
            .plot_manager
            .lock()
            .await
            .load_plots(self.harvester_state.clone())
            .await
        {
            Ok(_) => {
                debug!("Done Loading Plots");
            }
            Err(e) => {
                debug!("Error loading plots: {:?}", e);
            }
        }
        Ok(())
    }
}
