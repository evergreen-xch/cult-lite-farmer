use crate::config::Config;
use crate::harvester::api::{
    HarvesterHandshakeHandle, NewSignagePointHarvesterHandle, RequestSignaturesHandle,
};
use crate::harvester::plot_manager::PlotManager;
use crate::harvester::plot_sync::PlotSyncSender;
use crate::harvester::server::HarvesterServer;
use dg_xch_utils::clients::protocols::ProtocolMessageTypes;
use dg_xch_utils::clients::websocket::harvester::HarvesterClient;
use dg_xch_utils::clients::websocket::{ChiaMessageFilter, ChiaMessageHandler, Websocket};
use log::debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use uuid::Uuid;

mod api;
mod plot_manager;
mod plot_sync;
mod server;

pub struct Harvester {
    config: Arc<Config>,
    plot_manager: Arc<Mutex<PlotManager>>,
    _plot_sync_sender: Arc<Mutex<PlotSyncSender>>,
}
impl Harvester {
    pub fn new(config: Arc<Config>) -> Self {
        let manager_arc = Arc::new(Mutex::new(PlotManager::new(config.clone())));
        Self {
            config,
            plot_manager: manager_arc.clone(),
            _plot_sync_sender: Arc::new(Mutex::new(PlotSyncSender::new(manager_arc))),
        }
    }

    pub async fn run(self, shutdown_receiver: Receiver<()>) {
        let global_run = Arc::new(Mutex::new(true));
        let server = HarvesterServer::new(&self.config);
        let server_run = global_run.clone();
        let handle = tokio::spawn(async move {
            let _ = server.start(server_run, shutdown_receiver).await;
        });
        loop {
            debug!("Harvester Starting");
            let client = match HarvesterClient::new_ssl(
                &self.config.harvester.farmer_peer.host,
                self.config.harvester.farmer_peer.port,
                &format!(
                    "{}/{}",
                    &self.config.harvester.ssl.root_path,
                    &self.config.harvester.ssl.certs.private_crt
                ),
                &format!(
                    "{}/{}",
                    &self.config.harvester.ssl.root_path,
                    &self.config.harvester.ssl.certs.private_key
                ),
                &format!(
                    "{}/{}",
                    &self.config.harvester.ssl.root_path, &self.config.harvester.ssl.ca.private_crt
                ),
                "testnet10",
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    debug!(
                        "Failed to Start Harvester Client, Waiting and trying again: {:?}",
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if !*global_run.lock().await {
                        break;
                    }
                    continue;
                }
            };

            let harvester_handshake_handle_id = Uuid::new_v4();
            let harvester_handshake_handle = Arc::new(HarvesterHandshakeHandle {
                id: harvester_handshake_handle_id,
                config: self.config.clone(),
                plot_manager: self.plot_manager.clone(),
            });
            client
                .client
                .lock()
                .await
                .subscribe(
                    harvester_handshake_handle_id,
                    ChiaMessageHandler::new(
                        ChiaMessageFilter {
                            msg_type: Some(ProtocolMessageTypes::HarvesterHandshake),
                        },
                        harvester_handshake_handle,
                    ),
                )
                .await;

            let new_signage_point_harvester_id = Uuid::new_v4();
            let new_signage_point_harvester_handle = Arc::new(NewSignagePointHarvesterHandle {
                id: new_signage_point_harvester_id,
                config: self.config.clone(),
                plot_manager: self.plot_manager.clone(),
                client: client.client.clone(),
            });
            client
                .client
                .lock()
                .await
                .subscribe(
                    new_signage_point_harvester_id,
                    ChiaMessageHandler::new(
                        ChiaMessageFilter {
                            msg_type: Some(ProtocolMessageTypes::NewSignagePointHarvester),
                        },
                        new_signage_point_harvester_handle,
                    ),
                )
                .await;

            let request_signatures_id = Uuid::new_v4();
            let request_signatures_handle = Arc::new(RequestSignaturesHandle {
                id: request_signatures_id,
                config: self.config.clone(),
                plot_manager: self.plot_manager.clone(),
                client: client.client.clone(),
            });
            client
                .client
                .lock()
                .await
                .subscribe(
                    request_signatures_id,
                    ChiaMessageHandler::new(
                        ChiaMessageFilter {
                            msg_type: Some(ProtocolMessageTypes::RequestSignatures),
                        },
                        request_signatures_handle,
                    ),
                )
                .await;
            debug!("Harvester Initialized");
            let _ = client.join().await;
            if !*global_run.lock().await {
                break;
            }
        }
        let _ = handle.await;
    }
}
