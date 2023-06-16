use crate::config::Config;
use crate::harvester::server::HarvesterServer;
use crate::harvester::tasks::harvester_handshake::HarvesterHandshakeHandle;
use crate::harvester::tasks::new_signage_point_harvester::NewSignagePointHarvesterHandle;
use crate::harvester::tasks::plot_manager::PlotManager;
use crate::harvester::tasks::request_signatures::RequestSignaturesHandle;
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::harvester::HarvesterClient;
use dg_xch_clients::websocket::{
    ChiaMessageFilter, ChiaMessageHandler, ClientSSLConfig, Websocket,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::join;
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;

mod server;
mod tasks;

#[derive(Debug, Default, Clone)]
pub struct HarvesterState {
    pub og_plot_count: usize,
    pub nft_plot_count: usize,
    pub invalid_plot_count: usize,
    pub plot_space: u64,
}

pub struct Harvester {
    config: Arc<Config>,
    plot_manager: Arc<Mutex<PlotManager>>,
}
impl Harvester {
    pub fn new(config: Arc<Config>) -> Self {
        let manager_arc = Arc::new(Mutex::new(PlotManager::new(config.clone())));
        Self {
            config,
            plot_manager: manager_arc,
        }
    }

    pub async fn run(
        self,
        shutdown_receiver: Arc<AtomicBool>,
        harvester_state: Arc<Mutex<HarvesterState>>,
        additional_headers: &Option<HashMap<String, String>>,
    ) -> Result<(), Error> {
        let server = HarvesterServer::new(&self.config);
        let server_run = shutdown_receiver.clone();
        let server_handle = tokio::spawn(async move {
            let mut failed = 0;
            let mut res = Err(Error::new(
                ErrorKind::ConnectionAborted,
                "Harvester Server Never Connected",
            ));
            loop {
                if !server_run.load(Ordering::Relaxed) {
                    break;
                }
                res = server.start(server_run.clone()).await;
                if let Err(e) = &res {
                    error!("Error Starting Harvester Server: {:?}", e);
                    failed += 1;
                    if failed >= 5 {
                        error!(
                            "Error Starting Harvester Server, Too Many Retries({failed}): {:?}",
                            e
                        );
                        server_run.store(false, Ordering::Relaxed);
                    } else {
                        warn!(
                            "Failed to Start Harvester Server, Retry Attempts({failed}): {:?}",
                            e
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                } else {
                    info!("Harvester Server Stopped");
                }
            }
            res
        });
        let plot_manager_arc = self.plot_manager.clone();
        let plot_manager_run = shutdown_receiver.clone();
        let plot_manager_harvester_state = harvester_state.clone();
        let plot_refresh_handle = tokio::spawn(async move {
            let mut last_update = Instant::now();
            let mut plot_count;
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                if !plot_manager_run.load(Ordering::Relaxed) {
                    break;
                }
                plot_count = plot_manager_arc.lock().await.plots.len();
                if Instant::now().duration_since(last_update) > Duration::from_secs(300)
                    || (Instant::now().duration_since(last_update) > Duration::from_secs(10)
                        && plot_count == 0)
                {
                    last_update = Instant::now();
                    info!("Refreshing plots:");
                    info!("Current plot count: : {plot_count}");
                    if let Err(e) = plot_manager_arc
                        .lock()
                        .await
                        .load_plots(plot_manager_harvester_state.clone())
                        .await
                    {
                        error!("Failed to reload plots: {:?}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
        loop {
            info!("Harvester Starting");
            let client = match HarvesterClient::new_ssl(
                &self.config.harvester.farmer_peer.host,
                self.config.harvester.farmer_peer.port,
                ClientSSLConfig {
                    ssl_crt_path: &format!(
                        "{}/{}",
                        &self.config.harvester.ssl.root_path,
                        &self.config.harvester.ssl.certs.private_crt
                    ),
                    ssl_key_path: &format!(
                        "{}/{}",
                        &self.config.harvester.ssl.root_path,
                        &self.config.harvester.ssl.certs.private_key
                    ),
                    ssl_ca_crt_path: &format!(
                        "{}/{}",
                        &self.config.harvester.ssl.root_path,
                        self.config
                            .harvester
                            .ssl
                            .ca
                            .public_crt
                            .as_ref()
                            .cloned()
                            .unwrap_or_default()
                    ),
                },
                &self.config.selected_network,
                additional_headers,
                shutdown_receiver.clone(),
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Failed to Start Harvester Client, Waiting and trying again: {:?}",
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    if !shutdown_receiver.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
            };
            info!("Harvester Client Started");

            let harvester_handshake_handle_id = Uuid::new_v4();
            let harvester_handshake_handle = Arc::new(HarvesterHandshakeHandle {
                id: harvester_handshake_handle_id,
                config: self.config.clone(),
                plot_manager: self.plot_manager.clone(),
                harvester_state: harvester_state.clone(),
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
                            id: None,
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
                            id: None,
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
                            id: None,
                        },
                        request_signatures_handle,
                    ),
                )
                .await;
            info!("Harvester Initialized");
            if let Err(e) = client.join().await {
                error!("Failed to Join Harvester Client: {:?}", e);
            };
            if !shutdown_receiver.load(Ordering::Relaxed) {
                break;
            }
        }
        match join!(plot_refresh_handle, server_handle) {
            (Err(e), Err(e2)) => {
                error!("Error Joining Both: {:?} : {:?}", e, e2);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(Error::new(ErrorKind::Other, e))
            }
            (Err(e), _) => {
                error!("Error Joining Plot Refresh: {:?}", e);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(Error::new(ErrorKind::Other, e))
            }
            (_, Err(e)) => {
                error!("Error Joining Server: {:?}", e);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(Error::new(ErrorKind::Other, e))
            }
            (_, Ok(Err(e))) => {
                error!("Error in Server: {:?}", e);
                shutdown_receiver.store(false, Ordering::Relaxed);
                Err(Error::new(ErrorKind::Other, e))
            }
            (Ok(_), Ok(Ok(_))) => {
                info!("Harvester Server Shutting Down");
                shutdown_receiver.store(false, Ordering::Relaxed);
                Ok(())
            }
        }
    }
}
