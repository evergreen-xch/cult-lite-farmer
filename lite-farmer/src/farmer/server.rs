use crate::config::tls::{AllowAny, TlsAcceptor, TlsStream};
use crate::farmer::tasks::handshake::HandshakeHandle;
use crate::farmer::tasks::new_proof_of_space::NewProofOfSpaceHandle;
use crate::farmer::tasks::respond_signatures::RespondSignaturesHandle;
use crate::farmer::{Farmer, FarmerState};
use crate::SocketPeer;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::shared::{load_certs, load_private_key};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{
    ChiaMessageFilter, ChiaMessageHandler, ServerConnection, Websocket,
};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper_tungstenite::{is_upgrade_request, upgrade, HyperWebsocket};
use log::{error, info};
use rustls::{RootCertStore, ServerConfig};
use std::convert::Infallible;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite;
use uuid::Uuid;

pub struct FarmerServer {
    pub farmer: Arc<Farmer>,
    pub farmer_state: Arc<Mutex<FarmerState>>,
}
impl FarmerServer {
    pub fn new(farmer: Arc<Farmer>, farmer_state: Arc<Mutex<FarmerState>>) -> Self {
        FarmerServer {
            farmer,
            farmer_state,
        }
    }

    pub async fn start<T: PoolClient + Sized + Sync + Send + 'static>(
        &self,
        global_run: Arc<AtomicBool>,
        client: Arc<T>,
    ) -> Result<(), Error> {
        let (host, port, root_path, private_crt, private_key, chia_private_crt) = {
            info!("Loading Farmer Config");
            let config = self.farmer.config.lock().await;
            (
                config.farmer.host.clone(),
                config.farmer.port,
                config.farmer.ssl.root_path.clone(),
                config.farmer.ssl.certs.private_crt.clone(),
                config.farmer.ssl.certs.private_key.clone(),
                config.farmer.ssl.ca.private_crt.clone(),
            )
        };
        info!("Loading Farmer Certs");
        let certs = load_certs(&format!("{}/{}", &root_path, &private_crt))?;
        info!("Loading Farmer Key");
        let key = load_private_key(&format!("{}/{}", &root_path, &private_key))?;
        let mut root_cert_store = RootCertStore::empty();
        info!("Loading Pub Cert");
        for cert in load_certs(&format!("{}/{}", &root_path, &chia_private_crt))? {
            root_cert_store.add(&cert).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Invalid Root Cert for Farmer Server: {:?}", e),
                )
            })?;
        }
        info!("Loading TLS Config");
        let tls_cfg = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(AllowAny::new(root_cert_store))
                .with_single_cert(certs, key)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid Cert for Farmer Server: {:?}", e),
                    )
                })?,
        );
        info!("Loading Socket Config");
        let addr = SocketAddr::from((
            Ipv4Addr::from_str(if host == "localhost" {
                "127.0.0.1"
            } else {
                &host
            })
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse Farmer Host Address: {:?}", e),
                )
            })?,
            port,
        ));
        let farmer_arc = self.farmer.clone();
        let farmer_state_arc = self.farmer_state.clone();
        info!("Building Server");
        let server_run = global_run.clone();
        let server = Server::builder(TlsAcceptor::new(
            tls_cfg,
            AddrIncoming::bind(&addr).map_err(|e| Error::new(ErrorKind::Other, e))?,
        ))
        .serve(make_service_fn(move |conn: &TlsStream| {
            let server_run = server_run.clone();
            info!("Farmer Connection Started");
            let remote_addr = conn.remote_addr();
            let farmer = farmer_arc.clone();
            let farmer_state = farmer_state_arc.clone();
            let socket_client = client.clone();
            let peer_arc = conn.peer_id.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    info!("Moving to Websocket Handle");
                    websocket_handler(
                        remote_addr,
                        peer_arc.clone(),
                        req,
                        farmer.clone(),
                        farmer_state.clone(),
                        socket_client.clone(),
                        server_run.clone(),
                    )
                }))
            }
        }));
        info!("Starting Server with graceful shutdown");
        let grace_run = global_run.clone();
        let grace = server.with_graceful_shutdown(async move {
            let sleep_interval = Duration::from_millis(100);
            loop {
                if !grace_run.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(sleep_interval).await;
            }
            info!("Graceful Shutdown Started");
        });
        let handle = tokio::spawn(async {
            info!("Farmer Server Started");
            grace
                .await
                .map_err(|e| Error::new(ErrorKind::Other, format!("Farmer Server Error: {:?}", e)))
        });
        let sp_farmer_arc = self.farmer.clone();
        let mut last_clear = Instant::now();
        loop {
            if !global_run.load(Ordering::Relaxed) {
                info!("Farmer Server Stopping from global");
                break;
            }
            let now = Instant::now();
            if now.duration_since(last_clear).as_secs() > 60 * 60 * 16 {
                let mut to_remove = vec![];
                for (k, v) in sp_farmer_arc.cache_time.lock().await.iter() {
                    if now.duration_since(*v).as_secs() > 60 * 60 * 12 {
                        to_remove.push(*k);
                    }
                }
                for b in to_remove {
                    let _ = sp_farmer_arc.signage_points.lock().await.remove(&b);
                    let _ = sp_farmer_arc.quality_to_identifiers.lock().await.remove(&b);
                }
                last_clear = now;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        handle.await.map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Failed to join Farmer Server: {:?}", e),
            )
        })?
    }
}

#[inline]
async fn websocket_handler<T: PoolClient + Sized + Sync + Send + 'static>(
    addr: Option<SocketAddr>,
    peer_id: Arc<std::sync::Mutex<Option<Bytes32>>>,
    mut req: Request<Body>,
    farmer: Arc<Farmer>,
    farmer_state: Arc<Mutex<FarmerState>>,
    client: Arc<T>,
    run: Arc<AtomicBool>,
) -> Result<Response<Body>, tungstenite::error::Error> {
    if is_upgrade_request(&req) {
        let (response, websocket) = upgrade(&mut req, None)?;
        let addr = addr.ok_or_else(|| Error::new(ErrorKind::Other, "Invalid Peer"))?;
        let peer_id = Arc::new(
            (*peer_id.lock().map_err(|e| {
                error!("Failed ot lock peer_id: {:?}", e);
                Error::new(ErrorKind::Other, format!("Failed ot lock peer_id: {:?}", e))
            })?)
            .ok_or_else(|| {
                error!("Invalid Peer");
                Error::new(ErrorKind::Other, "Invalid Peer")
            })?,
        );
        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                addr,
                peer_id.clone(),
                websocket,
                farmer,
                farmer_state.clone(),
                client.clone(),
                run,
            )
            .await
            {
                {
                    farmer_state
                        .lock()
                        .await
                        .recent_errors
                        .add(format!("Error in websocket connection: {}", e));
                }
                error!("Error in websocket connection: {}", e);
            }
        });
        Ok(response)
    } else {
        error!("Invalid Connection, Normal HTTP request sent to websocket");
        {
            farmer_state
                .lock()
                .await
                .recent_errors
                .add("Invalid Connection, Normal HTTP request sent to websocket".to_string());
        }
        Ok(Response::new(Body::from(
            "HTTP NOT SUPPORTED ON THIS ENDPOINT",
        )))
    }
}

async fn handle_connection<T: PoolClient + Sized + Sync + Send + 'static>(
    _peer_addr: SocketAddr,
    peer_id: Arc<Bytes32>,
    stream: HyperWebsocket,
    farmer: Arc<Farmer>,
    farmer_state: Arc<Mutex<FarmerState>>,
    client: Arc<T>,
    run: Arc<AtomicBool>,
) -> Result<(), tungstenite::error::Error> {
    info!("New Farmer Server Connection");
    let (server, mut stream) = ServerConnection::new(stream.await?);
    let handshake_handle_id = Uuid::new_v4();
    let handshake_handle = HandshakeHandle {
        id: handshake_handle_id,
        farmer: farmer.clone(),
        farmer_state: farmer_state.clone(),
        peer_id: peer_id.clone(),
    };
    server
        .subscribe(
            handshake_handle_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::Handshake),
                    id: None,
                },
                Arc::new(handshake_handle),
            ),
        )
        .await;
    let new_proof_of_space_id = Uuid::new_v4();
    let new_proof_of_space_handle = NewProofOfSpaceHandle {
        id: new_proof_of_space_id,
        farmer: farmer.clone(),
        farmer_state: farmer_state.clone(),
        peer_id: peer_id.clone(),
        pool_client: client.clone(),
    };
    server
        .subscribe(
            new_proof_of_space_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::NewProofOfSpace),
                    id: None,
                },
                Arc::new(new_proof_of_space_handle),
            ),
        )
        .await;
    let respond_signatures_id = Uuid::new_v4();
    let respond_signatures_handle = RespondSignaturesHandle {
        id: respond_signatures_id,
        farmer: farmer.clone(),
        farmer_state: farmer_state.clone(),
    };
    server
        .subscribe(
            respond_signatures_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::RespondSignatures),
                    id: None,
                },
                Arc::new(respond_signatures_handle),
            ),
        )
        .await;
    info!("Farmer Server Connection Started");
    let handle = tokio::spawn(async move { stream.run(run).await });
    let peer = Arc::new(Mutex::new(server));
    {
        let removed = farmer.peers.lock().await.insert(
            *peer_id,
            SocketPeer {
                node_type: None,
                websocket: peer,
            },
        );
        if let Some(removed) = removed {
            info!("Sending Close to Removed Harvester");
            let _ = removed.websocket.lock().await.close(None).await;
        }
    }
    let _ = handle.await;
    info!("Farmer Server Connection Finished");
    Ok(())
}
