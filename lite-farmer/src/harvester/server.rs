use crate::config::tls::{TlsAcceptor, TlsStream};
use crate::config::Config;
use crate::harvester::api::HandshakeHandle;
use crate::Peer;
use dg_xch_utils::clients::protocols::shared::{load_certs, load_private_key};
use dg_xch_utils::clients::protocols::ProtocolMessageTypes;
use dg_xch_utils::clients::websocket::{ChiaMessageFilter, ChiaMessageHandler, Websocket};
use dg_xch_utils::types::blockchain::sized_bytes::Bytes32;
use hyper::server::conn::AddrIncoming;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use hyper_tungstenite::{is_upgrade_request, upgrade, HyperWebsocket};
use log::{debug, error};
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite;
use uuid::Uuid;

pub struct HarvesterServer {
    pub config: Arc<Config>,
    peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
}
impl HarvesterServer {
    pub fn new(config: &Config) -> Self {
        HarvesterServer {
            config: Arc::new(config.clone()),
            peers: Arc::new(Mutex::new(HashMap::default())),
        }
    }

    pub async fn start(
        &self,
        global_run: Arc<Mutex<bool>>,
        mut signal: Receiver<()>,
    ) -> Result<(), Error> {
        let certs = load_certs(&format!(
            "{}/{}",
            &self.config.harvester.ssl.root_path, &self.config.harvester.ssl.certs.private_crt
        ))?;
        let key = load_private_key(&format!(
            "{}/{}",
            &self.config.harvester.ssl.root_path, &self.config.harvester.ssl.certs.private_key
        ))?;
        let mut root_cert_store = rustls::RootCertStore::empty();
        if let Some(public_crt) = &self.config.harvester.ssl.ca.public_crt {
            for cert in load_certs(&format!(
                "{}/{}",
                &self.config.harvester.ssl.root_path, public_crt
            ))? {
                root_cert_store.add(&cert).map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid Root Cert for Harvester Server: {:?}", e),
                    )
                })?;
            }
        }
        let tls_cfg = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(AllowAnyAuthenticatedClient::new(root_cert_store))
                .with_single_cert(certs, key)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid Cert for Harvester Server: {:?}", e),
                    )
                })?,
        );

        let addr = SocketAddr::from((
            Ipv4Addr::from_str(if self.config.harvester.host == "localhost" {
                "127.0.0.1"
            } else {
                &self.config.harvester.host
            })
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse Harvester Host Address: {:?}", e),
                )
            })?,
            self.config.harvester.port,
        ));
        let peers_arc = self.peers.clone();
        let config_arc = self.config.clone();
        let server = Server::builder(TlsAcceptor::new(
            tls_cfg,
            AddrIncoming::bind(&addr).map_err(|e| Error::new(ErrorKind::Other, e))?,
        ))
        .serve(make_service_fn(move |conn: &TlsStream| {
            let remote_addr = conn.remote_addr();
            let config = config_arc.clone();
            let peer_id = conn.peer_id();
            let peers = peers_arc.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    harvester_websocket_handler(
                        remote_addr,
                        peer_id.clone(),
                        req,
                        config.clone(),
                        peers.clone(),
                    )
                }))
            }
        }));
        let grace = server.with_graceful_shutdown(async move {
            signal.recv().await;
        });
        let server_handle = tokio::spawn(async {
            let _ = grace.await;
        });
        loop {
            if !*global_run.lock().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let _ = server_handle.await;
        debug!("Harvester Server Closing");
        Ok(())
    }
}

async fn harvester_websocket_handler(
    addr: Option<SocketAddr>,
    peer_id: Option<Bytes32>,
    mut req: Request<Body>,
    config: Arc<Config>,
    peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
) -> Result<Response<Body>, tungstenite::error::Error> {
    if is_upgrade_request(&req) {
        let (response, websocket) = upgrade(&mut req, None)?;
        let addr = addr.ok_or_else(|| Error::new(ErrorKind::Other, "Invalid Peer"))?;
        let peer_id =
            Arc::new(peer_id.ok_or_else(|| Error::new(ErrorKind::Other, "Invalid Peer"))?);
        tokio::spawn(async move {
            if let Err(e) =
                harvester_handle_connection(addr, peer_id, websocket, config, peers).await
            {
                error!("Error in websocket connection: {}", e);
            }
        });
        Ok(response)
    } else {
        Ok(Response::new(Body::from(
            "HTTP NOT SUPPORTED ON THIS ENDPOINT",
        )))
    }
}

async fn harvester_handle_connection(
    _peer_addr: SocketAddr,
    peer_id: Arc<Bytes32>,
    stream: HyperWebsocket,
    config: Arc<Config>,
    peers: Arc<Mutex<HashMap<Bytes32, Peer>>>,
) -> Result<(), tungstenite::error::Error> {
    let (server, mut stream) = dg_xch_utils::clients::websocket::Server::new(stream.await?);
    let handshake_handle_id = Uuid::new_v4();
    let handshake_handle = HandshakeHandle {
        id: handshake_handle_id,
        config: config.clone(),
        peers: peers.clone(),
        peer_id: peer_id.clone(),
    };
    server
        .subscribe(
            handshake_handle_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::Handshake),
                },
                Arc::new(handshake_handle),
            ),
        )
        .await;
    let handle = tokio::spawn(async move { stream.run().await });
    let peer = Arc::new(Mutex::new(server));
    {
        peers.lock().await.insert(
            peer_id.as_ref().clone(),
            Peer {
                node_type: None,
                websocket: peer,
            },
        );
    }
    let _ = handle.await;
    //Removed the Closed Peer
    {
        if let Some(removed) = peers.lock().await.remove(peer_id.as_ref()) {
            let _ = removed.websocket.lock().await.close(None);
        }
    }
    Ok(())
}
