use crate::config::tls::{TlsAcceptor, TlsStream};
use crate::farmer::api::{HandshakeHandle, NewProofOfSpaceHandle, RespondSignaturesHandle};
use crate::farmer::Farmer;
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
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, DistinguishedNames, RootCertStore, ServerConfig};
use std::convert::Infallible;
use std::io::{Error, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite;
use uuid::Uuid;

pub struct AllowAny {
    _roots: RootCertStore,
}
impl AllowAny {
    pub fn new_arc(_roots: RootCertStore) -> Arc<dyn ClientCertVerifier> {
        Arc::new(Self { _roots })
    }
}

impl ClientCertVerifier for AllowAny {
    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        Some(vec![])
    }

    fn verify_client_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _now: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
}

pub struct FarmerServer {
    pub farmer: Arc<Farmer>,
}
impl<'a> FarmerServer {
    pub fn new(farmer: Arc<Farmer>) -> Self {
        FarmerServer { farmer }
    }

    pub async fn start(
        &self,
        global_run: Arc<Mutex<bool>>,
        mut signal: Receiver<()>,
    ) -> Result<(), Error> {
        let (host, port, root_path, private_crt, private_key, public_crt) = {
            let config = self.farmer.config.lock().await;
            (
                config.farmer.host.clone(),
                config.farmer.port,
                config.farmer.ssl.root_path.clone(),
                config.farmer.ssl.certs.private_crt.clone(),
                config.farmer.ssl.certs.private_key.clone(),
                config.farmer.ssl.ca.public_crt.clone(),
            )
        };
        let certs = load_certs(&format!("{}/{}", &root_path, &private_crt))?;
        let key = load_private_key(&format!("{}/{}", &root_path, &private_key))?;
        let mut root_cert_store = RootCertStore::empty();
        if let Some(public_crt) = public_crt {
            for cert in load_certs(&format!("{}/{}", &root_path, &public_crt))? {
                root_cert_store.add(&cert).map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid Root Cert for Farmer Server: {:?}", e),
                    )
                })?;
            }
        }
        let tls_cfg = Arc::new(
            ServerConfig::builder()
                .with_safe_defaults()
                .with_client_cert_verifier(AllowAny::new_arc(root_cert_store))
                .with_single_cert(certs, key)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("Invalid Cert for Farmer Server: {:?}", e),
                    )
                })?,
        );
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
        let server = Server::builder(TlsAcceptor::new(
            tls_cfg,
            AddrIncoming::bind(&addr).map_err(|e| Error::new(ErrorKind::Other, e))?,
        ))
        .serve(make_service_fn(move |conn: &TlsStream| {
            let remote_addr = conn.remote_addr();
            let farmer = farmer_arc.clone();
            let peer_id = {
                let now = Instant::now();
                let mut peer = None;
                loop {
                    if conn.peer_id().is_some() {
                        peer = conn.peer_id();
                        break;
                    }
                    if Instant::now().duration_since(now).as_secs() > 5 {
                        break;
                    }
                }
                peer
            };
            let peer_arc = Arc::new(peer_id.unwrap_or_default());
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    websocket_handler(remote_addr, peer_arc.clone(), req, farmer.clone())
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
        debug!("Farmer Server Closing");
        Ok(())
    }
}

#[inline]
async fn websocket_handler(
    addr: Option<SocketAddr>,
    peer_id: Arc<Bytes32>,
    mut req: Request<Body>,
    farmer: Arc<Farmer>,
) -> Result<Response<Body>, tungstenite::error::Error> {
    if is_upgrade_request(&req) {
        let (response, websocket) = upgrade(&mut req, None)?;
        let addr = addr.ok_or_else(|| Error::new(ErrorKind::Other, "Invalid Peer"))?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(addr, peer_id.clone(), websocket, farmer).await {
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

async fn handle_connection(
    _peer_addr: SocketAddr,
    peer_id: Arc<Bytes32>,
    stream: HyperWebsocket,
    farmer: Arc<Farmer>,
) -> Result<(), tungstenite::error::Error> {
    let (server, mut stream) = dg_xch_utils::clients::websocket::Server::new(stream.await?);
    let handshake_handle_id = Uuid::new_v4();
    let handshake_handle = HandshakeHandle {
        id: handshake_handle_id,
        farmer: farmer.clone(),
        peer_id: peer_id.as_ref().clone(),
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
    let new_proof_of_space_id = Uuid::new_v4();
    let new_proof_of_space_handle = NewProofOfSpaceHandle {
        id: new_proof_of_space_id,
        farmer: farmer.clone(),
        peer_id: peer_id.clone(),
    };
    server
        .subscribe(
            new_proof_of_space_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::NewProofOfSpace),
                },
                Arc::new(new_proof_of_space_handle),
            ),
        )
        .await;
    let respond_signatures_id = Uuid::new_v4();
    let respond_signatures_handle = RespondSignaturesHandle {
        id: respond_signatures_id,
        farmer: farmer.clone(),
    };
    server
        .subscribe(
            respond_signatures_id,
            ChiaMessageHandler::new(
                ChiaMessageFilter {
                    msg_type: Some(ProtocolMessageTypes::RespondSignatures),
                },
                Arc::new(respond_signatures_handle),
            ),
        )
        .await;
    let handle = tokio::spawn(async move { stream.run().await });
    let peer = Arc::new(Mutex::new(server));
    {
        let removed = farmer.peers.lock().await.insert(
            peer_id.as_ref().clone(),
            Peer {
                node_type: None,
                websocket: peer,
            },
        );
        if let Some(removed) = removed {
            let _ = removed.websocket.lock().await.close(None);
        }
    }
    let _ = handle.await;
    Ok(())
}
