pub mod tls;

use dg_xch_utils::types::blockchain::sized_bytes::{Bytes32, Bytes48};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::fs;
use std::fs::OpenOptions;
use std::io::{Error, ErrorKind, Write};
use std::ops::Sub;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::create_dir_all;

const CHIA_CA_CRT: &str = "-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIUXIpxI5MoZQ65/vhc7DK/d5ymoMUwDQYJKoZIhvcNAQEL
BQAwRDENMAsGA1UECgwEQ2hpYTEQMA4GA1UEAwwHQ2hpYSBDQTEhMB8GA1UECwwY
T3JnYW5pYyBGYXJtaW5nIERpdmlzaW9uMB4XDTIxMDEyMzA4NTEwNloXDTMxMDEy
MTA4NTEwNlowRDENMAsGA1UECgwEQ2hpYTEQMA4GA1UEAwwHQ2hpYSBDQTEhMB8G
A1UECwwYT3JnYW5pYyBGYXJtaW5nIERpdmlzaW9uMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAzz/L219Zjb5CIKnUkpd2julGC+j3E97KUiuOalCH9wdq
gpJi9nBqLccwPCSFXFew6CNBIBM+CW2jT3UVwgzjdXJ7pgtu8gWj0NQ6NqSLiXV2
WbpZovfrVh3x7Z4bjPgI3ouWjyehUfmK1GPIld4BfUSQtPlUJ53+XT32GRizUy+b
0CcJ84jp1XvyZAMajYnclFRNNJSw9WXtTlMUu+Z1M4K7c4ZPwEqgEnCgRc0TCaXj
180vo7mCHJQoDiNSCRATwfH+kWxOOK/nePkq2t4mPSFaX8xAS4yILISIOWYn7sNg
dy9D6gGNFo2SZ0FR3x9hjUjYEV3cPqg3BmNE3DDynQIDAQABoxMwETAPBgNVHRMB
Af8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAEugnFQjzHhS0eeCqUwOHmP3ww
/rXPkKF+bJ6uiQgXZl+B5W3m3zaKimJeyatmuN+5ST1gUET+boMhbA/7grXAsRsk
SFTHG0T9CWfPiuimVmGCzoxLGpWDMJcHZncpQZ72dcy3h7mjWS+U59uyRVHeiprE
hvSyoNSYmfvh7vplRKS1wYeA119LL5fRXvOQNW6pSsts17auu38HWQGagSIAd1UP
5zEvDS1HgvaU1E09hlHzlpdSdNkAx7si0DMzxKHUg9oXeRZedt6kcfyEmryd52Mj
1r1R9mf4iMIUv1zc2sHVc1omxnCw9+7U4GMWLtL5OgyJyfNyoxk3tC+D3KNU
-----END CERTIFICATE-----";

const CHIA_CA_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzz/L219Zjb5CIKnUkpd2julGC+j3E97KUiuOalCH9wdqgpJi
9nBqLccwPCSFXFew6CNBIBM+CW2jT3UVwgzjdXJ7pgtu8gWj0NQ6NqSLiXV2WbpZ
ovfrVh3x7Z4bjPgI3ouWjyehUfmK1GPIld4BfUSQtPlUJ53+XT32GRizUy+b0CcJ
84jp1XvyZAMajYnclFRNNJSw9WXtTlMUu+Z1M4K7c4ZPwEqgEnCgRc0TCaXj180v
o7mCHJQoDiNSCRATwfH+kWxOOK/nePkq2t4mPSFaX8xAS4yILISIOWYn7sNgdy9D
6gGNFo2SZ0FR3x9hjUjYEV3cPqg3BmNE3DDynQIDAQABAoIBAGupS4BJdx8gEAAh
2VDRqAAzhHTZb8j9uoKXJ+NotEkKrDTqUMiOu0nOqOsFWdYPo9HjxoggFuEU+Hpl
a4kj4uF3OG6Yj+jgLypjpV4PeoFM6M9R9BCp07In2i7DLLK9gvYA85SoVLBd/tW4
hFH+Qy3M+ZNZ1nLCK4pKjtaYs0dpi5zLoVvpEcEem2O+aRpUPCZqkNwU0umATCfg
ZGfFzgXI/XPJr8Uy+LVZOFp3PXXHfnZZD9T5AjO/ViBeqbMFuWQ8BpVOqapNPKj8
xDY3ovw3uiAYPC7eLib3u/WoFelMc2OMX0QljLp5Y+FScFHAMxoco3AQdWSYvSQw
b5xZmg0CgYEA6zKASfrw3EtPthkLR5NBmesI4RbbY6iFVhS5loLbzTtStvsus8EI
6RQgLgAFF14H21YSHxb6dB1Mbo45BN83gmDpUvKPREslqD3YPMKFo5GXMmv+JhNo
5Y9fhiOEnxzLJGtBB1HeGmg5NXp9mr2Ch9u8w/slfuCHckbA9AYvdxMCgYEA4ZR5
zg73+UA1a6Pm93bLYZGj+hf7OaB/6Hiw9YxCBgDfWM9dJ48iz382nojT5ui0rClV
5YAo8UCLh01Np9AbBZHuBdYm9IziuKNzTeK31UW+Tvbz+dEx7+PlYQffNOhcIgd+
9SXjoZorQksImKdMGZld1lEReHuBawq92JQvtY8CgYEAtNwUws7xQLW5CjKf9d5K
5+1Q2qYU9sG0JsmxHQhrtZoUtRjahOe/zlvnkvf48ksgh43cSYQF/Bw7lhhPyGtN
6DhVs69KdB3FS2ajTbXXxjxCpEdfHDB4zW4+6ouNhD1ECTFgxBw0SuIye+lBhSiN
o6NZuOr7nmFSRpIZ9ox7G3kCgYA4pvxMNtAqJekEpn4cChab42LGLX2nhFp7PMxc
bqQqM8/j0vg3Nihs6isCd6SYKjstvZfX8m7V3/rquQxWp9oRdQvNJXJVGojaDBqq
JdU7V6+qzzSIufQLpjV2P+7br7trxGwrDx/y9vAETynShLmE+FJrv6Jems3u3xy8
psKwmwKBgG5uLzCyMvMB2KwI+f3np2LYVGG0Pl1jq6yNXSaBosAiF0y+IgUjtWY5
EejO8oPWcb9AbqgPtrWaiJi17KiKv4Oyba5+y36IEtyjolWt0AB6F3oDK0X+Etw8
j/xlvBNuzDL6gRJHQg1+d4dO8Lz54NDUbKW8jGl+N/7afGVpGmX9
-----END RSA PRIVATE KEY-----";

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Peer {
    pub host: String,
    pub port: u16,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SslCertInfo {
    #[serde(default)]
    pub public_crt: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    pub private_crt: String,
    pub private_key: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SslInfo {
    pub root_path: String,
    pub certs: SslCertInfo,
    pub ca: SslCertInfo,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FullNodeConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FarmerConfig {
    pub host: String,
    pub port: u16,
    pub local_full_node_peer: Option<Peer>,
    pub remote_full_node_peer: Peer,
    pub ssl: SslInfo,
    pub farming_info: Vec<FarmingInfo>,
    pub xch_target_address: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HarvesterConfig {
    pub host: String,
    pub port: u16,
    pub farmer_peer: Peer,
    pub ssl: SslInfo,
    pub plot_directories: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FarmingInfo {
    pub farmer_secret_key: String,
    pub launcher_id: Option<String>,
    pub pool_secret_key: Option<String>,
    pub owner_secret_key: Option<String>,
    pub auth_secret_key: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolWalletConfig {
    pub launcher_id: Bytes32,
    pub pool_url: String,
    pub payout_instructions: String,
    pub target_puzzle_hash: Bytes32,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub owner_public_key: Bytes48,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub worker_name: String,
    pub selected_network: String,
    pub farmer: FarmerConfig,
    pub harvester: HarvesterConfig,
    pub pool_list: Vec<PoolWalletConfig>,
    pub license: bool,
    #[serde(skip_serializing, skip_deserializing)]
    pub path: PathBuf,
}
impl Config {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn save_as_yaml<P: AsRef<Path>>(&self, path: Option<P>) -> Result<(), Error> {
        if let Some(p) = path {
            fs::write(
                p.as_ref(),
                serde_yaml::to_string(&self)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        } else {
            fs::write(
                self.path.as_path(),
                serde_yaml::to_string(&self)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))?,
            )
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Config {
            worker_name: "lite-farmer".to_string(),
            selected_network: "mainnet".to_string(),
            farmer: FarmerConfig {
                host: "127.0.0.1".to_string(),
                port: 8447,
                local_full_node_peer: Some(Peer {
                    host: "127.0.0.1".to_string(),
                    port: 8444,
                }),
                remote_full_node_peer: Peer {
                    host: "127.0.0.1".to_string(),
                    port: 8444,
                },
                ssl: SslInfo {
                    root_path: "./ssl/".to_string(),
                    certs: SslCertInfo {
                        public_crt: None,
                        public_key: None,
                        private_crt: "farmer/private_farmer.crt".to_string(),
                        private_key: "farmer/private_farmer.key".to_string(),
                    },
                    ca: SslCertInfo {
                        public_crt: Some("ca/chia_ca.crt".to_string()),
                        public_key: Some("ca/chia_ca.key".to_string()),
                        private_crt: "ca/private_ca.crt".to_string(),
                        private_key: "ca/private_ca.key".to_string(),
                    },
                },
                farming_info: vec![],
                // farming_info: vec![FarmingInfo {
                //     farmer_secret_key: "YOUR SECRET KEY HERE".to_string(),
                //     launcher_id: Some(
                //         "If Using a PlotNFT put YOUR LAUNCHER ID HERE, otherwise leave blank"
                //             .to_string(),
                //     ),
                //     pool_secret_key: Some(
                //         "If Using a OG Plot, otherwise leave blank, YOUR POOL SECRET KEY"
                //             .to_string(),
                //     ),
                //     owner_secret_key: Some(
                //         "If Using a PlotNFT put YOUR OWNER SECRET KEY, otherwise leave blank"
                //             .to_string(),
                //     ),
                //     auth_secret_key: Some(
                //         "If Using a PlotNFT put YOUR AUTH SECRET KEY, otherwise leave blank"
                //             .to_string(),
                //     ),
                // }],
                xch_target_address: "YOUR PAYOUT ADDRESS HERE".to_string(),
            },
            harvester: HarvesterConfig {
                host: "127.0.0.1".to_string(),
                port: 8448,
                farmer_peer: Peer {
                    host: "127.0.0.1".to_string(),
                    port: 8447,
                },
                ssl: SslInfo {
                    root_path: "./ssl/".to_string(),
                    certs: SslCertInfo {
                        public_crt: None,
                        public_key: None,
                        private_crt: "harvester/private_harvester.crt".to_string(),
                        private_key: "harvester/private_harvester.key".to_string(),
                    },
                    ca: SslCertInfo {
                        public_crt: Some("ca/chia_ca.crt".to_string()),
                        public_key: Some("ca/chia_ca.key".to_string()),
                        private_crt: "ca/private_ca.crt".to_string(),
                        private_key: "ca/private_ca.key".to_string(),
                    },
                },
                plot_directories: vec![],
            },
            pool_list: vec![],
            license: false,
            path: PathBuf::from("./farmer_config.yaml"),
        }
    }
}
impl TryFrom<&Path> for Config {
    type Error = Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        serde_yaml::from_str::<Config>(&fs::read_to_string(value)?)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
    }
}
impl TryFrom<&PathBuf> for Config {
    type Error = Error;
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(value.as_path())
    }
}

pub fn generate_ca_signed_cert(
    cert_path: &Path,
    cert_data: &[u8],
    key_path: &Path,
    key_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (key_data, cert_data) = generate_ca_signed_cert_data(cert_data, key_data)
        .map_err(|e| Error::new(ErrorKind::Other, format!("OpenSSL Errors: {:?}", e)))?;
    write_ssl_cert_and_key(cert_path, &cert_data, key_path, &key_data, true)?;
    Ok((key_data, cert_data))
}

fn write_ssl_cert_and_key(
    cert_path: &Path,
    cert_data: &[u8],
    key_path: &Path,
    key_data: &[u8],
    overwrite: bool,
) -> Result<(), Error> {
    if cert_path.exists() && overwrite {
        fs::remove_file(cert_path)?;
    }
    let mut crt = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(cert_path)?;
    crt.write_all(cert_data)?;
    crt.flush()?;
    if key_path.exists() && overwrite {
        fs::remove_file(key_path)?;
    }
    let mut key = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(key_path)?;
    key.write_all(key_data)?;
    key.flush()
}

fn generate_ca_signed_cert_data(
    cert_data: &[u8],
    key_data: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let root_cert = X509::from_pem(cert_data)?;
    let root_key = PKey::from_rsa(Rsa::private_key_from_pem(key_data)?)?;
    let cert_key = Rsa::generate(2048)?;
    let pub_key = PKey::from_rsa(cert_key)?;
    let mut cert = X509Builder::new()?;
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("O", "Chia").unwrap();
    x509_name
        .append_entry_by_text("OU", "Organic Farming Division")
        .unwrap();
    x509_name.append_entry_by_text("CN", "Chia").unwrap();
    let name = x509_name.build();
    cert.set_subject_name(name.as_ref())?;
    cert.set_issuer_name(root_cert.issuer_name())?;
    cert.set_pubkey(pub_key.as_ref())?;
    let mut bn = BigNum::new()?;
    bn.rand(32, MsbOption::MAYBE_ZERO, true)?;
    cert.set_serial_number(bn.to_asn1_integer()?.as_ref())?;
    cert.set_not_before(
        Asn1Time::from_unix(
            SystemTime::now()
                .sub(Duration::from_secs(60 * 60 * 24))
                .duration_since(UNIX_EPOCH)
                .expect("Should be later than Epoch")
                .as_secs() as i64,
        )?
        .as_ref(),
    )?;
    cert.set_not_after(Asn1Time::from_str_x509("210008020000000")?.as_ref())?;
    let ctx = cert.x509v3_context(Some(root_cert.as_ref()), None);
    let san = SubjectAlternativeName::new().dns("chia.net").build(&ctx)?;
    cert.append_extension(san)?;
    cert.sign(root_key.as_ref(), MessageDigest::sha256())?;
    let x509 = cert.build();
    Ok((x509.to_pem()?, x509.public_key()?.public_key_to_pem()?))
}

pub fn make_ca_cert(cert_path: &Path, key_path: &Path) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let (key_data, cert_data) = make_ca_cert_data()
        .map_err(|e| Error::new(ErrorKind::Other, format!("OpenSSL Errors: {:?}", e)))?;
    write_ssl_cert_and_key(cert_path, &cert_data, key_path, &key_data, true)?;
    Ok((key_data, cert_data))
}

fn make_ca_cert_data() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let root_key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("O", "Chia").unwrap();
    x509_name
        .append_entry_by_text("OU", "Organic Farming Division")
        .unwrap();
    x509_name.append_entry_by_text("CN", "Chia").unwrap();
    let mut cert = X509Builder::new()?;
    let name = x509_name.build();
    cert.set_subject_name(name.as_ref())?;
    cert.set_issuer_name(name.as_ref())?;
    cert.set_pubkey(root_key.as_ref())?;
    let mut bn = BigNum::new()?;
    bn.rand(32, MsbOption::MAYBE_ZERO, true)?;
    cert.set_serial_number(bn.to_asn1_integer()?.as_ref())?;
    cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
    let base = BasicConstraints::new().critical().ca().build()?;
    cert.append_extension(base)?;
    cert.sign(root_key.as_ref(), MessageDigest::sha256())?;
    let x509 = cert.build();
    Ok((x509.to_pem()?, x509.public_key()?.public_key_to_pem()?))
}

const ALL_PRIVATE_NODE_NAMES: [&str; 8] = [
    "full_node",
    "wallet",
    "farmer",
    "harvester",
    "timelord",
    "crawler",
    "data_layer",
    "daemon",
];

const ALL_PUBLIC_NODE_NAMES: [&str; 6] = [
    "full_node",
    "wallet",
    "farmer",
    "introducer",
    "timelord",
    "data_layer",
];

pub async fn create_all_ssl(root_path: &Path, overwrite: bool) -> Result<(), Error> {
    let ssl_dir = root_path.join(Path::new("/ssl/"));
    let ca_dir = ssl_dir.join(Path::new("/ca/"));
    create_dir_all(&ca_dir).await?;
    let private_ca_key_path = ca_dir.join("private_ca.key");
    let private_ca_crt_path = ca_dir.join("private_ca.crt");
    let chia_ca_crt_path = ca_dir.join("chia_ca.crt");
    let chia_ca_key_path = ca_dir.join("chia_ca.key");
    write_ssl_cert_and_key(
        &chia_ca_crt_path,
        CHIA_CA_CRT.as_bytes(),
        &chia_ca_key_path,
        CHIA_CA_KEY.as_bytes(),
        true,
    )?;
    let (key, crt) = if !private_ca_crt_path.exists() || !private_ca_key_path.exists() {
        make_ca_cert(&private_ca_crt_path, &private_ca_key_path)?
    } else {
        (
            fs::read(private_ca_key_path)?,
            fs::read(private_ca_crt_path)?,
        )
    };
    generate_ssl_for_nodes(
        &ssl_dir,
        &crt,
        &key,
        "private",
        &ALL_PRIVATE_NODE_NAMES,
        overwrite,
    )
    .await?;
    generate_ssl_for_nodes(
        &ssl_dir,
        CHIA_CA_CRT.as_bytes(),
        CHIA_CA_KEY.as_bytes(),
        "public",
        &ALL_PUBLIC_NODE_NAMES,
        false,
    )
    .await
}

async fn generate_ssl_for_nodes(
    ssl_dir: &Path,
    crt: &[u8],
    key: &[u8],
    prefix: &str,
    nodes: &[&str],
    overwrite: bool,
) -> Result<(), Error> {
    for node_name in nodes {
        let node_dir = ssl_dir.join(Path::new(*node_name));
        create_dir_all(&node_dir).await?;
        let key_path = node_dir.join(Path::new(&format!("{prefix}_{node_name}.key")));
        let crt_path = node_dir.join(Path::new(&format!("{prefix}_{node_name}.crt")));
        if key_path.exists() && crt_path.exists() && !overwrite {
            continue;
        }
        generate_ca_signed_cert(&crt_path, crt, &key_path, key)?;
    }
    Ok(())
}
