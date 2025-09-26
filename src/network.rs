use pq_tls::objects::{Ed25519Keypair, FrodoKem1344Keypair, PqTlsSettings, X25519Keypair};
use pq_tls::sign_obj::{Falcon1024Keypair, FalconPadded1024Keypair};
use ed25519_dalek::ed25519::signature::{SignerMut};
use rustls::pki_types::{CertificateDer, ServerName};
use std::fmt::format;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use tokio_rustls::{TlsConnector, rustls};
use rustls::pki_types::pem::PemObject;
use tokio_rustls::client::TlsStream;
use std::error::Error as StdError;
use pq_tls::client::PqTlsClient;
use lazy_static::lazy_static;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;
use rand::rngs::OsRng;
use std::sync::Mutex;
use std::sync::Arc;
use jni::sys::jint;
use log::info;
use std::io;

use crate::database;

static CERT_PEM: &[u8] = include_bytes!("cert.pem");

const AUTH_PACKET_HEADER_BYTE: u8 = 0;
const SERVER_IP: &'static str = "148.113.191.144";


lazy_static! {
    static ref GLOBAL_STREAM: Mutex<Option<PqTlsClient>> = Mutex::new(None);
}


pub fn set_stream(stream: PqTlsClient) {
    let mut global = GLOBAL_STREAM.lock().unwrap();
    *global = Some(stream);
}

pub fn get_stream() -> Result<PqTlsClient, String>{
    let stream_guard = GLOBAL_STREAM.lock().unwrap();
    let stream = stream_guard.as_ref().ok_or("Database not initialized")?;
    Ok(stream.clone())
}

pub async fn create_connection() -> Result<TlsStream<TcpStream>, Box<dyn StdError + Send + Sync + 'static>> {
    let addr = (SERVER_IP, 8443)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

    let domain = "localhost";

    let mut root_cert_store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CERT_PEM) {
        root_cert_store.add(cert?)?;
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await?;

    let domain = ServerName::try_from(domain)?.to_owned();
    let stream = connector.connect(domain, stream).await?;
    Ok(stream)
}

pub fn init_connexion() -> jint {
    android_logger::init_once(android_logger::Config::default().with_min_level(log::Level::Info));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return -1;
        }
    };
    info!("About to try to connect to the server");
    rt.block_on(async {
        let stream = create_connection().await.unwrap();
        info!("Got tls connexion to the server");
        let mut settings = PqTlsSettings {
            pq_signing_keys: pq_tls::objects::PqSigningKeys::FalconPadded1024(
                FalconPadded1024Keypair::generate(),
            ),
            c_signing_keys: pq_tls::objects::CSigningKeys::Ed25519(Ed25519Keypair::generate()),
            pq_aka_keys: pq_tls::objects::PqAKAKeys::FrodoKem1344(FrodoKem1344Keypair::generate()),
            c_aka_keys: pq_tls::objects::CAKAKeys::X25519(X25519Keypair::generate()),
        };
        let mut client = pq_tls::client::PqTlsClient::new(stream, &mut settings)
            .await
            .unwrap();

        let auth_packet = create_auth_packet();
        client.write(&auth_packet).await.unwrap();
        info!("Sent auth request");
       
        loop {
            let auth_response = client.pull_packet().await.unwrap();
            match auth_response[0] {
                0 => {
                    break;
                },
                1 => panic!(),
                2 => {
                    info!("Send Long terme Keys first auth");
                    let packet = create_first_auth_packet();
                    client.write(&packet).await.unwrap();
                },
                3 => {
                    info!("Ephemeral Keys needed");

                    let packet = create_ephemeral_key_packet();
                    println!("Wrote");
                    client.write(&packet).await.unwrap();
                },
                4 => {
                    info!("Refresh of Atomic keys needed, amount");
                    let num: [u8; 8] = auth_response[1..9]
                            .try_into()
                            .map_err(|e| format!("Error: {}", e)).unwrap();
                    for i in 0..u64::from_be_bytes(num) {
                        let packet = create_atomic_key_packet(i);
                        client.write(&packet).await.unwrap();
                    }
                    
                }
                _ => panic!()
            }
        }

        set_stream(client);
    });
    println!("Connexion initialised");
    return 0;
}

const PACKET_HEADER_BYTE: u8 = 1; // or whatever constant you use
const PACKET_HEADER_SIZE: usize = 3;

/// === AUTH PACKET ===
pub fn create_auth_packet() -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let mut header = [0u8; PACKET_HEADER_SIZE];
    header[0] = PACKET_HEADER_BYTE;

    let mut session_guard = database::GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_mut().expect("Session not initialized");

    let ed_pk = session.ed25519_keypair.public.as_bytes();
    let ml_dsa_pk = session.ml_dsa_keypair.public();

    // what is being signed
    let mut sign_part = Vec::new();
    sign_part.extend_from_slice(ed_pk);
    sign_part.extend_from_slice(ml_dsa_pk);

    let ml_dsa_sign = session.ml_dsa_keypair.sign(&sign_part);
    let ed_sign = session.ed25519_keypair.secret.sign(&sign_part);

    // === build ===
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&ed_sign.to_bytes());        // 64B
    packet.extend_from_slice(ml_dsa_sign.bytes());        // 4595B
    packet.extend_from_slice(ed_pk);                      // 32B
    packet.extend_from_slice(ml_dsa_pk);                  // 2592B

    packet
}

/// === FIRST AUTH PACKET ===
fn create_first_auth_packet() -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let mut header = [0u8; PACKET_HEADER_SIZE];
    header[0] = 2; // "first auth" tag

    let mut rng = OsRng;
    let kyber_keypair = kyber::kyber1024::keypair(&mut rng, None);

    let mut session_guard = database::GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_mut().expect("Session not initialized");

    let ed_pk = session.ed25519_keypair.public.as_bytes();
    let ml_dsa_pk = session.ml_dsa_keypair.public();
    let kyber_pk = &kyber_keypair.public;

    let mut sign_part = Vec::new();
    sign_part.extend_from_slice(ed_pk);
    sign_part.extend_from_slice(ml_dsa_pk);
    sign_part.extend_from_slice(kyber_pk);

    let ml_dsa_sign = session.ml_dsa_keypair.sign(&sign_part);
    let ed_sign = session.ed25519_keypair.secret.sign(&sign_part);

    packet.extend_from_slice(&header);
    packet.extend_from_slice(&ed_sign.to_bytes());        // 64B
    packet.extend_from_slice(ml_dsa_sign.bytes());        // 4595B
    packet.extend_from_slice(ed_pk);                      // 32B
    packet.extend_from_slice(ml_dsa_pk);                  // 2592B
    packet.extend_from_slice(kyber_pk);                   // 1568B

    packet
}

/// === EPHEMERAL KEY PACKET ===
fn create_ephemeral_key_packet() -> Vec<u8> {
    let now = SystemTime::now();
    let seven_days = Duration::from_secs(7 * 24 * 60 * 60);
    let future = now + seven_days;
    let ts = future.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let ts_bytes: [u8; 8] = ts.to_be_bytes();

    let mut packet: Vec<u8> = Vec::new();
    let mut header = [0u8; PACKET_HEADER_SIZE];
    header[0] = 3;

    let mut rng = OsRng;

    let kyber_keypair = kyber::kyber1024::keypair(&mut rng, None);

    let mut session_guard = database::GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_mut().expect("Session not initialized");

    let kyber_pk = &kyber_keypair.public;

    let mut sign_part = Vec::new();
    sign_part.extend_from_slice(kyber_pk);                   // 1568B
    sign_part.extend_from_slice(&ts_bytes);                  // 8B

    let ml_dsa_sign = session.ml_dsa_keypair.sign(&sign_part);
    let ed_sign = session.ed25519_keypair.secret.sign(&sign_part);

    packet.extend_from_slice(&header);
    packet.extend_from_slice(&ed_sign.to_bytes());        // 64B
    packet.extend_from_slice(ml_dsa_sign.bytes());        // 4595B
    packet.extend_from_slice(&sign_part);

               

    packet
}

fn create_atomic_key_packet(id: u64) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let mut header = [0u8; PACKET_HEADER_SIZE];
    header[0] = 4; // "first auth" tag

    let mut rng = OsRng;
    let kyber_keypair = kyber::kyber1024::keypair(&mut rng, None);

    let mut session_guard = database::GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_mut().expect("Session not initialized");

    let kyber_pk = &kyber_keypair.public;

    let mut sign_part = Vec::new();
    sign_part.extend_from_slice(kyber_pk);

    let ml_dsa_sign = session.ml_dsa_keypair.sign(&sign_part);
    let ed_sign = session.ed25519_keypair.secret.sign(&sign_part);

    packet.extend_from_slice(&header);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&ed_sign.to_bytes());        // 64B
    packet.extend_from_slice(ml_dsa_sign.bytes());        // 4595B
    packet.extend_from_slice(&sign_part);

    packet
}

fn create_send_message_packet(dst_user_id: Vec<u8>, message: &str) -> Vec<u8> {
    let mut packet: Vec<u8> = Vec::new();
    let mut header = [0u8; PACKET_HEADER_SIZE];
    header[0] = 0x10; // Message idk
    
    let mut session_guard = database::GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_mut().expect("Session not initialized");

    let mut sign_part = Vec::new();
    sign_part.extend_from_slice(&dst_user_id);

    let ml_dsa_sign = session.ml_dsa_keypair.sign(&sign_part);
    let ed_sign = session.ed25519_keypair.secret.sign(&sign_part);

    packet.extend_from_slice(&header);
    packet.extend_from_slice(&ed_sign.to_bytes());        // 64B
    packet.extend_from_slice(ml_dsa_sign.bytes());        // 4595B
    packet.extend_from_slice(&sign_part);

    packet
}


pub async fn send_new_message(dst_user_id: Vec<u8>, message: &str) -> Result<(), String> {
    // Convert get_stream() error to String
    let stream = get_stream().map_err(|e| format!("Failed to get stream: {}", e))?;

    let packet = create_send_message_packet(dst_user_id, message);

    // Convert write() error to String
    stream.write(&packet)
        .await
        .map_err(|e| format!("Error writing to socket: {}", e))?;

    Ok(())
}
