use std::error::Error as StdError;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use bincode::{Decode, Encode};
use pq_tls::objects::{Ed25519Keypair, FrodoKem1344Keypair, PqTlsSettings, X25519Keypair};
use pq_tls::sign_obj::{Falcon1024Keypair, FalconPadded1024Keypair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{rustls, TlsConnector};
use jni::objects::GlobalRef;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jint;

use jni::objects::{JObject, JValue};
use lazy_static::lazy_static;
use std::sync::Mutex;
use pq_tls::client::PqTlsClient;

mod database;

static CERT_PEM: &[u8] = include_bytes!("cert.pem");

lazy_static! {
    static ref GLOBAL_STREAM: Mutex<Option<PqTlsClient>> = Mutex::new(None);
}

lazy_static! {
    static ref CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);
}

pub fn set_stream(stream: PqTlsClient) {
    let mut global = GLOBAL_STREAM.lock().unwrap();
    *global = Some(stream);
}

fn notify_new_message(env: &mut JNIEnv, message: &str) {
    if let Some(callback) = &*CALLBACK.lock().unwrap() {
        let java_str = env.new_string(message).unwrap();
        env.call_method(
            callback.as_obj(),
            "onNewMessage",
            "(Ljava/lang/String;)V",
            &[JValue::Object(&java_str.into())],
        ).unwrap();
    }
}

async fn client() -> Result<TlsStream<TcpStream>, Box<dyn StdError + Send + Sync + 'static>> {
    let addr = ("192.168.1.230", 443)
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_init(
    env: JNIEnv,
    _class: JObject,
    callback: JObject,
) {
    let global = env.new_global_ref(callback).unwrap();
    *CALLBACK.lock().unwrap() = Some(global);
        android_logger::init_once(
    android_logger::Config::default().with_min_level(log::Level::Info)
);
    run_client();

    let java_vm = env.get_java_vm().unwrap();
    std::thread::spawn(move || {
        loop {
            let mut env = java_vm.attach_current_thread().unwrap();
            notify_new_message(&mut env, "Hello world");
            std::thread::sleep(tokio::time::Duration::from_millis(500));
        }
    });
} 

fn run_client(
) -> jint {
    android_logger::init_once(android_logger::Config::default().with_min_level(log::Level::Info));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            return -1;
        }
    };

    rt.block_on(async {
        let stream = client().await.unwrap();
        let mut settings = PqTlsSettings {
            pq_signing_keys: pq_tls::objects::PqSigningKeys::FalconPadded1024(FalconPadded1024Keypair::generate()),
            c_signing_keys: pq_tls::objects::CSigningKeys::Ed25519(Ed25519Keypair::generate()),
            pq_aka_keys: pq_tls::objects::PqAKAKeys::FrodoKem1344(FrodoKem1344Keypair::generate()),
            c_aka_keys: pq_tls::objects::CAKAKeys::X25519(X25519Keypair::generate())
        };
        let client = pq_tls::client::PqTlsClient::new(stream, &mut settings).await.unwrap();
        set_stream(client);
    });
    return 0;
}