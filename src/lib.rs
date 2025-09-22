use base64::Engine;
use bincode::{Decode, Encode};
use jni::JNIEnv;
use jni::objects::GlobalRef;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jobject, jstring};
use pq_tls::objects::{Ed25519Keypair, FrodoKem1344Keypair, PqTlsSettings, X25519Keypair};
use pq_tls::sign_obj::{Falcon1024Keypair, FalconPadded1024Keypair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::error::Error as StdError;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::io::{AsyncWriteExt, copy, split, stdin as tokio_stdin, stdout as tokio_stdout};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsConnector, rustls};

use jni::objects::{JObject, JValue};
use lazy_static::lazy_static;
use pq_tls::client::PqTlsClient;
use std::sync::Mutex;

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
        )
        .unwrap();
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
    mut env: JNIEnv,
    _class: JObject,
    db_path: JString,
    callback: JObject,
) -> jint {
    let global = env.new_global_ref(callback).unwrap();
    *CALLBACK.lock().unwrap() = Some(global);

    android_logger::init_once(android_logger::Config::default().with_min_level(log::Level::Info));
    std::panic::set_hook(Box::new(|info| {
        log::error!("panic: {:?}", info);
    }));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            return -1;
        }
    };

    let db_path: String = env
        .get_string(&db_path)
        .expect("Couldn't get Java string!")
        .into();

    if let Err(e) = rt.block_on(async { database::init_db(db_path.clone()).await }) {
        return -1;
    }

    //run_client();

    let java_vm = env.get_java_vm().unwrap();
    std::thread::spawn(move || {
        loop {
            let mut env = java_vm.attach_current_thread().unwrap();
            notify_new_message(&mut env, "Hi josh sup ?");
            std::thread::sleep(tokio::time::Duration::from_millis(500));
        }
    });
    return 0;
}
use log::error;
use log::info;
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_createProfile(
    mut env: JNIEnv,
    _class: JObject,
    password: JString,
    username: JString,
) {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            return;
        }
    };

    let password: String = env
        .get_string(&password)
        .expect("Couldn't get Java string!")
        .into();
    let username: String = env
        .get_string(&username)
        .expect("Couldn't get Java string!")
        .into();

    let res = rt.block_on(async { database::create_profile(&password, &username).await });
    if res.is_err() {
        info!("create table error: {:?}", res);
    }
}

fn run_client() -> jint {
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
            pq_signing_keys: pq_tls::objects::PqSigningKeys::FalconPadded1024(
                FalconPadded1024Keypair::generate(),
            ),
            c_signing_keys: pq_tls::objects::CSigningKeys::Ed25519(Ed25519Keypair::generate()),
            pq_aka_keys: pq_tls::objects::PqAKAKeys::FrodoKem1344(FrodoKem1344Keypair::generate()),
            c_aka_keys: pq_tls::objects::CAKAKeys::X25519(X25519Keypair::generate()),
        };
        let client = pq_tls::client::PqTlsClient::new(stream, &mut settings)
            .await
            .unwrap();
        set_stream(client);
    });
    return 0;
}
use std::error::Error;

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getProfiles(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            panic!()
        }
    };
    let res: Result<Vec<database::Profile>, Box<dyn Error + Send + Sync>> =
        rt.block_on(async { database::get_all_profiles().await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
    }
    let mut profiles = Vec::new();
    for profile in res.unwrap() {
        profiles.push(profile.export());
    }
    let json = serde_json::to_string(&profiles).unwrap();
    let output = env.new_string(json).unwrap();
    output.into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_loadWithProfile(
    mut env: JNIEnv,
    _class: JObject,
    user_id: JString,
    password: JString,
) -> jint {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            panic!()
        }
    };
    let user_id_str: String = env
        .get_string(&user_id)
        .expect("Couldn't get userId string")
        .into();
    let password_str: String = env
        .get_string(&password)
        .expect("Couldn't get password string")
        .into();
    let user_id_bytes = decode_b64(&user_id_str).expect("Couldn't decode b64");
    let res =
        rt.block_on(async { database::load_with_profile(&user_id_bytes, &password_str).await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
        return -1;
    }
    return 0;
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_createChat(
    mut env: JNIEnv,
    _class: JObject,
    user_id: JString,
    chat_name: JString,
) -> jint {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            panic!()
        }
    };
    let user_id_str: String = env
        .get_string(&user_id)
        .expect("Couldn't get userId string")
        .into();
    let chat_name_str: String = env
        .get_string(&chat_name)
        .expect("Couldn't get password string")
        .into();
    let user_id_bytes = decode_b64(&user_id_str).expect("Couldn't decode b64");
    let res =
        rt.block_on(async { database::create_chat(&user_id_bytes, &chat_name_str).await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
        return -1;
    }
    return 0;
}

use base64::engine::general_purpose;
fn decode_b64(string: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    general_purpose::STANDARD
        .decode(string)
        .map_err(|_| "Invalid base64".into())
}
