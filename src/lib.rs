use std::{error::Error, sync::Mutex};

use base64::Engine;
use jni::{
    JNIEnv, JavaVM,
    objects::{GlobalRef, JObject, JString, JValue},
    sys::{jint, jstring},
};
use lazy_static::lazy_static;
use log::info;
use zeroizing_alloc::ZeroAlloc;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::DateTime;
use sqlx::types::chrono::Utc;
use std::sync::RwLock;
mod database;
mod network;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);

lazy_static! {
    static ref CALLBACK: Mutex<Option<GlobalRef>> = Mutex::new(None);
}

lazy_static! {
    static ref TOKIO_RT: tokio::runtime::Runtime = tokio::runtime::Runtime::new().unwrap();
}


lazy_static! {
    pub static ref NEW_CHAT_SETUP: RwLock<Option<(Vec<u8>, String)>> =
        RwLock::new(None);
}

use std::sync::Arc;
pub struct SafeJavaVM(pub JavaVM);

// Assert thread-safety for JavaVM (this is OK in practice: JavaVM is a VM handle)
unsafe impl Send for SafeJavaVM {}
unsafe impl Sync for SafeJavaVM {}
lazy_static! {
    static ref JVM: Mutex<Option<Arc<JavaVM>>> = Mutex::new(None);
}

fn notify_new_message(env: &mut JNIEnv, message: &str) {
    info!("Notifying callback");
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

    let db_path: String = env
        .get_string(&db_path)
        .expect("Couldn't get Java string!")
        .into();

    if let Err(e) = TOKIO_RT.block_on(async { database::init_db(db_path.clone()).await }) {
        info!("Error Init Database {:?}", e);
        return -1;
    }

    return 0;
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_createProfile(
    mut env: JNIEnv,
    _class: JObject,
    password: JString,
    username: JString,
) {
    let password: String = env
        .get_string(&password)
        .expect("Couldn't get Java string!")
        .into();
    let username: String = env
        .get_string(&username)
        .expect("Couldn't get Java string!")
        .into();

    let res = TOKIO_RT.block_on(async { database::create_profile(&password, &username).await });
    if res.is_err() {
        info!("create table error: {:?}", res);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getProfiles(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let res: Result<Vec<ProfileExported>, Box<dyn Error + Send + Sync>> =
        TOKIO_RT.block_on(async { database::get_all_profiles().await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
    }
    let mut profiles = Vec::new();
    for profile in res.unwrap() {
        profiles.push(profile);
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
    let jvm = env.get_java_vm().expect("get_java_vm failed");
    *JVM.lock().unwrap() = Some(Arc::new(jvm));
    let user_id_str: String = env
        .get_string(&user_id)
        .expect("Couldn't get userId string")
        .into();
    info!("User id grabbed");
    let password_str: String = env
        .get_string(&password)
        .expect("Couldn't get password string")
        .into();
    info!("password grabbed");
    let user_id_bytes = decode_b64(&user_id_str).expect("Couldn't decode b64");
    info!("User id decoded");
    let res = TOKIO_RT
        .block_on(async { database::load_with_profile(&user_id_bytes, &password_str).await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
        return -1;
    }

    network::init_connexion(&mut env);
    return 0;
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_createChat(
    mut env: JNIEnv,
    _class: JObject,
    user_id: JString,
    chat_name: JString,
) -> jint {
    let user_id_str: String = env
        .get_string(&user_id)
        .expect("Couldn't get userId string")
        .into();
    let chat_name_str: String = env
        .get_string(&chat_name)
        .expect("Couldn't get password string")
        .into();
    let user_id_bytes = decode_b64(&user_id_str).expect("Couldn't decode b64");
    {
        let mut setup = NEW_CHAT_SETUP.write().unwrap();
        *setup = Some((user_id_bytes.clone(), chat_name_str.clone()));
    }

    return 0;
}
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getChats(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let res: Result<Vec<(Vec<u8>, std::string::String)>, Box<dyn Error + Send + Sync>> =
        TOKIO_RT.block_on(async { database::get_chats().await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
    }
    let chats_json = match res {
        Ok(chats) => {
            // Convert each chat to a serializable struct
            #[derive(serde::Serialize)]
            struct ChatExport {
                dest_id_b64: String,
                name: String,
            }

            let exported: Vec<ChatExport> = chats
                .into_iter()
                .map(|(id_dest, name)| ChatExport {
                    dest_id_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id_dest),
                    name,
                })
                .collect();

            serde_json::to_string(&exported).unwrap_or("[]".to_string())
        }
        Err(e) => {
            log::error!("Error fetching chats: {:?}", e);
            "[]".to_string()
        }
    };

    // Return as Java string
    env.new_string(chats_json)
        .expect("Failed to create jstring")
        .into_raw()
}
use base64::engine::general_purpose;

use crate::database::ProfileExported;
fn decode_b64(string: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(string)
        .map_err(|_| "Invalid base64".into())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getCurrentProfile(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let res = TOKIO_RT.block_on(async { database::get_current_profile().await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
    }
    let json = serde_json::to_string(&res.unwrap()).unwrap();
    let output = env.new_string(json).unwrap();
    output.into_raw()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_sendMessage(
    mut env: JNIEnv,
    _class: JObject,
    user_id_b64: JString,
    message: JString,
) -> jint {
    let user_id_b64: String = match env.get_string(&user_id_b64) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let message: String = match env.get_string(&message) {
        Ok(s) => s.into(),
        Err(_) => return -2,
    };

    let user_id = match decode_b64(&user_id_b64) {
        Ok(bytes) => bytes,
        Err(_) => return -3,
    };
    
    TOKIO_RT.block_on(async move {
        info!("Sending message to {:?}", user_id);
        let status = match database::chat_exists(&user_id).await {
            Ok(exists) => exists,
            Err(e) => {
                info!("Error checking chat existence: {}", e);
                false
            }
        };
        if !status {
            info!("Chat does not exist");
            {
                let setup = NEW_CHAT_SETUP.read().unwrap();
                if let Some((ref uid, ref name)) = *setup {
                    info!("Current setup: {:?}, {:?}", uid, name);
                    let res = database::create_chat(&uid, &name).await;
                    if res.is_err() {
                        info!("Error fetching profiles: {:?}", res);
                    }
                    info!("Chat created in DB");
                };
            }
            // Request the keypackage
            info!("Requesting keypackage");
            network::LISTENER_STOP.notify_waiters();
            
            let mut stream = network::get_stream().unwrap();
            let packet = network::create_request_keypackage_packet(&user_id);
            stream.write(&packet).await.unwrap();
            let packet = stream.pull_packet().await.unwrap();
            info!("Keypackage received");
            let keypackage: KeyPackage = match bincode::deserialize(&packet[1..]){
                Ok(kp) => kp,
                Err(e) => {
                    info!("Failed to deserialize keypackage: {}", e);
                    return;
                }
            };
            

        } else {
            if let Err(e) = network::send_new_message(user_id, &message).await {
                info!("send_new_message error: {}", e);
            };
        }
    });

    0
}


#[derive(Debug, Clone, Serialize, Deserialize)]
struct AtomicKey {
    kem_pk: Vec<u8>,
    signature_of_key: Vec<u8>,
    pq_signature_of_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyPackage {
    long_term_pq_sign_key: Vec<u8>,
    long_term_sign_key: Vec<u8>,
    long_term_kem_key: Vec<u8>,

    eph_kem_pk: Vec<u8>,
    signature_of_key: Vec<u8>,
    pq_signature_of_key: Vec<u8>,
    created_at: DateTime<Utc>,
    
    key_package_id: Vec<u8>,
    atomic_key: AtomicKey,
}
