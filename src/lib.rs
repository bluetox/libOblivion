use base64::Engine;
use jni::JNIEnv;
use jni::objects::GlobalRef;
use jni::objects::JString;
use jni::sys::{jint, jstring};
use log::info;
use serde::Serialize;
use std::error::Error;
use std::net;
use jni::objects::{JObject, JValue};
use lazy_static::lazy_static;
use std::sync::Mutex;
use zeroizing_alloc::ZeroAlloc;

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
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            panic!()
        }
    };
    let res: Result<Vec<ProfileExported>, Box<dyn Error + Send + Sync>> =
        rt.block_on(async { database::get_all_profiles().await });
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
        TOKIO_RT.block_on(async { 
            database::load_with_profile(&user_id_bytes, &password_str).await 
        });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
        return -1;
    }
    network::init_connexion();
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
    let res =
        TOKIO_RT.block_on(async { database::create_chat(&user_id_bytes, &chat_name_str).await });
    if res.is_err() {
        info!("Error fetching profiles: {:?}", res);
        return -1;
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
                    dest_id_b64: base64::engine::general_purpose::STANDARD.encode(id_dest),
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
    general_purpose::STANDARD
        .decode(string)
        .map_err(|_| "Invalid base64".into())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getCurrentProfile(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let res=
        TOKIO_RT.block_on(async { database::get_current_profile().await });
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
    message: JString
) -> jint {
    // Convert JStrings safely
    let user_id_b64: String = match env.get_string(&user_id_b64) {
        Ok(s) => s.into(),
        Err(_) => return -1, // invalid JString
    };

    let message: String = match env.get_string(&message) {
        Ok(s) => s.into(),
        Err(_) => return -2, // invalid JString
    };

    // Decode Base64 safely
    let user_id = match decode_b64(&user_id_b64) {
        Ok(bytes) => bytes,
        Err(_) => return -3, // invalid base64
    };

    // Run async sending safely
    TOKIO_RT.spawn(async move {
        if let Err(e) = network::send_new_message(user_id, &message).await {
            info!("send_new_message error: {}", e);
        }
    });

    0
}
