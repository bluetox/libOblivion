use base64::Engine;
use jni::JNIEnv;
use jni::objects::GlobalRef;
use jni::objects::JString;
use jni::sys::{jint, jstring};
use log::info;
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
        rt.block_on(async { 
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
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_example_oblivion_RustBridge_getChats(
    env: JNIEnv,
    _class: JObject,
) -> jstring {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            panic!()
        }
    };
    let res: Result<Vec<(Vec<u8>, std::string::String)>, Box<dyn Error + Send + Sync>> =
        rt.block_on(async { database::get_chats().await });
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
fn decode_b64(string: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    general_purpose::STANDARD
        .decode(string)
        .map_err(|_| "Invalid base64".into())
}
