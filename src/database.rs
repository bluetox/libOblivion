use std::{path::Path, sync::Mutex};

use base64::{Engine, engine::general_purpose};
use lazy_static::lazy_static;
use log::{error, info};
use rand::Rng;
use serde::Serialize;
use sqlx::{Pool, Row, Sqlite, sqlite::SqlitePoolOptions};

lazy_static! {
    static ref GLOBAL_POOL: Mutex<Option<sqlx::SqlitePool>> = Mutex::new(None);
}

lazy_static! {
    pub static ref GLOBAL_OBLIVION_SESSION: Mutex<Option<OblivionSession>> = Mutex::new(None);
}

#[derive(Debug)]
pub struct Ed25519Keypair {
    pub public: ed25519_dalek::VerifyingKey,
    pub secret: ed25519_dalek::SigningKey,
}

#[derive(Debug)]
pub struct OblivionSession {
    pub user_id: Vec<u8>,
    pub username: String,
    pub ed25519_keypair: Ed25519Keypair,
    pub ml_dsa_keypair: pure_dsa::Keypair,
}

#[derive(Serialize, Debug)]
pub struct ProfileExported {
    pub user_id: String,
    pub username: String,
    pub created_at: String,
}

#[derive(Serialize, Debug)]
pub struct Profile {
    pub user_id: Vec<u8>,
    pub username: String,
    pub seed: Vec<u8>,
    pub pwd_hash: Vec<u8>,
    pub created_at: String,
}

impl Profile {
    pub fn export(&self) -> ProfileExported {
        ProfileExported {
            user_id: encode_bytes(&self.user_id),
            username: self.username.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

fn encode_bytes(bytes: &Vec<u8>) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn get_pool() -> Result<Pool<Sqlite>, Box<dyn std::error::Error + Send + Sync>> {
    let pool_guard = GLOBAL_POOL.lock().unwrap();
    let pool = pool_guard.as_ref().ok_or("Database not initialized")?;
    Ok(pool.clone())
}

pub async fn init_db<P: AsRef<Path>>(
    db_path: P,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_path = db_path.as_ref();

    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

    info!("Opening sqlite db at: {}", db_url);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .map_err(|e| {
            error!("sqlx connect error: {}", e);
            e
        })?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS profiles (
            userId BLOB PRIMARY KEY,
            username TEXT NOT NULL,
            seed BLOB NOT NULL,
            pwdHash BLOB NOT NULL,
            createdAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS chats (
            idDest BLOB NOT NULL,
            idReceiver BLOB NOT NULL,
            name TEXT NOT NULL,
            updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(idReceiver, idDest)
        );
        "#,
    )
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("create table error: {}", e);
        e
    })?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            idReceiver BLOB NOT NULL,
            idDest BLOB NOT NULL,
            content TEXT NOT NULL,
            updatedAt TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .execute(&pool)
    .await?;

    *GLOBAL_POOL.lock().unwrap() = Some(pool.clone());
    info!("Database initialized successfully at {}", db_path.display());

    Ok(())
}

pub async fn create_profile(
    password: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill(&mut seed);
    let pool = get_pool()?;

    let ml_algo = pure_dsa::Algorithm::Mode5;
    let ml_keypair = ml_algo.generate_with_seed(&seed);

    let ed_secret = ed25519_dalek::SigningKey::from_bytes(&seed);
    let ed_public = ed25519_dalek::VerifyingKey::from(&ed_secret);
    let mut hash = blake3::Hasher::new();

    hash.update(ml_keypair.public());
    hash.update(ed_public.as_bytes());

    let user_id_hash = hash.finalize().as_bytes().to_vec();
    let pwd_hash = blake3::hash(password.as_bytes()).as_bytes().to_vec();

    sqlx::query("INSERT INTO profiles (userId, username, seed, pwdHash) VALUES (?, ?, ?, ?)")
        .bind(user_id_hash)
        .bind(username)
        .bind(&seed[..])
        .bind(pwd_hash)
        .execute(&pool)
        .await?;
    info!("New profile {} created", username);
    Ok(())
}

pub async fn get_all_profiles()
-> Result<Vec<ProfileExported>, Box<dyn std::error::Error + Send + Sync>> {
    let pool = get_pool()?;

    let rows = sqlx::query("SELECT userId, username, seed, pwdHash, createdAt FROM profiles")
        .fetch_all(&pool)
        .await?;

    let profiles = rows
        .into_iter()
        .map(|row| ProfileExported {
            user_id: encode_bytes(&row.get::<Vec<u8>, _>("userId")),
            username: row.get::<String, _>("username"),
            created_at: row.get::<String, _>("createdAt"),
        })
        .collect();

    Ok(profiles)
}
pub async fn get_current_profile()
-> Result<ProfileExported, Box<dyn std::error::Error + Send + Sync>> {
    let pool = get_pool()?;

    let session_guard = GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_ref().unwrap();
    let user_id = &session.user_id;
    let row = sqlx::query("SELECT username, createdAt FROM profiles WHERE userId = ?")
        .bind(user_id)
        .fetch_one(&pool)
        .await?;

    let username = row.get::<String, _>("username");
    let created_at = row.get::<String, _>("createdAt");

    let profile = ProfileExported {
        user_id: encode_bytes(&user_id),
        username,
        created_at,
    };

    Ok(profile)
}

pub async fn load_with_profile(
    user_id: &[u8],
    password: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = get_pool()?;

    let row = sqlx::query(
        "SELECT userId, username, seed, pwdHash, createdAt FROM profiles WHERE userId = ?",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await?;

    let user_id: Vec<u8> = row.try_get("userId")?;
    let username: String = row.try_get("username")?;
    let seed: Vec<u8> = row.try_get("seed")?;
    let pwd_hash: Vec<u8> = row.try_get("pwdHash")?;

    let input_pwd_hash = blake3::hash(password.as_bytes()).as_bytes().to_vec();

    if input_pwd_hash != pwd_hash {
        return Err("Invalid password".into());
    }

    let seed_arr: [u8; 32] = seed.try_into().map_err(|_| "Seed is not 32 bytes")?;

    let ml_algo = pure_dsa::Algorithm::Mode5;
    let ml_keypair = ml_algo.generate_with_seed(&seed_arr);

    let ed_secret = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    let ed_public = ed25519_dalek::VerifyingKey::from(&ed_secret);

    let ed_keypair = Ed25519Keypair {
        public: ed_public,
        secret: ed_secret,
    };

    let session = OblivionSession {
        user_id,
        username,
        ed25519_keypair: ed_keypair,
        ml_dsa_keypair: ml_keypair,
    };

    *GLOBAL_OBLIVION_SESSION.lock().unwrap() = Some(session);
    Ok(())
}

pub async fn create_chat(
    dst_user_id: &[u8],
    chat_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = get_pool()?;
    let session_guard = GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_ref().unwrap();
    let profile_id = &session.user_id;
    sqlx::query("INSERT INTO chats (idDest, name, idReceiver) VALUES (?, ?, ?)")
        .bind(dst_user_id)
        .bind(chat_name)
        .bind(profile_id)
        .execute(&pool)
        .await?;
    info!("New chat {} created", chat_name);
    Ok(())
}

pub async fn get_chats() -> Result<Vec<(Vec<u8>, String)>, Box<dyn std::error::Error + Send + Sync>>
{
    let pool = get_pool()?;
    let session_guard = GLOBAL_OBLIVION_SESSION.lock().unwrap();
    let session = session_guard.as_ref().ok_or("No session available")?;
    let profile_id = &session.user_id;

    let rows =
        sqlx::query("SELECT idDest, name FROM chats WHERE idReceiver = ? ORDER BY updatedAt DESC")
            .bind(profile_id)
            .fetch_all(&pool)
            .await?;

    let chats = rows
        .into_iter()
        .map(|row| {
            let id_dest: Vec<u8> = row.try_get("idDest").unwrap_or_default();
            let name: String = row.try_get("name").unwrap_or_default();
            (id_dest, name)
        })
        .collect();

    Ok(chats)
}

pub async fn chat_exists(user_id: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let pool = get_pool().expect("Failed to get DB pool");
    let session_guard = GLOBAL_OBLIVION_SESSION.lock()?;
    let session = session_guard.as_ref().ok_or("No session available")?;
    let profile_id = &session.user_id;

    let row = sqlx::query("SELECT 1 FROM chats WHERE idReceiver = ? AND idDest = ? LIMIT 1")
        .bind(profile_id)
        .bind(user_id)
        .fetch_optional(&pool)
        .await?;

    Ok(if row.is_some() { true } else { false })
}
