use sqlx::{sqlite::SqlitePoolOptions, Row};

async fn main() -> Result<(), sqlx::Error> {
    let db_path = "/data/data/com.example.app/databases/storage.db";
    let db_url = format!("sqlite://{}", db_path);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    // Create a table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            seed BYTES NOT NULL,
            pwd_hash BYTES NOT NULL
        );
        "#
    )
    .execute(&pool)
    .await?;

    // Insert a user
    sqlx::query("INSERT INTO users (name, email) VALUES (?, ?)")
        .bind("Alice")
        .bind("alice@example.com")
        .execute(&pool)
        .await?;

    // Fetch rows
    let rows = sqlx::query("SELECT id, name, email FROM users")
        .fetch_all(&pool)
        .await?;

    for row in rows {
        let id: i64 = row.get("id");
        let name: String = row.get("name");
        let email: String = row.get("email");
        println!("User {id}: {name} <{email}>");
    }

    Ok(())
}
