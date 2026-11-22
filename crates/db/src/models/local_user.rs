use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use ts_rs::TS;
use uuid::Uuid;

/// A local account row. It carries the password hash, so it is deliberately
/// not `Serialize`: send [`LocalUserProfile`] to clients instead.
#[derive(Debug, Clone, FromRow)]
pub struct LocalUser {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The public view of a local account.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
pub struct LocalUserProfile {
    pub id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

impl From<&LocalUser> for LocalUserProfile {
    fn from(user: &LocalUser) -> Self {
        Self {
            id: user.id,
            username: user.username.clone(),
            created_at: user.created_at,
        }
    }
}

impl LocalUser {
    pub async fn count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar!(r#"SELECT COUNT(*) as "count!: i64" FROM local_users"#)
            .fetch_one(pool)
            .await
    }

    /// Usernames are compared case-insensitively (the column is `COLLATE NOCASE`).
    pub async fn find_by_username(
        pool: &SqlitePool,
        username: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            LocalUser,
            r#"SELECT id as "id!: Uuid", username, password_hash,
                      created_at as "created_at!: DateTime<Utc>",
                      updated_at as "updated_at!: DateTime<Utc>"
               FROM local_users
               WHERE username = $1"#,
            username
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_id(pool: &SqlitePool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            LocalUser,
            r#"SELECT id as "id!: Uuid", username, password_hash,
                      created_at as "created_at!: DateTime<Utc>",
                      updated_at as "updated_at!: DateTime<Utc>"
               FROM local_users
               WHERE id = $1"#,
            id
        )
        .fetch_optional(pool)
        .await
    }

    /// Inserts a user. `password_hash` must already be a KDF output, never a
    /// plaintext password. Fails with a unique-constraint error if the
    /// username is taken.
    pub async fn create(
        pool: &SqlitePool,
        username: &str,
        password_hash: &str,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query_as!(
            LocalUser,
            r#"INSERT INTO local_users (id, username, password_hash)
               VALUES ($1, $2, $3)
               RETURNING id as "id!: Uuid", username, password_hash,
                         created_at as "created_at!: DateTime<Utc>",
                         updated_at as "updated_at!: DateTime<Utc>""#,
            id,
            username,
            password_hash
        )
        .fetch_one(pool)
        .await
    }

    /// Inserts the user only if the table is still empty, in one statement, so
    /// two concurrent first-run setups cannot both create an admin.
    pub async fn create_first(
        pool: &SqlitePool,
        username: &str,
        password_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query_as!(
            LocalUser,
            r#"INSERT INTO local_users (id, username, password_hash)
               SELECT $1, $2, $3
               WHERE NOT EXISTS (SELECT 1 FROM local_users)
               RETURNING id as "id!: Uuid", username, password_hash,
                         created_at as "created_at!: DateTime<Utc>",
                         updated_at as "updated_at!: DateTime<Utc>""#,
            id,
            username,
            password_hash
        )
        .fetch_optional(pool)
        .await
    }
}
