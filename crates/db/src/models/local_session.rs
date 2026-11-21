use chrono::{DateTime, Utc};
use sqlx::{FromRow, SqlitePool};
use uuid::Uuid;

use super::local_user::LocalUser;

/// A signed-in browser session for a local account. Only the SHA-256 hash of
/// the cookie token is stored.
#[derive(Debug, Clone, FromRow)]
pub struct LocalSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl LocalSession {
    pub async fn create(
        pool: &SqlitePool,
        user_id: Uuid,
        token_hash: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4();
        sqlx::query_as!(
            LocalSession,
            r#"INSERT INTO local_sessions (id, user_id, token_hash, expires_at)
               VALUES ($1, $2, $3, $4)
               RETURNING id as "id!: Uuid", user_id as "user_id!: Uuid", token_hash,
                         created_at as "created_at!: DateTime<Utc>",
                         expires_at as "expires_at!: DateTime<Utc>""#,
            id,
            user_id,
            token_hash,
            expires_at
        )
        .fetch_one(pool)
        .await
    }

    /// Returns the user that owns an unexpired session with this token hash.
    pub async fn find_user_by_token_hash(
        pool: &SqlitePool,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<LocalUser>, sqlx::Error> {
        sqlx::query_as!(
            LocalUser,
            r#"SELECT u.id as "id!: Uuid", u.username, u.password_hash,
                      u.created_at as "created_at!: DateTime<Utc>",
                      u.updated_at as "updated_at!: DateTime<Utc>"
               FROM local_sessions s
               JOIN local_users u ON u.id = s.user_id
               WHERE s.token_hash = $1 AND s.expires_at > $2"#,
            token_hash,
            now
        )
        .fetch_optional(pool)
        .await
    }

    pub async fn delete_by_token_hash(
        pool: &SqlitePool,
        token_hash: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            "DELETE FROM local_sessions WHERE token_hash = $1",
            token_hash
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_expired(pool: &SqlitePool, now: DateTime<Utc>) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!("DELETE FROM local_sessions WHERE expires_at <= $1", now)
            .execute(pool)
            .await?;
        Ok(result.rows_affected())
    }
}
