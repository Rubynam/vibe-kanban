//! Local accounts: username/password sign-in stored in the local SQLite
//! database, with no dependency on the cloud API.
//!
//! # Mode
//!
//! `VK_LOCAL_AUTH` decides whether the local server requires a local sign-in:
//!
//! * `true` / `1` / `on` / `yes`: always required.
//! * `false` / `0` / `off` / `no`: never required (the old behaviour).
//! * unset, empty or `auto`: required only when no cloud API is configured
//!   (`VK_SHARED_API_BASE` is missing or empty). A self-hosted Docker image
//!   therefore gets a login out of the box, while the desktop app, which ships
//!   with the cloud API compiled in, keeps working as before.
//!
//! Local sign-in is a gate in front of the whole local API. It is separate from
//! cloud sign-in (`/api/auth/*`), which still unlocks organizations and remote
//! projects when a cloud API is configured: both can be active at once.
//!
//! # Storage
//!
//! Passwords are hashed with Argon2id (random salt, PHC string format) and
//! verified in constant time by the `password-hash` crate. Session tokens are
//! 256 random bits; only their SHA-256 hash is written to the database.

use std::{fmt::Write as _, sync::OnceLock};

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use chrono::{DateTime, Duration, Utc};
use db::models::{
    local_session::LocalSession,
    local_user::{LocalUser, LocalUserProfile},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use thiserror::Error;
use ts_rs::TS;

pub const LOCAL_AUTH_ENV: &str = "VK_LOCAL_AUTH";
pub const SESSION_COOKIE_NAME: &str = "vk_local_session";
pub const SESSION_TTL_DAYS: i64 = 30;
pub const MIN_USERNAME_LEN: usize = 3;
pub const MAX_USERNAME_LEN: usize = 64;
pub const MIN_PASSWORD_LEN: usize = 8;
/// Caps the work an attacker can make the KDF do per request.
pub const MAX_PASSWORD_LEN: usize = 1024;

#[derive(Debug, Error)]
pub enum LocalAuthError {
    #[error("Invalid username or password")]
    InvalidCredentials,
    #[error("Local sign-in is already set up")]
    AlreadySetUp,
    #[error("Username is already taken")]
    UsernameTaken,
    #[error("{0}")]
    Validation(String),
    #[error("Local sign-in is disabled")]
    Disabled,
    #[error("Password hashing failed: {0}")]
    Hash(String),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// Username and password sent to `/api/local-auth/{setup,login,users}`.
#[derive(Debug, Clone, Deserialize, TS)]
pub struct LocalAuthCredentials {
    pub username: String,
    pub password: String,
}

/// Response from `GET /api/local-auth/status`.
#[derive(Debug, Clone, Serialize, TS)]
pub struct LocalAuthStatusResponse {
    /// Whether this server requires a local sign-in.
    pub enabled: bool,
    /// True when local sign-in is enabled and no account exists yet, so the UI
    /// should offer to create the first one.
    pub setup_required: bool,
    /// The signed-in local account, if the request carried a valid session.
    pub user: Option<LocalUserProfile>,
}

/// Decides from `VK_LOCAL_AUTH` and whether a cloud API is configured.
pub fn resolve_enabled(env_value: Option<&str>, remote_configured: bool) -> bool {
    match env_value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("true" | "1" | "on" | "yes") => true,
        Some("false" | "0" | "off" | "no") => false,
        None | Some("" | "auto") => !remote_configured,
        Some(other) => {
            tracing::warn!(
                value = other,
                "unrecognised {LOCAL_AUTH_ENV} value; falling back to auto"
            );
            !remote_configured
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, LocalAuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| LocalAuthError::Hash(e.to_string()))
}

/// Constant-time check of `password` against a stored PHC string. A malformed
/// hash counts as a mismatch.
pub fn verify_password(password: &str, stored_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A hash of a random password, used to spend the same time on unknown
/// usernames as on known ones, so response timing does not reveal which
/// usernames exist.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        hash_password(&generate_session_token()).expect("hashing a random password")
    })
}

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

pub fn hash_session_token(token: &str) -> String {
    to_hex(&Sha256::digest(token.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn validate_username(username: &str) -> Result<(), LocalAuthError> {
    let len = username.chars().count();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&len) {
        return Err(LocalAuthError::Validation(format!(
            "Username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters"
        )));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(LocalAuthError::Validation(
            "Username may only contain letters, digits, '.', '_' and '-'".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), LocalAuthError> {
    let len = password.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(LocalAuthError::Validation(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(LocalAuthError::Validation(format!(
            "Password must be at most {MAX_PASSWORD_LEN} bytes"
        )));
    }
    Ok(())
}

/// A freshly issued session: the raw token goes into the cookie and is never
/// stored.
#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub user: LocalUser,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct LocalAuthService {
    pool: SqlitePool,
    enabled: bool,
}

impl LocalAuthService {
    pub fn new(pool: SqlitePool, enabled: bool) -> Self {
        Self { pool, enabled }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn status(
        &self,
        token: Option<&str>,
    ) -> Result<LocalAuthStatusResponse, LocalAuthError> {
        if !self.enabled {
            return Ok(LocalAuthStatusResponse {
                enabled: false,
                setup_required: false,
                user: None,
            });
        }
        let user = match token {
            Some(token) => self.authenticate(token).await?,
            None => None,
        };
        let setup_required = user.is_none() && LocalUser::count(&self.pool).await? == 0;
        Ok(LocalAuthStatusResponse {
            enabled: true,
            setup_required,
            user: user.as_ref().map(LocalUserProfile::from),
        })
    }

    /// Creates the first account and signs it in. Refused once any account
    /// exists, so it cannot be used to take over a configured server.
    pub async fn setup(
        &self,
        credentials: &LocalAuthCredentials,
    ) -> Result<IssuedSession, LocalAuthError> {
        self.ensure_enabled()?;
        if LocalUser::count(&self.pool).await? > 0 {
            return Err(LocalAuthError::AlreadySetUp);
        }
        let username = credentials.username.trim();
        validate_username(username)?;
        validate_password(&credentials.password)?;
        let hash = hash_password_blocking(credentials.password.clone()).await?;
        let user = LocalUser::create_first(&self.pool, username, &hash)
            .await?
            .ok_or(LocalAuthError::AlreadySetUp)?;
        self.issue_session(user).await
    }

    /// Adds another account. The route only allows this for a signed-in user.
    pub async fn create_user(
        &self,
        credentials: &LocalAuthCredentials,
    ) -> Result<LocalUser, LocalAuthError> {
        self.ensure_enabled()?;
        let username = credentials.username.trim();
        validate_username(username)?;
        validate_password(&credentials.password)?;
        let hash = hash_password_blocking(credentials.password.clone()).await?;
        LocalUser::create(&self.pool, username, &hash)
            .await
            .map_err(|e| match &e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    LocalAuthError::UsernameTaken
                }
                _ => LocalAuthError::Database(e),
            })
    }

    pub async fn login(
        &self,
        credentials: &LocalAuthCredentials,
    ) -> Result<IssuedSession, LocalAuthError> {
        self.ensure_enabled()?;
        if credentials.password.len() > MAX_PASSWORD_LEN {
            return Err(LocalAuthError::InvalidCredentials);
        }
        let user = LocalUser::find_by_username(&self.pool, credentials.username.trim()).await?;
        let stored_hash = user
            .as_ref()
            .map(|u| u.password_hash.clone())
            .unwrap_or_else(|| dummy_hash().to_string());
        let password = credentials.password.clone();
        let matches = tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
            .await
            .map_err(|e| LocalAuthError::Hash(e.to_string()))?;
        match user {
            Some(user) if matches => self.issue_session(user).await,
            _ => Err(LocalAuthError::InvalidCredentials),
        }
    }

    pub async fn logout(&self, token: &str) -> Result<(), LocalAuthError> {
        LocalSession::delete_by_token_hash(&self.pool, &hash_session_token(token)).await?;
        Ok(())
    }

    /// Returns the user for a valid, unexpired session token.
    pub async fn authenticate(&self, token: &str) -> Result<Option<LocalUser>, LocalAuthError> {
        if token.is_empty() {
            return Ok(None);
        }
        Ok(LocalSession::find_user_by_token_hash(
            &self.pool,
            &hash_session_token(token),
            Utc::now(),
        )
        .await?)
    }

    pub async fn delete_expired_sessions(&self) -> Result<u64, LocalAuthError> {
        Ok(LocalSession::delete_expired(&self.pool, Utc::now()).await?)
    }

    async fn issue_session(&self, user: LocalUser) -> Result<IssuedSession, LocalAuthError> {
        let token = generate_session_token();
        let expires_at = Utc::now() + Duration::days(SESSION_TTL_DAYS);
        LocalSession::create(&self.pool, user.id, &hash_session_token(&token), expires_at).await?;
        Ok(IssuedSession {
            user,
            token,
            expires_at,
        })
    }

    fn ensure_enabled(&self) -> Result<(), LocalAuthError> {
        if self.enabled {
            Ok(())
        } else {
            Err(LocalAuthError::Disabled)
        }
    }
}

async fn hash_password_blocking(password: String) -> Result<String, LocalAuthError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| LocalAuthError::Hash(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    async fn test_service(enabled: bool) -> LocalAuthService {
        // One connection, so every query sees the same in-memory database.
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../db/migrations").run(&pool).await.unwrap();
        LocalAuthService::new(pool, enabled)
    }

    fn creds(username: &str, password: &str) -> LocalAuthCredentials {
        LocalAuthCredentials {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    #[test]
    fn hash_is_argon2id_salted_and_verifies() {
        let a = hash_password("correct horse").unwrap();
        let b = hash_password("correct horse").unwrap();
        assert!(a.starts_with("$argon2id$"));
        assert!(!a.contains("correct horse"));
        assert_ne!(a, b, "each hash gets its own salt");
        assert!(verify_password("correct horse", &a));
        assert!(verify_password("correct horse", &b));
        assert!(!verify_password("wrong horse", &a));
        assert!(!verify_password("correct horse", "not-a-phc-string"));
    }

    #[test]
    fn session_tokens_are_random_and_hashed() {
        let t1 = generate_session_token();
        let t2 = generate_session_token();
        assert_eq!(t1.len(), 64);
        assert_ne!(t1, t2);
        let h = hash_session_token(&t1);
        assert_eq!(h.len(), 64);
        assert_ne!(h, t1);
        assert_eq!(h, hash_session_token(&t1));
    }

    #[test]
    fn mode_resolution() {
        assert!(resolve_enabled(None, false));
        assert!(!resolve_enabled(None, true));
        assert!(resolve_enabled(Some(""), false));
        assert!(!resolve_enabled(Some("auto"), true));
        assert!(resolve_enabled(Some("TRUE"), true));
        assert!(resolve_enabled(Some(" on "), true));
        assert!(!resolve_enabled(Some("0"), false));
        assert!(!resolve_enabled(Some("off"), false));
        assert!(resolve_enabled(Some("bogus"), false));
    }

    #[test]
    fn validation_rules() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("a.b-c_d").is_ok());
        assert!(validate_username("ab").is_err());
        assert!(validate_username("has space").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password("long enough").is_ok());
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[tokio::test]
    async fn setup_then_login_success() {
        let service = test_service(true).await;
        let status = service.status(None).await.unwrap();
        assert!(status.enabled && status.setup_required && status.user.is_none());

        let setup = service.setup(&creds("admin", "s3cret-pass")).await.unwrap();
        assert_eq!(setup.user.username, "admin");
        assert_ne!(setup.user.password_hash, "s3cret-pass");

        let status = service.status(Some(&setup.token)).await.unwrap();
        assert!(!status.setup_required);
        assert_eq!(status.user.unwrap().username, "admin");

        // Usernames are case-insensitive and surrounding whitespace is ignored.
        let login = service
            .login(&creds(" ADMIN ", "s3cret-pass"))
            .await
            .unwrap();
        assert_eq!(login.user.id, setup.user.id);
        assert_ne!(login.token, setup.token);
        assert!(service.authenticate(&login.token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn login_failures() {
        let service = test_service(true).await;
        service.setup(&creds("admin", "s3cret-pass")).await.unwrap();

        assert!(matches!(
            service.login(&creds("admin", "wrong-pass")).await,
            Err(LocalAuthError::InvalidCredentials)
        ));
        assert!(matches!(
            service.login(&creds("nobody", "s3cret-pass")).await,
            Err(LocalAuthError::InvalidCredentials)
        ));
        assert!(matches!(
            service
                .login(&creds("admin", &"x".repeat(MAX_PASSWORD_LEN + 1)))
                .await,
            Err(LocalAuthError::InvalidCredentials)
        ));
        assert!(service.authenticate("not-a-token").await.unwrap().is_none());
        assert!(service.authenticate("").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn setup_only_once_and_users_are_unique() {
        let service = test_service(true).await;
        service.setup(&creds("admin", "s3cret-pass")).await.unwrap();
        assert!(matches!(
            service.setup(&creds("intruder", "s3cret-pass")).await,
            Err(LocalAuthError::AlreadySetUp)
        ));

        service
            .create_user(&creds("second", "another-pass"))
            .await
            .unwrap();
        assert!(matches!(
            service.create_user(&creds("Second", "another-pass")).await,
            Err(LocalAuthError::UsernameTaken)
        ));
        assert!(
            service
                .login(&creds("second", "another-pass"))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn logout_revokes_session() {
        let service = test_service(true).await;
        let session = service.setup(&creds("admin", "s3cret-pass")).await.unwrap();
        service.logout(&session.token).await.unwrap();
        assert!(
            service
                .authenticate(&session.token)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_mode_refuses_sign_in() {
        let service = test_service(false).await;
        let status = service.status(None).await.unwrap();
        assert!(!status.enabled && !status.setup_required);
        assert!(matches!(
            service.setup(&creds("admin", "s3cret-pass")).await,
            Err(LocalAuthError::Disabled)
        ));
        assert!(matches!(
            service.login(&creds("admin", "s3cret-pass")).await,
            Err(LocalAuthError::Disabled)
        ));
    }
}
