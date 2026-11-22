-- Local accounts: username/password sign-in that works without the cloud API.
-- Passwords are stored only as Argon2id PHC strings; session tokens are stored
-- only as SHA-256 hashes so a leaked database cannot be replayed as a cookie.

CREATE TABLE local_users (
    id            BLOB PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE TABLE local_sessions (
    id           BLOB PRIMARY KEY,
    user_id      BLOB NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    expires_at   TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES local_users(id) ON DELETE CASCADE
);

CREATE INDEX idx_local_sessions_user_id ON local_sessions(user_id);
CREATE INDEX idx_local_sessions_expires_at ON local_sessions(expires_at);
