-- Security VPN: схема базы данных (MariaDB / MySQL).
-- Применяется установщиком (server/install.sh), можно запускать повторно.

CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(30)  NOT NULL UNIQUE,
    password      VARCHAR(255) NOT NULL,
    uuid          CHAR(36)     NOT NULL UNIQUE,   -- идентификатор в Xray (VLESS)
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    synced        TINYINT(1)   NOT NULL DEFAULT 0, -- 1 = пользователь уже добавлен в конфиг Xray
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tokens (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT      NOT NULL,
    token_hash    CHAR(64) NOT NULL UNIQUE,        -- sha256 от токена, сам токен в базе не хранится
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    DATETIME NOT NULL,
    last_used_at  DATETIME NULL,
    INDEX idx_tokens_user (user_id),
    INDEX idx_tokens_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attempts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    bucket        VARCHAR(100) NOT NULL,           -- например "login:ip:1.2.3.4"
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_attempts_bucket (bucket, created_at)
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
