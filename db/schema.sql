-- ============================================================
-- PrivaVault — MySQL Schema
-- Phase 1-2 | branch: feature/auth-upload
--
-- Run this once to set up the database from scratch:
--   mysql -u root -p < db/schema.sql
--
-- Or paste it into MySQL Workbench / DBeaver directly.
-- ============================================================

-- Create and select the database
CREATE DATABASE IF NOT EXISTS privavault
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE privavault;

-- ============================================================
-- TABLE A: users
--
-- One row per registered account.
-- Stores BCrypt hash (identity verification) and PBKDF2 salt
-- (key derivation) separately — they serve different purposes.
--
-- The raw password NEVER touches this table.
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    user_id       INT           NOT NULL AUTO_INCREMENT,
    email         VARCHAR(255)  NOT NULL,
    password_hash VARCHAR(255)  NOT NULL,   -- BCrypt output (~60 chars, VARCHAR 255 is safe)
    pbkdf2_salt   VARCHAR(255)  NOT NULL,   -- 64-char hex string (secrets.token_hex(32))
    created_at    TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id),
    UNIQUE KEY uq_users_email (email)       -- enforces one account per email address

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- TABLE B: documents
--
-- Central vault anchor. One row per uploaded file.
--
-- IMPORTANT: encrypted_key_blob is BLOB, not VARCHAR.
-- It holds raw binary — the Fernet key wrapped by the
-- PBKDF2-derived wrapping key. Storing binary in VARCHAR
-- risks silent encoding corruption.
--
-- The raw Fernet key is NEVER stored here or anywhere on disk.
-- Without the user's password in an active request,
-- encrypted_key_blob is cryptographically useless.
-- ============================================================
CREATE TABLE IF NOT EXISTS documents (
    doc_id             INT           NOT NULL AUTO_INCREMENT,
    user_id            INT           NOT NULL,
    original_filename  VARCHAR(255)  NOT NULL,
    cloud_storage_url  VARCHAR(512)  NOT NULL,   -- pointer to the blob in Azure
    ai_summary         TEXT,                      -- NULL until Stream A completes
    encrypted_key_blob BLOB          NOT NULL,
    upload_status      ENUM(
                           'processing',          -- dual stream running
                           'ready',               -- both streams succeeded
                           'failed'               -- one or both streams failed
                       )             NOT NULL DEFAULT 'processing',
    uploaded_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (doc_id),

    -- Fast lookup: "give me all documents belonging to user X"
    INDEX idx_documents_user_id (user_id),

    FOREIGN KEY (user_id)
        REFERENCES users (user_id)
        ON DELETE CASCADE      -- deleting a user removes all their documents
        ON UPDATE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- TABLE C: document_tags
--
-- One row per tag per document (not one row per document).
-- Decoupling tags into their own table lets you run:
--   SELECT doc_id FROM document_tags WHERE tag_name = 'Medical Record'
-- with a simple index scan instead of a LIKE query on a
-- comma-separated string column.
-- ============================================================
CREATE TABLE IF NOT EXISTS document_tags (
    tag_id   INT          NOT NULL AUTO_INCREMENT,
    doc_id   INT          NOT NULL,
    tag_name VARCHAR(100) NOT NULL,

    PRIMARY KEY (tag_id),

    -- Fast lookup: "give me all tags for document X"
    INDEX idx_tags_doc_id (doc_id),

    -- Fast search: "give me all documents tagged 'Invoice'"
    INDEX idx_tags_tag_name (tag_name),

    FOREIGN KEY (doc_id)
        REFERENCES documents (doc_id)
        ON DELETE CASCADE      -- deleting a document removes all its tags
        ON UPDATE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- TABLE D: access_logs
--
-- Append-only audit trail. Every auth event and file operation
-- lands here. Required for GDPR/HIPAA compliance narrative.
--
-- doc_id is NULLABLE — auth events (REGISTER, LOGIN) don't
-- have an associated document, so they log doc_id = NULL.
--
-- user_id is RESTRICT on delete — you cannot delete a user
-- who has audit log entries. This protects the compliance trail.
-- If you need to delete a user, archive their logs first.
-- ============================================================
CREATE TABLE IF NOT EXISTS access_logs (
    log_id     INT         NOT NULL AUTO_INCREMENT,
    user_id    INT         NOT NULL,
    doc_id     INT,                              -- NULL for REGISTER / LOGIN events
    action     VARCHAR(50) NOT NULL,             -- 'REGISTER' | 'LOGIN' | 'UPLOAD' | 'DOWNLOAD'
    ip_address VARCHAR(45),                      -- 45 chars covers full IPv6 addresses
    timestamp  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (log_id),

    -- Fast audit queries: "show me all activity for user X"
    INDEX idx_logs_user_id (user_id),

    -- Fast time-range queries: "show me all activity in the last 7 days"
    INDEX idx_logs_timestamp (timestamp),

    FOREIGN KEY (user_id)
        REFERENCES users (user_id)
        ON DELETE RESTRICT     -- cannot delete a user who has audit log entries
        ON UPDATE CASCADE,

    FOREIGN KEY (doc_id)
        REFERENCES documents (doc_id)
        ON DELETE SET NULL     -- if a document is deleted, keep the log but null the doc_id
        ON UPDATE CASCADE

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- ============================================================
-- Quick sanity check — run after applying schema:
--   SHOW TABLES;
--   DESCRIBE users;
--   DESCRIBE documents;
--   DESCRIBE document_tags;
--   DESCRIBE access_logs;
-- ============================================================