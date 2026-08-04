-- =============================================================================
-- ARES — Automated Red-team Exploit System
-- Database schema (structure only, no data)
--
-- Usage:
--   1. Create the database (see README, "Database" step):
--        CREATE DATABASE ares CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
--   2. Import this schema:
--        mysql -u ares -p --skip-ssl ares < docs/ares.sql
--
-- Note: this file contains table definitions (DDL) only. It includes no lab
-- data or audit results. The data tree hangs off `jobs`: deleting a job
-- cascades to its hosts, scans, vulnerabilities, attempts, sessions and logs.
-- =============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------------------------------
-- jobs — root of the tree. One row per audit run.
--   type  : execution mode ('normal' iterative without AI / 'ia' LLM agent)
--   model : name of the LLM used (e.g. gemma4:26b), NULL in normal mode
-- -----------------------------------------------------------------------------
CREATE TABLE jobs (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT,
  type       VARCHAR(20)  NOT NULL,
  model      VARCHAR(100) DEFAULT NULL,
  timestamp  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- hosts — hosts discovered within a job.
--   target_host : target IP (or hostname)
--   os_info     : estimated OS (filled in after the deep scan)
--   state       : per-host flow state ('pending', 'done', ...)
-- -----------------------------------------------------------------------------
CREATE TABLE hosts (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  jobs_id      INT UNSIGNED NOT NULL,
  target_host  VARCHAR(45)  NOT NULL,
  os_info      VARCHAR(255) DEFAULT NULL,
  state        VARCHAR(20)  NOT NULL DEFAULT 'pending',
  timestamp    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_hosts_job (jobs_id),
  KEY idx_hosts_target (jobs_id, target_host),
  CONSTRAINT fk_hosts_job FOREIGN KEY (jobs_id) REFERENCES jobs (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- host_nmap — service enumeration result (nmap -sV) per open port.
-- -----------------------------------------------------------------------------
CREATE TABLE host_nmap (
  id            INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  host_id       INT UNSIGNED     NOT NULL,
  port          SMALLINT UNSIGNED NOT NULL,
  nmap_state    VARCHAR(20)      DEFAULT NULL,
  nmap_service  VARCHAR(100)     DEFAULT NULL,
  nmap_version  VARCHAR(255)     DEFAULT NULL,
  state         VARCHAR(20)      NOT NULL DEFAULT 'done',
  timestamp     DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_hostnmap_host (host_id),
  KEY idx_hostnmap_hostport (host_id, port),
  CONSTRAINT fk_hostnmap_host FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- host_vuln — detected CVEs, linked to the service/port where they appear.
--   severity : CVE severity mapping
-- -----------------------------------------------------------------------------
CREATE TABLE host_vuln (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  host_id       INT UNSIGNED NOT NULL,
  host_nmap_id  INT UNSIGNED DEFAULT NULL,
  cve           VARCHAR(20)  NOT NULL,
  severity      ENUM('critical','high','medium','low') DEFAULT NULL,
  service       VARCHAR(100) DEFAULT NULL,
  state         VARCHAR(20)  NOT NULL DEFAULT 'done',
  timestamp     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_hostvuln_host (host_id),
  KEY idx_hostvuln_nmap (host_nmap_id),
  CONSTRAINT fk_hostvuln_host FOREIGN KEY (host_id)      REFERENCES hosts (id)     ON DELETE CASCADE,
  CONSTRAINT fk_hostvuln_nmap FOREIGN KEY (host_nmap_id) REFERENCES host_nmap (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- exploit_attempt — each exploitation attempt (successful or not) on a host.
--   success     : 1 if a session was opened, 0 if it failed
--   duration_ms : attempt duration in milliseconds
--   output      : trace (module, payload, result)
-- -----------------------------------------------------------------------------
CREATE TABLE exploit_attempt (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  jobs_id      INT UNSIGNED NOT NULL,
  host_id      INT UNSIGNED NOT NULL,
  port         SMALLINT UNSIGNED DEFAULT NULL,
  success      TINYINT(1)   NOT NULL DEFAULT 0,
  duration_ms  INT UNSIGNED DEFAULT NULL,
  output       TEXT         DEFAULT NULL,
  state        VARCHAR(20)  NOT NULL DEFAULT 'done',
  timestamp    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_attempt_job (jobs_id),
  KEY idx_attempt_host (host_id),
  CONSTRAINT fk_attempt_job  FOREIGN KEY (jobs_id) REFERENCES jobs (id)  ON DELETE CASCADE,
  CONSTRAINT fk_attempt_host FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- exploit_session — session opened on a compromised host.
--   type   : 'shell' | 'meterpreter' | 'ssh'
--   method : how it was opened ('exploit', ...)
--   cve    : CVE leveraged (NULL when access was credential-based)
--   user   : session user (e.g. for SSH access)
-- -----------------------------------------------------------------------------
CREATE TABLE exploit_session (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  jobs_id      INT UNSIGNED NOT NULL,
  host_id      INT UNSIGNED NOT NULL,
  type         VARCHAR(20)  DEFAULT NULL,
  method       VARCHAR(20)  DEFAULT NULL,
  cve          VARCHAR(20)  DEFAULT NULL,
  user         VARCHAR(100) DEFAULT NULL,
  duration_ms  INT UNSIGNED DEFAULT NULL,
  state        VARCHAR(20)  NOT NULL DEFAULT 'done',
  timestamp    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_session_job (jobs_id),
  KEY idx_session_host (host_id),
  CONSTRAINT fk_session_job  FOREIGN KEY (jobs_id) REFERENCES jobs (id)  ON DELETE CASCADE,
  CONSTRAINT fk_session_host FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- ssh_attempt — SSH credential access attempts (success or failure).
-- -----------------------------------------------------------------------------
CREATE TABLE ssh_attempt (
  id           INT UNSIGNED NOT NULL AUTO_INCREMENT,
  jobs_id      INT UNSIGNED NOT NULL,
  host_id      INT UNSIGNED NOT NULL,
  user         VARCHAR(100) DEFAULT NULL,
  password     VARCHAR(255) DEFAULT NULL,
  success      TINYINT(1)   NOT NULL DEFAULT 0,
  duration_ms  INT UNSIGNED DEFAULT NULL,
  state        VARCHAR(20)  NOT NULL DEFAULT 'done',
  timestamp    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_sshattempt_job (jobs_id),
  KEY idx_sshattempt_host (host_id),
  CONSTRAINT fk_sshattempt_job  FOREIGN KEY (jobs_id) REFERENCES jobs (id)  ON DELETE CASCADE,
  CONSTRAINT fk_sshattempt_host FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- activity_logs — event log for the agent (backs the historical context).
--   event_type      : event kind ('exploit_success', 'session_opened', ...)
--   reference_id    : id of the referenced record
--   reference_table : table that reference_id points to
--   details_json    : structured event details
-- -----------------------------------------------------------------------------
CREATE TABLE activity_logs (
  id               INT UNSIGNED NOT NULL AUTO_INCREMENT,
  jobs_id          INT UNSIGNED NOT NULL,
  event_type       VARCHAR(50)  NOT NULL,
  reference_id     INT UNSIGNED DEFAULT NULL,
  reference_table  VARCHAR(50)  DEFAULT NULL,
  details_json     JSON         DEFAULT NULL,
  intentos         INT UNSIGNED DEFAULT NULL,
  duration_ms      INT UNSIGNED DEFAULT NULL,
  observaciones    TEXT         DEFAULT NULL,
  comentarios      TEXT         DEFAULT NULL,
  timestamp        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_actlog_job (jobs_id),
  KEY idx_actlog_event (event_type),
  CONSTRAINT fk_actlog_job FOREIGN KEY (jobs_id) REFERENCES jobs (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;
