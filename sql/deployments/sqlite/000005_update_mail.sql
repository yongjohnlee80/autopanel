-- 000005: mail. Only what says mail exists and how far it got, the records
-- AutoPanel published, and each DKIM key's place in its rotation. Every key
-- and setting of mail is in the secret table, sealed, not here.

-- One mail server per AutoPanel.
--   host          the mail host: mail.example.com
--   bootstrapped  Unix seconds; 0 while Stalwart is not set up
--   created_at    Unix seconds
CREATE TABLE IF NOT EXISTS mail (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  host         TEXT NOT NULL,
  bootstrapped INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  CHECK (host <> '' AND host = lower(host))
);

-- A registry domain that receives mail.
CREATE TABLE IF NOT EXISTS mail_domain (
  name       TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);

-- The DNS records AutoPanel published, so it changes only its own. Public
-- data: not sealed.
--   remote_id  the DNS provider's id for the record
--   merged     1: AutoPanel added to a record that was there (SPF), not created it
CREATE TABLE IF NOT EXISTS mail_record (
  domain     TEXT NOT NULL,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL,
  value      TEXT NOT NULL,
  remote_id  TEXT NOT NULL,
  merged     INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (domain, name, type)
);

-- Each DKIM key's place in its rotation: created, published, signing,
-- retired, deleted.
CREATE TABLE IF NOT EXISTS mail_dkim (
  domain   TEXT NOT NULL,
  selector TEXT NOT NULL,
  step     TEXT NOT NULL,
  since    INTEGER NOT NULL,
  PRIMARY KEY (domain, selector)
);
