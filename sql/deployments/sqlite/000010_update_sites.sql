-- 000010: AutoPanel's own site, and the documents published to it.
--
-- A site is a host name with pages. security_gen rises whenever something
-- public is withdrawn: a build made before the change carries the older
-- number and is never served.
--
-- A document is what was published, as it was sent. The store owns its
-- identity: an id that is never used again, the user who first published it
-- (owner_id, never changed: a user with documents cannot be removed until
-- they are), and its level.
--   visibility  public, protected, internal or private; private unless said
--   active      1: an html document whose scripts may run; only when public
--   generation  rises when the level, the share list or the protection changes
--   version     rises when the content changes
--   meta        the front matter as sent, as JSON
--   source      the body as sent
-- A private document's share list is rows of site_doc_share.
--
-- A resource is one file of a document. name is the author's relative path,
-- byte for byte; name_fold is it in lower case, so two names that differ
-- only by case cannot both exist.
CREATE TABLE IF NOT EXISTS site (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  host         TEXT NOT NULL UNIQUE,
  content_host TEXT NOT NULL DEFAULT '',
  config       TEXT NOT NULL DEFAULT '',
  security_gen INTEGER NOT NULL DEFAULT 1,
  created_at   INTEGER NOT NULL,
  CHECK (host <> '' AND host = lower(host)),
  CHECK (content_host = lower(content_host) AND content_host <> host)
);

CREATE TABLE IF NOT EXISTS site_doc (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id    INTEGER NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  slug       TEXT NOT NULL,
  format     TEXT NOT NULL,
  owner_id   INTEGER NOT NULL REFERENCES app_user(id) ON DELETE RESTRICT,
  visibility TEXT NOT NULL DEFAULT 'private',
  collection TEXT NOT NULL DEFAULT '',
  ord        INTEGER NOT NULL DEFAULT 0,
  active     INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL DEFAULT 1,
  version    INTEGER NOT NULL DEFAULT 1,
  meta       TEXT NOT NULL DEFAULT '',
  source     BLOB NOT NULL,
  sha256     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (site_id, slug),
  CHECK (slug <> '' AND slug = lower(slug)),
  CHECK (format IN ('md', 'xmd', 'html')),
  CHECK (visibility IN ('public', 'protected', 'internal', 'private')),
  CHECK (active IN (0, 1)),
  CHECK (active = 0 OR (format = 'html' AND visibility = 'public')),
  CHECK (generation > 0 AND version > 0)
);
CREATE INDEX IF NOT EXISTS site_doc_owner ON site_doc(owner_id);

CREATE TABLE IF NOT EXISTS site_doc_share (
  doc_id  INTEGER NOT NULL REFERENCES site_doc(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  PRIMARY KEY (doc_id, user_id)
);

CREATE TABLE IF NOT EXISTS site_resource (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id    INTEGER NOT NULL REFERENCES site_doc(id) ON DELETE CASCADE,
  name      TEXT NOT NULL,
  name_fold TEXT NOT NULL,
  mime      TEXT NOT NULL,
  size      INTEGER NOT NULL,
  sha256    TEXT NOT NULL,
  data      BLOB NOT NULL,
  UNIQUE (doc_id, name_fold),
  CHECK (name <> '' AND name_fold = lower(name) AND size >= 0)
);
