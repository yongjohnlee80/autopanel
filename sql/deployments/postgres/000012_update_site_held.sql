-- 000012: the site's held documents: what was built of each, and protection.
--
-- site_built: the fingerprint of what a site's public pages were last built
-- from. A build whose public input has the same fingerprint builds no public
-- page again.
--
-- site_held: a node that is not public in effect (itself or a folder above
-- it is protected, internal or private) is built alone, and kept apart from
-- the public pages. A row says which build's files are the node's, and what
-- they were built from.
--   fingerprint  of the node's input: its content, address, level and the
--                site's configuration; the same one is not built again
--   build        the directory its files are in, under the held root
--   mermaid      1: its page may load the kit's diagram scripts
--
-- site_protect: a protected node's passphrase, as an Argon2id verifier.
--   generation   rises when the passphrase changes; a grant of an older one
--                opens nothing
--
-- site_grant: a reader who gave a protected node's passphrase.
--   id_hash      SHA-256 of the cookie's value; the value is never stored
--   node_id      the protected node it was given for
--   generation   the protection's generation it was issued at
CREATE TABLE IF NOT EXISTS site_built (
  site_id     bigint PRIMARY KEY REFERENCES site(id) ON DELETE CASCADE,
  fingerprint text COLLATE "C" NOT NULL
);

CREATE TABLE IF NOT EXISTS site_held (
  node_id     bigint PRIMARY KEY REFERENCES site_node(id) ON DELETE CASCADE,
  site_id     bigint NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  fingerprint text COLLATE "C" NOT NULL,
  build       bigint NOT NULL,
  mermaid     bigint NOT NULL DEFAULT 0,
  built_at    bigint NOT NULL,
  CHECK (build > 0 AND mermaid IN (0, 1))
);
CREATE INDEX IF NOT EXISTS site_held_site ON site_held(site_id);

CREATE TABLE IF NOT EXISTS site_protect (
  node_id    bigint PRIMARY KEY REFERENCES site_node(id) ON DELETE CASCADE,
  verifier   text COLLATE "C" NOT NULL,
  generation bigint NOT NULL DEFAULT 1,
  CHECK (verifier <> '' AND generation > 0)
);

CREATE TABLE IF NOT EXISTS site_grant (
  id_hash    bytea PRIMARY KEY,
  site_id    bigint NOT NULL REFERENCES site(id) ON DELETE CASCADE,
  node_id    bigint NOT NULL REFERENCES site_node(id) ON DELETE CASCADE,
  generation bigint NOT NULL,
  issued_at  bigint NOT NULL,
  expires_at bigint NOT NULL,
  CHECK (length(id_hash) = 32),
  CHECK (expires_at > issued_at)
);
CREATE INDEX IF NOT EXISTS site_grant_site ON site_grant(site_id, issued_at);
CREATE INDEX IF NOT EXISTS site_grant_expires ON site_grant(expires_at);
