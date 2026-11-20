-- 000011: browser sessions. A person signed in from a browser.
--   id_hash     SHA-256 of the cookie's value; the value itself is never stored
--   csrf_key    random; the page's second token is computed from it and the
--               cookie's value, so the store holds neither
--   host        app (mail and drive) or admin: a session belongs to the one
--               it was made on
--   created_at  a session ends a fixed time after this, whatever happens
--   seen_at     and after a time without a call; written at most once a minute
--   client      the address at login, for the list a user sees
--   agent       the browser's name at login, cut short
-- A user's sessions go with the user.
CREATE TABLE IF NOT EXISTS web_session (
  id_hash    bytea PRIMARY KEY,
  csrf_key   bytea NOT NULL,
  user_id    bigint NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  host       text COLLATE "C" NOT NULL,
  created_at bigint NOT NULL,
  seen_at    bigint NOT NULL,
  client     text COLLATE "C" NOT NULL DEFAULT '',
  agent      text COLLATE "C" NOT NULL DEFAULT '',
  CHECK (length(id_hash) = 32 AND length(csrf_key) = 32),
  CHECK (host IN ('app', 'admin')),
  CHECK (seen_at >= created_at)
);
CREATE INDEX IF NOT EXISTS web_session_user ON web_session(user_id, created_at);
