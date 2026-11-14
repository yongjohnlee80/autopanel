-- 000005: mail. The SQLite engine's 000005, translated as 000001 is.

CREATE TABLE IF NOT EXISTS mail (
  id           integer PRIMARY KEY CHECK (id = 1),
  host         text COLLATE "C" NOT NULL,
  bootstrapped bigint NOT NULL DEFAULT 0,
  created_at   bigint NOT NULL,
  CHECK (host <> '' AND host = lower(host))
);

CREATE TABLE IF NOT EXISTS mail_domain (
  name       text COLLATE "C" PRIMARY KEY,
  created_at bigint NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);

CREATE TABLE IF NOT EXISTS mail_record (
  domain     text COLLATE "C" NOT NULL,
  name       text COLLATE "C" NOT NULL,
  type       text COLLATE "C" NOT NULL,
  value      text COLLATE "C" NOT NULL,
  remote_id  text COLLATE "C" NOT NULL,
  merged     integer NOT NULL DEFAULT 0,
  updated_at bigint NOT NULL,
  PRIMARY KEY (domain, name, type)
);

CREATE TABLE IF NOT EXISTS mail_dkim (
  domain   text COLLATE "C" NOT NULL,
  selector text COLLATE "C" NOT NULL,
  step     text COLLATE "C" NOT NULL,
  since    bigint NOT NULL,
  PRIMARY KEY (domain, selector)
);
