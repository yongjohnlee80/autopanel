// Package deployments is the store's schema as SQL scripts, one directory per
// engine, compiled into the binary and applied by golib dao/deploy.
//
//	sqlite/000001_update_initialize_tables.sql   the baseline: no revert
//	sqlite/000002_update_<slug>.sql              a change …
//	sqlite/000002_revert_<slug>.sql              … and its undo
//	postgres/…                                   the same names, for PostgreSQL
//
// dao/deploy reads the tree, refuses a set that is not dense and paired,
// applies every pending script in one transaction and keeps the ledger. A
// released script never changes; the tests hold each released digest.
package deployments

import (
	"embed"
	"io/fs"

	"github.com/yongjohnlee80/golib/dao"
	"github.com/yongjohnlee80/golib/dao/deploy"
)

//go:embed sqlite/*.sql postgres/*.sql
var files embed.FS

// Engines are the engines the store has scripts for: each is a directory,
// named for its dialect. SQLite is the default; PostgreSQL is configured.
var Engines = []string{dao.DialectSQLite, dao.DialectPostgres}

// FS is the script tree.
func FS() fs.FS { return files }

// Runner applies the store's scripts.
func Runner() *deploy.Runner { return deploy.New(files) }
