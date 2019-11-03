package gopki

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var CREATE_CA_CONFIG_TABLE = "CREATE TABLE IF NOT EXISTS CACONFIG (id INTEGER PRIMARY KEY AUTOINCREMENT, caname VARCHAR(32), key VARCHAR(256), value BLOB, integrity CHAR(64))"

type DB struct {
	db *sql.DB
}

func NewDB(dbtype string, connect string) (d *DB, e error) {
	db, err := sql.Open(dbtype, connect)
	if err != nil {
		return _, err
	}

	return &DB{db}, nil
}

func (d *DB)CreateDB() (e error) {
	_, err := d.db.Exec(CREATE_CA_CONFIG_TABLE)
	if err != nil {
		return err
	}
	return nil
}

func (d *DB)CloseDB() {
	d.db.Close()
}