package models

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
	"gopki/ca"
	"gopki/utils"
	"math/big"
	"strings"
)

type SQLiteDB struct {
	db *sql.DB
	integrity []byte
	confidentiality []byte
}

func NewSQLiteDB(dataSource string, integrity []byte, confidentiality []byte) (*SQLiteDB, error) {
	db, _ := sql.Open("sqlite3", dataSource)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &SQLiteDB{db, integrity, confidentiality}, nil
}

var createSQLiteDB = `
	CREATE TABLE IF NOT EXISTS CA (caid INTEGER PRIMARY KEY AUTOINCREMENT, caname TEXT UNIQUE, subject TEXT, issuer TEXT, serialnumber TINYBLOB, validuntil DATE, certificate BLOB, privatekey TEXT, caserialnumber TINYBLOB, integrity TINYBLOB);
	CREATE TABLE IF NOT EXISTS CERTIFICATES (certificateid INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT, issuer TEXT, serialnumber TINYBLOB, validuntil DATE, certificate BLOB, privatekey TEXT, integrity TINYBLOB, caid INTEGER, FOREIGN KEY(caid) REFERENCES CA(caid));
`

func (sqlite *SQLiteDB)CreateDB() error {
	_, err := sqlite.db.Exec(createSQLiteDB)

	if err != nil {
		return err
	}

	return nil
}

func (sqlite *SQLiteDB)CloseDB() error {
	return sqlite.db.Close()
}

type SQLiteCAStorage struct {
	sqlite *SQLiteDB
	caname string
}

// Interface of CA Server
func NewSQliteCAStorage(db *SQLiteDB, caname string) (*SQLiteCAStorage){
	return &SQLiteCAStorage{db, caname}
}

func (store *SQLiteCAStorage) GetCA() (*ca.CA, error) {
	rows, err := store.sqlite.db.Query("SELECT caid, certificate, privateKey, serialNumber FROM CA WHERE caname = ?", store.caname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rows.Next()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	var cert, serialNumber []byte
	var privateKey string
	var caid int64
	err = rows.Scan(&caid, &cert, &privateKey, &serialNumber)
	if err != nil {
		return nil, err
	}

	caPrivateKey, err := utils.LoadPrivateKeyPem(strings.NewReader(privateKey), store.sqlite.confidentiality)
	if err != nil {
		return nil, err
	}
	n := new(big.Int)
	n = n.SetBytes(serialNumber)

	return ca.NewCA(caid, store, cert, caPrivateKey, n)
}

func (store *SQLiteCAStorage) StoreCA(ca ca.CA) (*ca.CA, error) {
	stmt, err := store.sqlite.db.Prepare("INSERT INTO CA(caname, subject, issuer, serialnumber, validuntil, certificate, privatekey, caserialnumber) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()


	priv, sernum, err := ca.GetPrivateData(store.sqlite.confidentiality)
	if err != nil {
		return nil, err
	}

	res, err := stmt.Exec(store.caname, ca.Certificate.Subject.String(), ca.Certificate.Issuer.String(), ca.Certificate.SerialNumber.Bytes(), ca.Certificate.NotAfter, ca.Bytes, priv, sernum)
	if err != nil {
		return nil, err
	}

	caid, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	ca.CAId = caid

	return &ca, nil
}

func (store *SQLiteCAStorage) GetNextSerialNumber() (*big.Int, error) {
	tx, err := store.sqlite.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	rows, err := tx.Query("SELECT caserialnumber FROM CA WHERE caname = ?", store.caname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rows.Next()
	var serialNumber []byte
	err = rows.Scan(&serialNumber)
	if err != nil {
		return nil, err
	}

	serNum := new(big.Int)
	serNum = serNum.SetBytes(serialNumber)
	serNum = serNum.Add(serNum, big.NewInt(1))

	_, err = tx.Exec("UPDATE CA SET caserialnumber = ? WHERE caname = ?", serNum.Bytes(), store.caname)
	if err != nil {
		return nil, err
	}

	return serNum, nil
}