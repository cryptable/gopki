package models

import (
	"database/sql"
	"gopki/ca"
	"gopki/utils"
	"math/big"
	"strings"
)

type MySQLdb struct {
	db *sql.DB
	integrity []byte
	confidentiality []byte
}

func NewMySQLDB(dataSource string, integrity []byte, confidentiality []byte) (*MySQLdb, error) {
	db, err := sql.Open("mysql", dataSource)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &MySQLdb{db, integrity, confidentiality}, nil
}

var createDB = `CREATE TABLE IF NOT EXISTS CA (caname VARCHAR(64) PRIMARY KEY, certificate BLOB, privatekey TEXT, serialnumber TINYBLOB);`

func (my *MySQLdb)CreateDB() error {
	_, err := my.db.Exec(createDB)

	if err != nil {
		return err
	}

	return nil
}


type MyCAStorage struct {
	my MySQLdb
	caname string
}

// Interface of CA Server
func (store *MyCAStorage) GetCA() (*ca.CA, error) {
	rows, err := store.my.db.Query("SELECT certificate, privateKey, serialNumber FROM CA WHERE caname = ?", store.caname)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rows.Next()
	var cert, serialNumber []byte
	var privateKey string
	err = rows.Scan(cert, privateKey, serialNumber)
	if err != nil {
		return nil, err
	}

	caPrivateKey, err := utils.LoadPrivateKeyPem(strings.NewReader(privateKey), store.my.confidentiality)
	if err = rows.Err(); err != nil {
		return nil, err
	}
	n := new(big.Int)
	n = n.SetBytes(serialNumber)

	return ca.NewCA(store, cert, caPrivateKey, n)
}

func (store *MyCAStorage) StoreCA(ca *ca.CA) error {
	stmt, err := store.my.db.Prepare("INSERT INTO CA( 'bootstrap', ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	priv, sernum, err := ca.GetPrivateData(store.my.confidentiality)
	if err != nil {
		return err
	}

	_, err = stmt.Exec(ca.Bytes, priv, sernum)
	if err != nil {
		return err
	}

	return nil
}

func (store *MyCAStorage) GetNextSerialNumber() (*big.Int, error) {
	tx, err := store.my.db.Begin()
	if err != nil {
		return nil, err
	}
	tx.Commit()

	rows, err := tx.Query("SELECT serialnumber FROM CA WHERE caname = 'bootstrap'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rows.Next()
	var serialNumber []byte
	err = rows.Scan(serialNumber)
	if err != nil {
		return nil, err
	}

	serNum := new(big.Int)
	serNum = serNum.SetBytes(serialNumber)
	serNum = serNum.Add(serNum, big.NewInt(1))

	_, err = tx.Exec("INSERT INTO CA SET serialnumber = ?", serNum)
	if err != nil {
		return nil, err
	}

	return serNum, nil
}