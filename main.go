package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"gopki/ca"
	"gopki/models"
	"log"
)

func BootstrapCA(store ca.CAStorage,
	dname string,
	years int,
	keylength int) *ca.CA {

	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, keylength)
	if err != nil {
		log.Fatal("bootstrap: rsa.GenerateKey() failed: " + err.Error())
	}
	ca, err := ca.CreateCA(store, dname, years, rsaKey.Public(), rsaKey)
	if err != nil {
		log.Fatal("bootstrap: ca.CreateCA() failed: " + err.Error())
	}

	return ca
}

func BootstrapRA(ca *ca.CA,
	dname string,
	keylength int) []byte {

	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, keylength)

	racert, err := ca.CreateTLSClientCertificate(dname, rsaKey.Public())
	if err != nil {
		log.Fatal("bootstrap: ca.CreateTLSClientCertificate() failed" + err.Error())
	}

	return racert
}

func main() {
	bootstrap := flag.Bool("bootstrap", false, "Used to bootstrap the CA with dname, keylength, years, confidentiality and integrity parameter")
	cadname := flag.String("cadname", "CN=Bootstrap CA", "Distinguished name of bootstrap CA")
//	radname := flag.String("radname", "CN=Bootstrap RA", "Distinguished name of bootstrap RA")
	keylength := flag.Int("keylength", 4096, "Keylength of the BootstrapCA")
	years := flag.Int("years", 20, "Years validity of the BootstrapCA")
	confidentiality := flag.String("confidentiality", "confidentiality", "Confidentiality key to keep secret data protected in DB")
	integrity := flag.String("integrity", "integrity", "Integrity key to keep data in DB protected")

	flag.Parse()

	var bootstrapca *ca.CA = nil
	if *bootstrap {
		db, err := models.NewSQLiteDB("./testing/test.sqlite", []byte(*integrity), []byte(*confidentiality))
		if err != nil {
			log.Fatal("bootstrap: DB connection failure: " + err.Error())
		}
		err = db.CreateDB()
		if err != nil {
			log.Fatal("bootstrap: DB creation failure: " + err.Error())
		}
		store := models.NewSQliteCAStorage(db, "bootstrap")
		bootstrapca = BootstrapCA(store, *cadname, *years, *keylength)

		log.Printf("INFO: ca started successful initialized: %s", bootstrapca.Certificate.Subject.String())
	} else {
		db, err := models.NewSQLiteDB("./testing/test.sqlite", []byte(*integrity), []byte(*confidentiality))
		if err != nil {
			log.Fatal("bootstrap: DB connection failure: " + err.Error())
		}
		store := models.NewSQliteCAStorage(db, "bootstrap")
		bootstrapca, err = store.GetCA()
		if err != nil {
			log.Fatal("bootstrap: DB connection failure: " + err.Error())
		}
		log.Printf("INFO: ca started successful: %s", bootstrapca.Certificate.Subject.String())
	}
}