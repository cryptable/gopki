package ca

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func overwriteFile(filename string) (f *os.File, err error){
	return os.OpenFile(filename, os.O_RDWR | os.O_CREATE, 0755)
}

func storeCertificate(cert []byte, filename string) (err error) {
	var pemCertificate = &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert,
	}
	w, err := os.Create(filename)
	defer w.Close()
	if err != nil {
		return err
	}
	err = pem.Encode(w, pemCertificate)
	if err != nil {
		return err
	}

	return nil
}

func storePrivateKey(priv crypto.PrivateKey, filename string) (err error) {

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	var pemPrivateKey = &pem.Block{
		Type:    "PRIVATE KEY",
		Bytes:  privBytes,
	}
	w, err := os.Create(filename)
	defer w.Close()
	if err != nil {
		return err
	}
	err = pem.Encode(w, pemPrivateKey)
	if err != nil {
		return err
	}

	return nil
}
