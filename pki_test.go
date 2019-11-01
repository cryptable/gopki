package gopki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
)

// ---------- Testing Module ----------

func TestNewCA(t *testing.T) {
	// Arrange
	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, 4096)
	subject := pkix.Name{
		CommonName:   "GoPKI",
		Organization: []string{"Cryptable"},
		Country:      []string{"BE"},
	}

	// Act
	ca, err := NewCA(subject, 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("NewCA() Failed", err)
		return
	}

	// Assert
	if (ca.Bytes == nil) {
		t.Error("empty ca.Bytes array")
	}

	if (ca.Certificate == nil) {
		t.Error("empty ca.Certificate")
	}

	if (ca.priv == nil) {
		t.Error("empty ca.priv")
	}

	if ca.certificateSerialNumber.Cmp(big.NewInt(1)) != 0 {
		t.Error("Serial number is not 1: ", ca.certificateSerialNumber)
	}
}

// ---------- Testing Certificates ----------
// ---------- Setup ----------
var setupCA *CA = nil

func setup(t *testing.T) {

	if (setupCA != nil) {
		return
	}

	// Create a Test CA
	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, 4096)
	subject := pkix.Name{
		CommonName:   "GoPKI",
		Organization: []string{"Cryptable"},
		Country:      []string{"BE"},
	}

	ca, err := NewCA(subject, 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("NewCA() Failed", err)
		panic(err)
	}

	// Write the CA for external validation
	// Create directory if not exists
	os.Mkdir("./testing", os.ModePerm)

	err = storeCertificate(ca.Bytes, "./testing/ca.pem")
	if err != nil {
		t.Error("store certificate failed :", err)
		return
	}

	err = storePrivateKey(ca.priv, "./testing/ca_key.pem")
	if err != nil {
		t.Error("store certificate failed :", err)
		return
	}

	setupCA = ca
}

func teardown(t *testing.T) {

}

func TestCA_CreateTLSClientCertificate(t *testing.T) {
	setup(t)
	defer teardown(t)

	// Arrange
	rnd := rand.Reader
	rsaKey, _ := rsa.GenerateKey(rnd, 2048)
	subject := pkix.Name{
		CommonName:   "SSL Client",
		Organization: []string{"Cryptable"},
		Country:      []string{"BE"},
	}

	// Act
	cert, err := setupCA.CreateTLSClientCertificate(subject, rsaKey.Public())

	// Assert
	if err != nil {
		t.Error("CA.CreateTLSCLientCertificate failed: ", err)
		return
	}
	if cert == nil {
		t.Error("Certificate is nil")
		return
	}

	err = storeCertificate(cert, "./testing/tlsclient.pem")
	if err != nil {
		t.Error("store certificate failed: ", err)
	}
	err = storePrivateKey(rsaKey, "./testing/tlsclient_key.pem")
	if err != nil {
		t.Error("store private key failed: ", err)
	}
}

func TestCA_CreateTLSServerCertificate(t *testing.T) {
	setup(t)
	defer teardown(t)

	// Arrange
	rnd := rand.Reader
	rsaKey, _ := rsa.GenerateKey(rnd, 2048)
	subject := pkix.Name{
		CommonName:   "SSL Server",
		Organization: []string{"Cryptable"},
		Country:      []string{"BE"},
	}

	// Act
	cert, err := setupCA.CreateTLSServerCertificate(subject, rsaKey.Public())

	// Assert
	if err != nil {
		t.Error("CA.CreateTLSServerCertificate failed: ", err)
		return
	}
	if cert == nil {
		t.Error("Certificate is nil")
		return
	}

	err = storeCertificate(cert, "./testing/tlsserver.pem")
	if err != nil {
		t.Error("store certificate failed: ", err)
	}
	err = storePrivateKey(rsaKey, "./testing/tlsserver_key.pem")
	if err != nil {
		t.Error("store private key failed: ", err)
	}
}

func overwriteFile(filename string) (f *os.File, err error){
	return os.OpenFile(filename, os.O_RDWR | os.O_CREATE, 0755)
}

func storeCertificate(cert []byte, filename string) (err error) {
	var pemPrivateKey = &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert,
	}
	w, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = pem.Encode(w, pemPrivateKey)
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
	if err != nil {
		return err
	}
	err = pem.Encode(w, pemPrivateKey)
	if err != nil {
		return err
	}

	return nil
}