package ca

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"gopki/utils"
	"math/big"
	"time"
)

type CA struct {
	priv crypto.PrivateKey
	Bytes []byte
	Certificate *x509.Certificate
	certificateSerialNumber *big.Int
	storage CAStorage
}

func NewCA(storage CAStorage, cert []byte , priv crypto.PrivateKey, serialNum *big.Int) (c *CA, e error) {
	certif, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}

	return &CA{priv, cert, certif, serialNum, storage }, nil
}

func CreateCA(storage CAStorage, dn string, years int, pub crypto.PublicKey, priv crypto.PrivateKey) (c *CA, e error) {

	pkixName, err := ConvertDNToPKIXName(dn)
	if err != nil {
		return nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     *pkixName,
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().AddDate(years,0,0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, pub, priv)
	if err != nil {
		return nil, err
	}

	return NewCA(storage, cert, priv, big.NewInt(2))
}

func LoadCA(storage CAStorage) (c *CA, e error) {
	ca, err := storage.GetCA()
	if err != nil {
		return nil, err
	}
	ca.storage = storage
	return ca, nil
}

func (ca *CA)createTLSCertificate(dn string, pub crypto.PublicKey, extKeyUsage []x509.ExtKeyUsage) (cert []byte, err error) {

	pkixName, err := ConvertDNToPKIXName(dn)
	if err != nil {
		return nil, err
	}

	certTemplate := x509.Certificate{
		SerialNumber:                ca.certificateSerialNumber,
		Subject:                     *pkixName,
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().AddDate(1,0,0),
		KeyUsage:                    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:                 extKeyUsage,
		BasicConstraintsValid:       true,
		IsCA:                        false,
	}

	ca.certificateSerialNumber, err = ca.storage.GetNextSerialNumber()
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, &certTemplate, ca.Certificate, pub, ca.priv)
}

func (ca *CA)CreateTLSClientCertificate(dn string, pub crypto.PublicKey) (c []byte, e error) {
	return ca.createTLSCertificate(dn, pub, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func (ca *CA)CreateTLSServerCertificate(dn string, pub crypto.PublicKey) (c []byte, e error) {
	return ca.createTLSCertificate(dn, pub, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (ca *CA)GetPrivateData(password []byte) (p string, s []byte, e error) {
	buf := new(bytes.Buffer)
	err := utils.StorePrivateKeyPem(buf, ca.priv, password)
	if err != nil {
		return "", nil, err
	}
	return buf.String(), ca.certificateSerialNumber.Bytes(), nil
}
