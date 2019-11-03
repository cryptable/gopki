package gopki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

type CA struct {
	priv crypto.PrivateKey
	Bytes []byte
	Certificate *x509.Certificate
	certificateSerialNumber *big.Int
}

func NewCA(dn string, years int, pub crypto.PublicKey, priv crypto.PrivateKey) (c *CA, e error) {

	pkixName, err := ConvertDNToPKIXName(dn)
	if err != nil {
		return nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber:                big.NewInt(2019),
		Subject:                     *pkixName,
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().AddDate(years,0,0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
	}
	caTmp, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, pub, priv)

	if err != nil {
		return nil, err
	}

	certif, _ := x509.ParseCertificate(caTmp)
	return &CA{priv,caTmp, certif, big.NewInt(1)}, nil
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

	ca.certificateSerialNumber.Add(ca.certificateSerialNumber, big.NewInt(1))

	return x509.CreateCertificate(rand.Reader, &certTemplate, ca.Certificate, pub, ca.priv)
}

func (ca *CA)CreateTLSClientCertificate(dn string, pub crypto.PublicKey) (cert []byte, err error) {
	return ca.createTLSCertificate(dn, pub, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func (ca *CA)CreateTLSServerCertificate(dn string, pub crypto.PublicKey) (cert []byte, err error) {
	return ca.createTLSCertificate(dn, pub, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}