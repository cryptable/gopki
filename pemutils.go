package gopki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
)

func LoadPrivateKeyPem(in io.Reader, password []byte) (p crypto.PrivateKey, e error) {

	encPrivateKey, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(encPrivateKey)

	var bytesPrivateKey []byte
	var privateKey crypto.PrivateKey
	if x509.IsEncryptedPEMBlock(block) {
		bytesPrivateKey, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}
	} else {
		bytesPrivateKey = block.Bytes
	}

	privateKey, err = x509.ParsePKCS8PrivateKey(bytesPrivateKey)
	if err == nil {
		return privateKey, nil
	}
	log.Print("W: Unkknown PKCS8 format: " + err.Error())
	privateKey, err = x509.ParsePKCS1PrivateKey(bytesPrivateKey)
	if err == nil {
		return privateKey, nil
	}
	log.Print("W: Unknown PKCS1 (rsa key) format: " + err.Error())
	privateKey, err = x509.ParseECPrivateKey(bytesPrivateKey)
	if err == nil {
		return privateKey, nil
	}
	log.Print("W: Unknown EC PrivateKey format: " + err.Error())

	return nil, err
}

func StorePrivateKeyPem(out io.Writer, p crypto.PrivateKey, password []byte) ( e error) {

	bytesPrivateKey, err := x509.MarshalPKCS8PrivateKey(p)
	if err != nil {
		return err
	}

	if password != nil {
		block, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", bytesPrivateKey, password, x509.PEMCipherAES256)
		if err != nil {
			return err
		}
		return pem.Encode(out, block)
	}

	block := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   bytesPrivateKey,
	}
	return pem.Encode(out, &block)
}

func LoadCertificate(in io.Reader) (c []byte, e error) {
	buf, err := ioutil.ReadAll(in)
	if err != nil {
		return nil, err
	}

	cert, _ := pem.Decode(buf)

	return cert.Bytes, nil
}

func StoreCertificate(out io.Writer, cert []byte) (err error) {
	var pemCertificate = &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert,
	}
	err = pem.Encode(out, pemCertificate)
	if err != nil {
		return err
	}

	return nil
}