package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"gopki/utils"
	"math/big"
	"os"
	"strings"
	"testing"
)

type MockStorage struct {
	mockCA *CA
}
// ---------- mockDB ----------
func NewMockDB() (*MockStorage) {
	db := new(MockStorage)
	return db
}

func (db *MockStorage) GetCA() (*CA, error) {
	return db.mockCA, nil
}

func (db *MockStorage) StoreCA(ca CA) (*CA, error) {
	db.mockCA = &ca
	return db.mockCA, nil
}

func (db *MockStorage) GetNextSerialNumber() (*big.Int, error) {
	db.mockCA.certificateSerialNumber = db.mockCA.certificateSerialNumber.Add(db.mockCA.certificateSerialNumber, big.NewInt(1))
	return db.mockCA.certificateSerialNumber, nil
}

// ---------- Testing Module ----------

func TestCreateCA(t *testing.T) {
	// Arrange
	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, 4096)
	storage := NewMockDB()

	// Act
ca, err := CreateCA(storage,"CN=GoPKI,O=Cryptable,C=BE", 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("CreateCA() Failed", err)
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

	if ca.certificateSerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Error("Serial number is not 1: ", ca.certificateSerialNumber)
	}
}

func TestNewCA(t *testing.T) {
	// Arrange
	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, 4096)
	storage := NewMockDB()
	testca, err := CreateCA(storage,"CN=GoPKI,O=Cryptable,C=BE", 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("CreateCA() Failed", err)
		return
	}

	ca, err := NewCA(0, storage, testca.Bytes, testca.priv, testca.certificateSerialNumber)
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

	if ca.certificateSerialNumber.Cmp(big.NewInt(2)) != 0 {
		t.Error("Serial number is not 1: ", ca.certificateSerialNumber)
	}
}

func TestNewCAFailure(t *testing.T) {
	// Arrange
	rnd := rand.Reader
	rsaKey, err := rsa.GenerateKey(rnd, 4096)
	storage := NewMockDB()
	testca, err := CreateCA(storage,"CN=GoPKI,O=Cryptable,C=BE", 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("NewCA() Failed", err)
		return
	}

	_, err = NewCA(0, storage, []byte("garbage"), testca.priv, testca.certificateSerialNumber)
	if err == nil {
		t.Error("CreateCA() success is a failure")
		return
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
	storage := NewMockDB()

	ca, err := CreateCA(storage,"CN=GoPKI,O=Cryptable,C=BE", 10, rsaKey.Public(), rsaKey)
	if err != nil {
		t.Error("NewCA() Failed", err)
		panic(err)
	}

	// Write the CA for external validation
	// Create directory if not exists
	os.Mkdir("../testing", os.ModePerm)

	err = storeCertificate(ca.Bytes, "../testing/ca.pem")
	if err != nil {
		t.Error("store certificate failed :", err)
		return
	}

	err = storePrivateKey(ca.priv, "../testing/ca_key.pem")
	if err != nil {
		t.Error("store certificate failed :", err)
		return
	}

	ca,err = ca.storage.StoreCA(*ca)

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

	// Act
	cert, err := setupCA.CreateTLSClientCertificate("CN=SSL Server, O=Cryptable, C=BE", rsaKey.Public())

	// Assert
	if err != nil {
		t.Error("CA.CreateTLSCLientCertificate failed: ", err)
		return
	}
	if cert == nil {
		t.Error("Certificate is nil")
		return
	}

	err = storeCertificate(cert, "../testing/tlsclient.pem")
	if err != nil {
		t.Error("store certificate failed: ", err)
	}
	err = storePrivateKey(rsaKey, "../testing/tlsclient_key.pem")
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

	// Act
	cert, err := setupCA.CreateTLSServerCertificate("CN=SSL Server, O=Cryptable, C=BE", rsaKey.Public())

	// Assert
	if err != nil {
		t.Error("CA.CreateTLSServerCertificate failed: ", err)
		return
	}
	if cert == nil {
		t.Error("Certificate is nil")
		return
	}

	err = storeCertificate(cert, "../testing/tlsserver.pem")
	if err != nil {
		t.Error("store certificate failed: ", err)
	}
	err = storePrivateKey(rsaKey, "../testing/tlsserver_key.pem")
	if err != nil {
		t.Error("store private key failed: ", err)
	}
}

func TestLoadCA(t *testing.T) {
	// Arrange
	cacert := `-----BEGIN CERTIFICATE-----
MIIFBDCCAuygAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCQkUx
EjAQBgNVBAoTCUNyeXB0YWJsZTEOMAwGA1UEAxMFR29QS0kwHhcNMTkxMTAzMTUz
MzUzWhcNMjkxMTAzMTUzMzUzWjAxMQswCQYDVQQGEwJCRTESMBAGA1UEChMJQ3J5
cHRhYmxlMQ4wDAYDVQQDEwVHb1BLSTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMi2TcFwsSKyNWvdQfqKLP8dj14fj1Btspnoe3AFkUElhc+mx4BtgNJU
pA/dGDu17EG7O0NMeLDSO12eDjzzvjJo3SQ+n8E9vXKs2xpP0Q9vxpd3tTAykmgq
gYSfvDVhYhErtfAt1Euao6T5tnuVmlqGsjX5YY93qxFwWfgw2ZoOrft54Wy4k0EJ
c0nkrnek2fWb5y/XVqsxlkIzL/RV+bwRNtu3WVMlhZR71wpejm1adDCODHKBW2GH
1sFMpDxis4hk7p7n7i2eMAXwQUq930obYxW0kGQR8DlkJtONYq0DlSyur0+NnbWp
+6nOEyVjAIaspFm4RR/bUWA6PRnZQ/wVOKs06wCbRt8/KWaS4TTlmGU8Me057xqB
YMGnmIy79Q5St8JhjdKsEVBNFBa68ARV/Vf72v3fNATMdQMqGnncV3qL/BcOnCB+
/ubLRnnOa0VyHV8X71v43HX5590t6/4+aoGg8VUiT1WLqp+4OHsI/tUsWcSnpZSk
pZw/4PgMCgjG42j3DRH/xkjd/vjO+IMJxqhWxmr+0lWDQ/I/8d1giGsPiweFsUQZ
09PMNfaWBaO+EG9+nxDm1KtumhyLnynbVcamxLMBn2sX91XQDD1VmjKqfYUbcuKI
24IUcd6wdVBT5BMUovxuWwuyMmjXVOuW2KVs801fwcbPM6uIWS8rAgMBAAGjJjAk
MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEB
CwUAA4ICAQA/aiScU3ZlufPgToVNvaVVvI0QAiFD6+bHdWx4Vr7b3zMVvZkOUvNs
PymA5vegcZ2302MRtSF+s/eUGtpE6QBBtj3WBBep/4RAZ2KYKDiufuE1dQVjTEa8
ybk4hbImR+aPPuwlRKBhMjS2Mc0ZSGcEvPLRCD1P5QLmbv622Otum7VPhuXi7TXb
re1twqJRcODL+KDe6iVAlQxGIrh2EH7R/ZI1MH3oRV79DBMNqXlbOWdVAMEvv+lV
JcEdo2Wx8aZi2TR1HzkIof1oHOhaFtkyqmFPFjqcNxzqvX/dFs3En78IhuOK0dv6
Zc3hpaCTOHoHvBr7pBiUyGPmt5M0wd5qG8cBnXbRa6+4mseO1BYb51jjRQQwxtux
9P2Mp92Gr3jBHu4jhhrcKSwPCmyEuRIsqFvG/QT3DASGpTzxudsgahDPbhwtdqed
tkOyvBURTRAbsJk/QMaJVHFoB2ciy5Oo6oY1fyVv7abHN6SOdbBCJst90oGOnGT0
ADU1/w3LPrjka4Hio/vTsBG4eddFLce0C7Pxx4JWttmGkxuKO+/K/fDAx4OSFy5/
+cVfV6tsFpjgL5WyrmLVvSqNi300UfwV5Nbxb4oIB0RXFz8NfmVrX8EI9iW6hGNt
ipCgSBu3oig2iKwdNSQy3hVggp3qlP9zsOhPpYRLXcyeomIu8vRMWQ==
-----END CERTIFICATE-----`
	caprivate := `-----BEGIN PRIVATE KEY-----
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
j6D1pJp1jVVYmDXGDGGegW9LKDVEzk8=
-----END PRIVATE KEY-----`
	serialNumber := big.NewInt(100)
	cert, _ := utils.LoadCertificate(strings.NewReader(cacert))
	certificate, _ := x509.ParseCertificate(cert)
	priv, _ := utils.LoadPrivateKeyPem(strings.NewReader(caprivate), nil)
	storage := NewMockDB()
	storage.StoreCA(CA{ 0,priv, cert, certificate, serialNumber, storage})

	// Act
	ca, err := LoadCA(storage)

	// Assert
	if err != nil {
		t.Error("LoadCA failed: " + err.Error())
		return
	}
	tlskeys, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err = ca.CreateTLSClientCertificate("CN=Test", tlskeys.Public())
	if err != nil {
		t.Error("LoadCA failed: " + err.Error())
		return
	}
}

func TestCA_GetPrivateData(t *testing.T) {
	// Arrange
	setup(t)
	defer teardown(t)

	// Act
	priv, sn, err := setupCA.GetPrivateData([]byte("test"))

	// Assert
	if err != nil {
		t.Error("GetPrivateData failed: " + err.Error())
		return
	}

	sernum := new(big.Int)
	sernum = sernum.SetBytes(sn)
	if sernum.Cmp(setupCA.certificateSerialNumber) != 0 {
		t.Error("Sernum not equal: " + sernum.String())
		return
	}
	_, err = utils.LoadPrivateKeyPem(strings.NewReader(priv), []byte("test"))
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
}