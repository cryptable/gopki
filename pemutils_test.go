package gopki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"strings"
	"testing"
)


func TestLoadRSAPrivateKeyPem(t *testing.T) {
	// Arrange
	var privateKeyPEM = `-----BEGIN PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,75789C9EC3390E591A76C4B245AACEA0

eIa75FQfJsa5X4CHMk9rZGOoxcS0ONVc1wwT7rGpvoNF8Qs4IwSj9IDMCEtaCEgA
frvwQ/x1vnWAP6QXAr0TdlqCB8iBH/xedNBalSQFEUYPo2ob84zfInDzP/cuh6/Z
1en/5kW+sgz09HjCCMRrDaf7/dmjmvjkSUDYgZoLQDg/twIcQgQV76h43+Vgu5bY
Vp46OBE+vJXSfdBXYoYboLGx/qe7iQ5ylUEjRse2z+ZxhjsWRFoJ8ywLYgkFGiF1
BO7cTpXR+Wtxpf4M9aBnrtTguwAYLXCz6Bg1tXtouqvco3kR2nZZ1MBL83jSLwhB
mFfAHTGf8utsWqHuhXefOeHNd+Z/WeyuF8bIE86n60/SQhlSUSwQkY35d+I0yAcY
FcT2cB8jge5OVrXAykNKUzAnCHKTFh3Npn3SGss5PMYspHQH99YuU1q/o9qBKC/K
KC74LDIiYhnfUkRaAbu+JceWkSBgJ1PQH1HH4sE/NM+reSxuFijqZ18VPZLG5a/r
73ghAc94REzV+ivMlFS3kjGLyguiRuz4NE1O7DHi+kZXn6NBv1OeH8sxYA3lSmU+
vh08U+36Tm5eyqv/onYNH/aVycX3L47R/JBYVbC3wJUYlEagsMYp4jx1MnDqF3qI
NlTAauYS+fj0TCGVmuhrQRjDpMw+LM6hgIaGMUm8YF6f8N64wFpyrW7Pa2ZQ9S59
9YytP3mCd/RCdjW001Tpr82nl00j+bFh63WbxQvrmFTPo3MetUBUe/WLGVCjCfLk
BkICZ03OHoiV5fw5plclr9AVvMlENzFjlOerXv07zrd+vq32bzOJImlb3WCqqw+4
wTEyLnKXCC6Ve65X/njAdPCT2MEzlzu4A+pdgmnETXWgRjq4uutoRjLv8+dLYHxv
51QeD1iUAiBkXLM3c2Uq+QjG7lYq7L/+AGo/TYyUABpE9V6sU7ErQ6rURQLceKaY
zy+RlQE7jg8zo4SW/UnAWZ8Un6RWuflBy3PFTW8voQ6g4REO/PEe7zJBLE9mElmM
RRM/5zDacEqRsizVYcQ/wOtYIE+7Gsf1sxQk8BlfxwF75FxP7JzI4qEfhQfd4lKL
euDfRHlTpFVXjkTWYpeAHn0x9Sa6LpSwkF22hXcg8FeGdwhoQ0XQc6Je1dAtmGRU
S8n+2bz9W0/XG1rmsfYoOajgkOJPAn1zi45WLYiGItNhuT4Uc+5j8z72Yky7DQbf
9NCWmsPJDuzfmcbzwITOa63jUkHlbhftTy6TtigKYw3DZtefFLbOe3nPPtbpnEJL
bQdVtYlyCF2hEa7WSAhH169jX05GgwxILQAIJY/O4ED1oXtfqXMEwzZtv+KKvdWB
Pqe3AcfqclFmyr2BlO6NclMGOc5lPp6RB4e9BQ50Cz7k/+8cmFDdEvGxgwQz509C
c240NvbiKafmKUW0Td6OMw4G+ZWe8VI0saoWMOxbnjTaTISSOD4/AdkRUe0hsmOh
c2xQaGMMOOSsFtedaHp/MXTd0wGH4o3PVADCCeRyvMRSUp7xl6vUYMgcnUB1QVXE
4Xbu9qSaiw8r8NGGHJltlPVPacV7XZnztRyE2omaDeJ6ewH/keaqD+U8f8Q22aZB
-----END PRIVATE KEY-----`

	// Act
	privateKey, err := LoadPrivateKeyPem(strings.NewReader(privateKeyPEM), []byte("system"))
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKey.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}
}


func TestLoadECPrivateKeyPem(t *testing.T) {
	// Arrange
	var privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,0543BED119CB14061C85375666E24B60

QA1epgwinpB4wO/yqx4zzEbpGuHCQnXUndyViVmDSORSOGOpVbJqQbVwcsWHQ1Xa
j+cSRaPNmvRgBEWqLYmRsEKyKX/GS587Fv60ff3fnqR7uleVo040KWssnVoYwWEH
vvnNbTOQ5B6MTBmJjFYLTZ9VaLtJ31/CRnm94rYtMxpq5ktj4h/RO2ca9XfWmTEh
0D9jA27xh02bl+jY1+B8oe9RKK/7EMQB+v0f0COPJdhu4ZznL8odvECtCAxq6mSL
PZWa7bY81iMibqXrqsI/yukgUY4+KHOz7HdU8oKhJOM=
-----END EC PRIVATE KEY-----`

	// Act
	privateKey, err := LoadPrivateKeyPem(strings.NewReader(privateKeyPEM), []byte("system"))
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKey.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}
}

func TestLoadPlainRSAPrivateKeyPem(t *testing.T) {
	// Arrange
	var privateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCps80oik8LQg5R
Rjh0JBCMAmugslABaZaJxiHHJlCmk+OOa9AaNvp+iCl1eH3DrlNEPC/J4Hhi8pk4
PdXrasS+2sWmpyx4+c92Bgw1otvHJhxmwhcNPOpL5bGFXR3yDypD4FZebuOeeJnQ
gZ8oA48W2OAGSN7XgXqgDUHIx4efUrTemSngAB+sxg3rWH16pu+5a8PDnbO3Mszl
9j0JoQp/AK9MHilJiBR8DFiltMiOGusYCZbYKtBQdzJRjjCmW+FLA9TZOTBupIpG
M2PWCq8c/qIyobNIVeVnzBKPLXrb4U0fR17cb6AnAHCaDVG3MD5/URq/qbxTu7rb
M6k4nUepAgMBAAECggEBAJnHB6Kz6jq+afD2G9QKlj/5NYRR8LPG9ZX1R8iKDM1V
9/+n7NTEeytLwZ3kSLqYbnXHwFpEIXMweO2BAycoAg8cebyxglhBruA5TLkR0exd
uaDYQkFJsNqD0uCR57/gRCFr2XgLLhH9IQzTWODOkMxYTHEFeYF5oCAGw1Tokhop
Q0sBl1HnMoQtSeq9Ejd3e7yVr3jAGh/b2JDgR2IPGO4Qxo2gPLsdPtGN0Na1AUD8
pkgP+NwNx/h1htzzMEbYUnKvMmDrJwV58mTryBtYwqpnyNSDoKe2AdfyolWaN60r
/DvZ+yCH06McaKKFMu6cHUcz/WKdw0UlSOp6MfJzUwECgYEA1RnGq1Iciaessriq
8U53PXvJC5Y0wYuWL3ZZnQk1KwW0IE8J3Y7wO4ZcWSRlvr3cUQm2vqbyHp14rIUQ
OefKsewU0MXXmZQYQ9ao7HiIZuqcE68TW2vcS2WI7zhz4tFmD40GYYqMGmEe6qIC
6Z2cEVH2adCwcUJMFBalnIf/i4kCgYEAy915xjacuHGQ3+CKr+JucA7kjn/kksQU
5i4tCo1hI6skBs/FNKpCjl47e3UO8mgGZK+yu3LHvq+y3kuqlCU7kIM6HwETXg/N
dTmFzDMOwUeR9v/2CVuDVTFha2d3I4rZ93DsLBE6dLPtOUKairUEt3NLWeJ/e1Ou
QogsoDDgMyECgYEAr+Ym5yNQCxAsrRlhgO2T31xeBwJlaZ0eyu6V6dm/2VNL659S
NV/XTEsLz0kL8vYk9X9fKOAE2uCAy2bKjgGWfmawh+PGoy5rGRQHO6oCbXEag+Tv
xXay0ElvTob6oS7XX964das3Gk8whdxVKyC9wk41aAKqodJnme1Xpm1bsoECgYBp
E293laBzhL1qVv7Epw3LHjH5rLuwVfZ7qaM3hCVkUAqSpDZ97Z++Z517BZu9n5Zk
ARc7fG6tvzuPTirOjt5Dnw+u+Uv1OGnqmMp4tHxPbMc0KzuyGQP5Pil7RWnn3OJ5
oi9oizy4+CA2Wjjzc1fKAlf9LTwN4dS4oB14N5jnYQKBgQCa6x1hhwUP9qApkjbe
71IJNL37TznhBkDDLuGVhfous6XKDiVJKYLZcWYKXmGT0m9LPr7REMgyGzaOn69s
0B7GzbU6dkoMQ2XIyFsceIIZWBbjHFpCCNwzPw6XXmONpsUweljuBxioU8kaF1a+
kxGtQ/gbEd2SoCyz/eRDNmfUvA==
-----END PRIVATE KEY-----`

	// Act
	privateKey, err := LoadPrivateKeyPem(strings.NewReader(privateKeyPEM), nil)
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKey.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}
}

func TestLoadPlainECPrivateKeyPem(t *testing.T) {
	// Arrange
	var privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB+wfTeP8s0ddlvxdZj4DOhh7yXI8kPwHjsXZXOl8gTsVP2A7TEBJ0
AsYz2Cr9qj8B6sQozrYWOOHmi09vX3g9hyOgBwYFK4EEACOhgYkDgYYABABQybkC
mqrv3PbaS7DjqPwuRvanpjUUd63S5NIQUXLi0LTjb0FAI/++LeYUIMCX9MpCkcq3
u3WJZyumWCewvECakAA0bp0P9yk2Xnu0AB7ZibEJkz7xzISCL4YGf+mJlbKelUUm
M3EYXUoFFfkmLPXqIqSb+cUG+cmvOQpygqh7WW1pGA==
-----END EC PRIVATE KEY-----`

	// Act
	privateKey, err := LoadPrivateKeyPem(strings.NewReader(privateKeyPEM), nil)
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKey.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}
}

func TestStoreRSAPrivateKeyPem(t *testing.T) {
	// Arrange
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Act
	buf := new(bytes.Buffer)
	err := StorePrivateKeyPem(buf, privateKey, []byte("system"))
	if err != nil {
		t.Error("StorePrivateKeyPem failed: " + err.Error())
		return
	}

	// Assert
	privateKeyTst, err := LoadPrivateKeyPem(bytes.NewReader(buf.Bytes()), []byte("system"))
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKeyTst.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}

	// Store file to test with openssl
	w, err := os.Create("./testing/encryptedRSAKey.pem")
	defer w.Close()
	if err != nil {
		t.Error("Create file failed: " + err.Error())
		return
	}
	_, err = w.Write(buf.Bytes())
	if err != nil {
		t.Error("Write file failed: " + err.Error())
		return
	}
}

func TestStoreRSAPrivateKeyPlainPem(t *testing.T) {
	// Arrange
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Act
	buf := new(bytes.Buffer)
	err := StorePrivateKeyPem(buf, privateKey, nil)
	if err != nil {
		t.Error("StorePrivateKeyPem failed: " + err.Error())
		return
	}

	// Assert
	privateKeyTst, err := LoadPrivateKeyPem(bytes.NewReader(buf.Bytes()), nil)
	if err != nil {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}
	key, ok := privateKeyTst.(crypto.Signer)
	if ! ok  {
		t.Error("LoadPrivateKeyPem failed: " + err.Error())
		return
	}

	h := sha256.New()
	h.Write([]byte("Bytes needed to be signed"))
	hash := h.Sum(nil)

	var signerOpts crypto.SignerOpts = crypto.SHA256
	_, err = key.Sign(rand.Reader, hash[:], signerOpts)
	if err != nil {
		t.Error("Sign failed: " + err.Error())
		return
	}
}

func TestLoadCertificate(t *testing.T) {
	certPEM := `-----BEGIN CERTIFICATE-----
MIIFBDCCAuygAwIBAgICB+MwDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCQkUx
EjAQBgNVBAoTCUNyeXB0YWJsZTEOMAwGA1UEAxMFR29QS0kwHhcNMTkxMTAzMTUw
NjEyWhcNMjkxMTAzMTUwNjEyWjAxMQswCQYDVQQGEwJCRTESMBAGA1UEChMJQ3J5
cHRhYmxlMQ4wDAYDVQQDEwVHb1BLSTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAMUj0FF+gZkY8hXPS2LKu4J9GT7TCNaxDpLR5h5eLWBPYj2rNpMJpX5s
Rh40ReQVvtw04GO6AAEfTPJZh/L07G6Oz5b9jci/jKWpt/ZOtVs6LmCGKVk94G+h
4oRZXpvxq/cFktgbKZV9R8Kn3QxCigG+TtIr27/EYiL52R+quIzh7SrdODNSB5UU
TrVumLi9OCWtRsRZ5NEw8jMhIfF9MdqIAQke9ideePqNEUjbziBxrWIghJcyKajr
bF7YYXyRx2sFp4IIw+/2tDrbSed5qEfibUIR8aHDYGxGO9qzVInXN6/YshbDQuLl
1lQ/KLuU+hkAgPWkROvWhHFzFiYF4g/DFhDj+Fcg76iWtuPnWFEm4mAFwBVSXkZS
UejaF7Cma2FUtCSwN1YVbQQupwDcVi+fFhXe/mj/dp5zaTz0Fi0FRaybbYnjNe9U
0nBicW2eH5Bs5xnXDqwfrQ/pOf5wlWtgLKC2HqmfE1+MhDVe9dxPPC2iXn8Ua4K3
CicDcAmgAbQUeCWNGjO8BnYADj/btzpg2GA3KpSSNW5TQibK8DUO/L/NCFH5Zm+q
H3X7wQYDhFkR9r2jyyzZMLr+ECjCV/w+Z4ylV8+NetTT/te2a96mfC4MnWvXZEBE
H9QTjh1UABmKtnBEuhVhuV0YG6B3apZtby8yOSj+o9/yWaURluFPAgMBAAGjJjAk
MA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEB
CwUAA4ICAQBoVxhptIVb/9VqnY52UU6O5idXWMjWxheXZCFXjS1vN4qtwLEGkiOu
xumzV9wPfCcQfOtdZqVpGX4Nkt0GQyfwWLyIZzT5WpfMKOlpOa+mFnZLFTZZTrf1
JrM9xKwpjAPhE1YbbxPzk/TQmx7zNqtoMzpbudXpKBC443dpuKMD0rts0aH0Bw8A
cx6dV3A/zQS8p1X5TJvEULUwQcmraFK68WEbSyOsWSe9AY3cYnxJLVrjAjmxtqYQ
zdYkwCVtckmpNsWBzt7fUgklThD/vcVf1Yd+lFRyiRMAIzQCBdM9Z2AVutKYsuLZ
rhQ1FER57/g4hgJG+S1rKTVWFvfPlcjhMoOyLQT7AiODIi1QMfH29zRabbUopBSn
ZRIFKBW6suDcCdh+Bc5//GANZR/8dyO7w2Ric5aAtmft8057jZJI9FkNe5HgjKl1
01YrAWSek5yFXjxjqWin5GFFFbptr2uRP3OfKKShOZasxcwRoWc/LsSfVzLVQBjU
WKwrTHXrO+BT2F/o3T6JJXxciOV+UZHmjC22ebrGc1ICMd5Z9BDjG7n7U5RyaxBw
N2+zlRqKGFE7dbqSinfmdEjo126uaTuW4NC9CzmctJpBIcY96SAgLwZxg0BmYOYQ
ij2DWRma36BP7dAlJzF2hXHRuEFx7XArgGZmva7PjiHclCNIBNZANQ==
-----END CERTIFICATE-----`

	cert, err := LoadCertificate(strings.NewReader(certPEM))
	if err != nil {
		t.Error("LoadCertificate failed: " + err.Error())
		return
	}

	_, err = x509.ParseCertificate(cert)
	if err != nil {
		t.Error("ParseCertificate failed: " + err.Error())
		return
	}

	// Test store certificate
	buf := new(bytes.Buffer)
	err = StoreCertificate(buf, cert)
	if err != nil {
		t.Error("StoreCertificate failed: " + err.Error())
		return
	}
	_, err = LoadCertificate(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Error("LoadCertificate after store failed: " + err.Error())
		return
	}

}