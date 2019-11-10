package models

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"fmt"
	"gopki/ca"
	"log"
	"math/big"
	rand2 "math/rand"
	"os"
	"testing"
	"time"
)

func TestNewSQLiteDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"

	//Act
	db, err := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()

	//Assert
	if err != nil {
		t.Error("NewSQLiteDB failed: " + err.Error())
	}

	if bytes.Compare(db.confidentiality,[]byte("Confidentiality")) != 0 {
		t.Errorf("Invalid NewSQLiteDB confidentiality data : %q expected %s", db.confidentiality, "Confidentiality")
	}

	if bytes.Compare(db.integrity,[]byte("Integrity")) != 0 {
		t.Errorf("Invalid NewSQLiteDB confidentiality data : %q expected %s", db.integrity, "Integrity")
	}
}

func TestNewSQLiteDBFailureInvalidDirectory(t *testing.T) {
	// Arrange
	ds := "file:../falsedir/test.sqlite"

	//Act
	_, err := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))

	//Assert
	if err == nil {
		t.Fatal("NewSQLiteDB success is a failure")
	}
	t.Log("INFO: error = " + err.Error())
}

func TestNewSQLiteDBFailureInvalidDataSource(t *testing.T) {
	// Arrange
	ds := "tcp://passwd@test.com"

	//Act
	_, err := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))

	//Assert
	if err == nil {
		t.Fatal("NewSQLiteDB success is a failure")
	}
	t.Log("INFO: error = " + err.Error())
}

func TestSQLiteDB_CreateDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()

	//Act
	err := db.CreateDB()

	//Assert
	if err != nil {
		t.Errorf("SQLiteDB_CreateDB() failed : %q", err.Error() )
	}

}

// CA Storage interface testing.
func dropDB(db *sql.DB) {
	db.Exec("DROP TABLE CA;")
	db.Exec("DROP TABLE CERTIFICATES;")
}

func verifyNameInDB(db *sql.DB, caid int64, canameRef string) bool {
	rows, err := db.Query("SELECT caname FROM CA WHERE caid = ?", caid)
	if err != nil {
		log.Panic("Error: ", err)
	}
	defer rows.Close()

	if ! rows.Next() {
		log.Panic("CAID not found : " + string(caid))
	}
	if err = rows.Err(); err != nil {
		log.Panic("Error: ", err)
	}
	var caname string
	if err = rows.Scan(&caname);  err != nil {
		log.Panic("Error: ", err)
	}
	if caname != canameRef {
		return false
	}
	return true
}

func createTestCA(cadname string) ([]byte, crypto.PrivateKey) {

	rnd := rand.Reader
	rsaKey, _ := rsa.GenerateKey(rnd, 1024) // Don't use insecure but faster
	pkixName, _ := ca.ConvertDNToPKIXName(cadname)
	caTemplate := x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     *pkixName,
		NotBefore:                   time.Now(),
		NotAfter:                    time.Now().AddDate(10,0,0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
	}
	cert, _ := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, rsaKey.Public(), rsaKey)

	return cert, rsaKey
}

func teardown() {

}

func TestSQLiteCAStorage_StoreCA(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))

	// Act
	caRet, err := store.StoreCA(*ca)

	// Assert
	if err != nil {
		t.Fatalf("SQLiteCAStorage_StoreCA() failed : %s", err.Error())
	}
	if bytes.Compare(ca.Bytes, caRet.Bytes) != 0 {
		t.Error("SQLiteCAStorage_StoreCA() failed ca certificates not equal")
	}
	if caRet.CAId == ca.CAId {
		t.Error("SQLiteCAStorage_StoreCA() failed ca CAId still 0")
	}
	if !verifyNameInDB(db.db, caRet.CAId, "bootstrap") {
		t.Logf("SQLiteCAStorage_StoreCA() failed ca CAId does not correspond to name %d : %s", caRet.CAId, store.caname)
	}
	t.Logf("INFO: Verify with DB Browser for SQLite  caname = %s, caId = %d", store.caname, caRet.CAId)
}

func TestSQLiteCAStorage_StoreCAMultipleCAs(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	for i:= 0 ; i<20; i++ {
		caname := fmt.Sprintf("ca%d", i)
		cadname := fmt.Sprintf("CN=Test CA%d, O=Test, C=BE", i)
		store := NewSQliteCAStorage(db, caname)
		cacert, cakey :=  createTestCA(cadname)
		ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))

		// Act
		caRet, err := store.StoreCA(*ca)

		// Assert
		if err != nil {
			t.Fatalf("SQLiteCAStorage_StoreCA() failed for %s : %s", caname, err.Error())
		}
		if !verifyNameInDB(db.db, caRet.CAId, caname) {
			t.Logf("SQLiteCAStorage_StoreCA() failed ca CAId does not correspond to name %d : %s", caRet.CAId, store.caname)
		}

	}
}

func TestSQLiteCAStorage_StoreCAMultipleCAsKeepEven(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	for i:= 0 ; i<20; i++ {
		caname := fmt.Sprintf("ca%d", i)
		cadname := fmt.Sprintf("CN=Test CA%d, O=Test, C=BE", i)
		store := NewSQliteCAStorage(db, caname)
		cacert, cakey :=  createTestCA(cadname)
		ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))

		// Act
		caRet, err := store.StoreCA(*ca)

		// Assert
		if err != nil {
			t.Fatalf("SQLiteCAStorage_StoreCA() failed for %s : %s", caname, err.Error())
		}
		if !verifyNameInDB(db.db, caRet.CAId, caname) {
			t.Logf("SQLiteCAStorage_StoreCA() failed ca CAId does not correspond to name %d : %s", caRet.CAId, store.caname)
		}

		if caRet.CAId % 2 == 1 {
			store.sqlite.db.Exec("DELETE FROM CA WHERE caid = ?", caRet.CAId)
		}
	}
}

func TestSQLiteCAStorage_StoreCAFailureSameCAName(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA1, O=Test, C=BE")
	ca1, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	cacert, cakey =  createTestCA("CN=Test CA2, O=Test, C=BE")
	ca2, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))

	// Act
	store.StoreCA(*ca1)
	_, err := store.StoreCA(*ca2)

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_StoreCA() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_StoreCAFailureRemoveDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	os.Remove("../testing/test.sqlite")

	// Act
	_, err := store.StoreCA(*ca)

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_StoreCA() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_GetCA(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	caTmp, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	caRef, _ := store.StoreCA(*caTmp)

	// Act
	caVer, err := store.GetCA()

	// Assert
	if err != nil {
		t.Fatalf("SQLiteCAStorage_GetCA() failed : %s", err.Error())
	}
	if caVer.CAId != caRef.CAId {
		t.Errorf("SQLiteCAStorage_GetCA() failed CA CAIds not equal")
	}
	if bytes.Compare(caVer.Bytes, caRef.Bytes) != 0 {
		t.Errorf("SQLiteCAStorage_GetCA() failed CA certificates don't compare")
	}
}

func TestSQLiteCAStorage_GetCAFromMultipleCAs(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	for i:= 0 ; i<20; i++ {
		caname := fmt.Sprintf("ca%d", i)
		cadname := fmt.Sprintf("CN=Test CA%d, O=Test, C=BE", i)
		store := NewSQliteCAStorage(db, caname)
		cacert, cakey := createTestCA(cadname)
		ca, _ := ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
		store.StoreCA(*ca)
	}
	rand2.Seed(time.Now().UnixNano())
	rand := rand2.Intn(20)
	caname := fmt.Sprintf("ca%d", rand)
	store := NewSQliteCAStorage(db, caname)

	// Act
	caVerify, err := store.GetCA()

	// Assert
	if err != nil {
		t.Fatalf("SQLiteCAStorage_GetCA() failed : %s", err.Error())
	}
	caCommonName := fmt.Sprintf("Test CA%d", rand)
	if caVerify.Certificate.Issuer.CommonName != caCommonName {
		t.Errorf("SQLiteCAStorage_GetCA() failed with wrong CA : %s", caVerify.Certificate.Issuer.String())
	}
	t.Logf("INFO: CA Found %s", caVerify.Certificate.Issuer.String())
}

func TestSQLiteCAStorage_GetCAFailureEmptyDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")

	// Act
	_, err := store.GetCA()

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_GetCA() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_GetCAFailureNoDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	defer db.CloseDB()
	dropDB(db.db)
	os.Remove("../testing/test.sqlite")
	store := NewSQliteCAStorage(db, "bootstrap")

	// Act
	_, err := store.GetCA()

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_GetCA() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_GetCAFailureWrongConfidentiality(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	store.StoreCA(*ca)
	db.CloseDB()
	db, _ = NewSQLiteDB(ds, []byte("Integrity"), []byte("WrongKey"))
	store = NewSQliteCAStorage(db, "bootstrap")

	// Act
	_, err := store.GetCA()

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_GetCA() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_GetNextSerialNumber(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	store.StoreCA(*ca)

	// Act
	nextSerNum, err := store.GetNextSerialNumber()

	// Assert
	if err != nil {
		t.Fatalf("SQLiteCAStorage_GetNextSerialNumber() Failed : " + err.Error())
	}
	if nextSerNum.Cmp(big.NewInt(3)) != 0 {
		t.Error("SQLiteCAStorage_GetNextSerialNumber() failed with not equal to 3 : " + nextSerNum.String())
	}
}

func TestSQLiteCAStorage_GetNextSerialNumberFailureWrongCA(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	store.StoreCA(*ca)
	store = NewSQliteCAStorage(db, "wrongca")

	// Act
	_, err := store.GetNextSerialNumber()

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_GetNextSerialNumber() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}

func TestSQLiteCAStorage_GetNextSerialNumberFailureRemoveDB(t *testing.T) {
	// Arrange
	ds := "file:../testing/test.sqlite"
	db, _ := NewSQLiteDB(ds, []byte("Integrity"), []byte("Confidentiality"))
	dropDB(db.db)
	db.CreateDB()
	store := NewSQliteCAStorage(db, "bootstrap")
	cacert, cakey :=  createTestCA("CN=Test CA, O=Test, C=BE")
	ca, _:= ca.NewCA(0, store, cacert, cakey, big.NewInt(2))
	store.StoreCA(*ca)
	os.Remove("../testing/test.sqlite")

	// Act
	_, err := store.GetNextSerialNumber()

	// Assert
	if err == nil {
		t.Fatalf("SQLiteCAStorage_GetNextSerialNumber() success is a failure")
	}
	t.Logf("INFO: Error message %q", err.Error())
}