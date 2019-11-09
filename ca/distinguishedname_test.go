package ca

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"testing"
)

func TestIsSpecial(t *testing.T) {
	data := [...]string{ ",", "=", "\n", "+", "<", ">", "#", ";"}

	if isSpecial("h") {
		t.Error("iSSpecial failed for normal character")
		return
	}
	for i := 0; i < len(data); i++ {
		if ! isSpecial(data[i]) {
			t.Error("iSSpecial failed for special character")
			return
		}
	}
}

func TestIsPair(t *testing.T) {
	data := [...]string{ "\\,", "\\=", "\\\n", "\\+", "\\<", "\\>", "\\#", "\\;", "\\\\", "\\\""}

	if isPair("h") {
		t.Error("isPair failed for non pair characters")
		return
	}
	if isPair("\\h") {
		t.Error("isPair failed for normal character")
		return
	}
	for i := 0; i < len(data); i++ {
		if ! isPair(data[i]) {
			t.Error("isPair failed for pair character")
			return
		}
	}
}

func TestIsHex(t *testing.T) {
	data := [...]string{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"A", "B", "C", "D", "E", "F",
		"a", "b", "c", "d", "e", "f"}

	if isHex("K") {
		t.Error("isHex failed for non hex character")
		return
	}
	for i := 0; i < len(data); i++ {
		if ! isHex(data[i]) {
			t.Error("isHex failed for hex character")
			return
		}
	}
}

func TestIsStringChar(t *testing.T) {
	data := [...]string{ ",", "=", "\n", "+", "<", ">", "#", ";", "\\", "\"" }

	if ! isStringChar("K") {
		t.Error("isStringChar failed for string character")
		return
	}
	for i := 0; i < len(data); i++ {
		if isStringChar(data[i]) {
			t.Error("isStringChar failed for non string character")
			return
		}
	}
}

func TestIsDigit(t *testing.T) {
	data := [...]string{ "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" }

	if isDigit("K") {
		t.Error("isDigit failed for non digit character")
		return
	}
	for i := 0; i < len(data); i++ {
		if ! isDigit(data[i]) {
			t.Error("isStringChar failed for digit character")
			return
		}
	}
}

func TestGetDigitString(t *testing.T) {
	digit := "1234567890"

	value, width := getDigitString(digit)
	if value != digit ||
		width != len(digit) {
		t.Error("getDigitString failed for valid digit string")
		return
	}

	nondigit := "123HG89"
	value, width = getDigitString(nondigit)
	if value != "123" ||
		width != 3 {
		t.Error("getDigitString failed for valid digit string")
		return
	}

	empty := ""
	value, width = getDigitString(empty)
	if value != "" ||
		width != 0 {
		t.Error("getDigitString failed for valid digit string")
		return
	}
}

func TestGetString(t *testing.T) {
	data := "\"Test string with \\, ; \\\\ and \\\" \""

	value, width, err := getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != data ||
		width != len(data) {
		t.Error("getString failed for valid string in \" with pairs and special characters:" + value)
		return
	}

	data = "\"Test string with \\, ; \\\\ and \\\" \", another string"
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != "\"Test string with \\, ; \\\\ and \\\" \"" ||
		width != len("\"Test string with \\, ; \\\\ and \\\" \"") {
		t.Error("getString failed for normal string")
		return
	}

	data = "#14EFc65"
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != data ||
		width != len(data) {
		t.Error("getString failed for hex string")
		return
	}

	data = "#14GFc65"
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != "#14" ||
		width != 3 {
		t.Error("getString failed for partial hex string")
		return
	}

	data = "Normal Test string"
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != data ||
		width != len(data) {
		t.Error("getString failed for normal string")
		return
	}

	data = "Normal Test string, another string"
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != "Normal Test string" ||
		width != len("Normal Test string") {
		t.Error("getString failed for normal string")
		return
	}

	data = "Normal Test string with spaces  "
	value, width, err = getString(data)
	if err != nil {
		t.Error("getString failed:" + err.Error())
		return
	}
	if value != "Normal Test string with spaces" ||
		width != len("Normal Test string with spaces") {
		t.Error("getString failed for normal string with spaces")
		return
	}
}

func TestGetOId(t *testing.T) {
	data := "1.2.3.897.09.37"

	value, width, err := getOID(data)
	if err != nil {
		t.Error("getOID failed:" + err.Error())
		return
	}
	if value != data ||
		width != len(data) {
		t.Error("getOID failed for OID :" + value)
		return
	}

	data = "1.2.3.897.09."
	value, width, err = getOID(data)
	if err == nil ||
		err.Error() != "missing number" {
		t.Error("getOID failed: no error when ending with a dot")
		return
	}

	data = "dsfsf"
	value, width, err = getOID(data)
	if err == nil ||
		err.Error() != "no oid" {
		t.Error("getOID failed: no error for a non oid")
		return
	}
}

func TestIsKeyChar(t *testing.T) {
	for c:='a' ; c<='z'; c++ {
		if ! isKeyChar(string(c)) {
			t.Error("isKeyChar failed : a-z")
		}
	}

	for c:='A' ; c<='Z'; c++ {
		if ! isKeyChar(string(c)) {
			t.Error("isKeyChar failed : A-Z")
		}
	}

	for c:='0' ; c<='9'; c++ {
		if ! isKeyChar(string(c)) {
			t.Error("isKeyChar failed : 0-9")
		}
	}

	if isKeyChar("#") {
		t.Error("isKeyChar failed : #")
	}
}

func TestGetKey(t *testing.T) {
	data := "CN = Test"

	value, width, err := getKey(data)
	if err != nil {
		t.Error("getKey failed:" + err.Error())
		return
	}
	if value != "CN" ||
		width != 2 {
		t.Error("getOID failed for OID :" + value)
		return
	}

	data = "OID.1.2.3.5 = Test"
	value, width, err = getKey(data)
	if err != nil {
		t.Error("getKey failed:" + err.Error())
		return
	}
	if value != "OID.1.2.3.5" ||
		width != len("OID.1.2.3.5") {
		t.Error("getKey failed for OID :" + value)
		return
	}

	data = "oid.1.2.3.5 = Test"
	value, width, err = getKey(data)
	if err != nil {
		t.Error("getKey failed:" + err.Error())
		return
	}
	if value != "oid.1.2.3.5" ||
		width != len("oid.1.2.3.5") {
		t.Error("getKey failed for OID :" + value)
		return
	}

	data = "oid.1.2.3. = Test"
	value, width, err = getKey(data)
	if err == nil {
		t.Error("getKey failed:" + err.Error())
		return
	}
	if err.Error() == "missing number" {
		t.Error("getKey failed with error :" + err.Error())
		return
	}
}

func TestOptionalSpaces(t *testing.T) {
	data := "   Test"

	width := optionalSpaces(data)
	if width != 3 {
		t.Error("optionalSpaces failed -> width:" + string(width))
		return
	}

	data = "Test   "

	width = optionalSpaces(data)
	if width != 0 {
		t.Error("optionalSpaces failed -> width:" + string(width))
		return
	}
}

func TestIsSeperator(t *testing.T) {
	data := ";"

	if ! isSeperator(data) {
		t.Error("isSeperator failed: " + data)
		return
	}

	data = ","

	if ! isSeperator(data) {
		t.Error("isSeperator failed: " + data)
		return
	}

	data = "j"

	if isSeperator(data) {
		t.Error("isSeperator failed: " + data)
		return
	}
}

func TestGetAttribute(t *testing.T) {
	data := "CN = Test"

	attr, width, err := getAttribute(data)
	if err != nil {
		t.Error("getAttribute failed: " + err.Error())
		return
	}
	if width != len(data) {
		t.Error("getAttribute failed for width: " + strconv.Itoa(width))
		return
	}
	if attr.key != "CN" &&
		attr.value != "Test" &&
		attr.next != nil {
		t.Error("getAttribute failed for parameter: " + attr.key + ":" + attr.value)
		return
	}

	data = "Test"

	attr, width, err = getAttribute(data)
	if err != nil {
		t.Error("getAttribute failed: " + err.Error())
		return
	}
	if width != len(data) {
		t.Error("getAttribute failed for width: " + strconv.Itoa(width))
		return
	}
	if attr.key != "" &&
		attr.value != "Test" &&
		attr.next != nil {
		t.Error("getAttribute failed for parameter: " + attr.key + ":" + attr.value)
		return
	}

	data = "Test =,"

	attr, width, err = getAttribute(data)
	if err != nil {
		t.Error("getAttribute failed: " + err.Error())
		return
	}
	if width != (len(data) - 1) {
		t.Error("getAttribute failed for width: " + strconv.Itoa(width))
		return
	}
	if attr.key != "Test" &&
		attr.value != "" &&
		attr.next != nil {
		t.Error("getAttribute failed for parameter: " + attr.key + ":" + attr.value)
		return
	}
}

func TestNameComponent(t *testing.T) {
	data := "CN = Test"

	attr, width, err := getNameComponent(data)
	if err != nil {
		t.Error("getNameComponent failed: " + err.Error())
		return
	}
	if width != len(data) {
		t.Error("getNameComponent failed for width: " + strconv.Itoa(width))
		return
	}
	if attr.key != "CN" &&
		attr.value != "Test" &&
		attr.next != nil {
		t.Error("getNameComponent failed for parameter: " + attr.key + ":" + attr.value)
		return
	}
	data = "CN = Test + OU = Organisation Unit + O = Organisation"

	attr, width, err = getNameComponent(data)
	if err != nil {
		t.Error("getNameComponent failed: " + err.Error())
		return
	}
	if width != len(data) {
		t.Error("getNameComponent failed for width: " + strconv.Itoa(width))
		return
	}
	if attr.key != "CN" ||
		attr.value != "Test" ||
		attr.next == nil {
		t.Error("getNameComponent failed for parameter: " + attr.key + ":" + attr.value)
		return
	}
	attrn := attr.next
	if attrn.key != "OU" ||
		attrn.value != "Organisation Unit" ||
		attrn.next == nil {
		t.Error("getNameComponent failed for parameter: " + attrn.key + ":" + attrn.value)
		return
	}
	attrn = attrn.next
	if attrn.key != "O" ||
		attrn.value != "Organisation" ||
		attrn.next != nil {
		t.Error("getNameComponent failed for parameter: " + attrn.key + ":" + attrn.value)
		return
	}

}

func TestSpacedSeperator(t *testing.T) {
	data := "  ,  "

	width, err := spacedSeperator(data)
	if err != nil {
		t.Error("spacedSeperator failed: " + err.Error())
		return
	}
	if width != 5 {
		t.Error("spacedSeperator failed with width " + strconv.Itoa(width))
		return
	}

	data = ",  "

	width, err = spacedSeperator(data)
	if err != nil {
		t.Error("spacedSeperator failed: " + err.Error())
		return
	}
	if width != 3 {
		t.Error("spacedSeperator failed with width " + strconv.Itoa(width))
		return
	}

	data = "  ,"

	width, err = spacedSeperator(data)
	if err != nil {
		t.Error("spacedSeperator failed: " + err.Error())
		return
	}
	if width != 3 {
		t.Error("spacedSeperator failed with width " + strconv.Itoa(width))
		return
	}

	data = "  m"
	width, err = spacedSeperator(data)
	if err == nil {
		t.Error("spacedSeperator failed with no error")
		return
	}
	if err.Error() != "missing seperator" {
		t.Error("spacedSeperator failed with wrong error")
		return
	}
}

func TestParseDistinguishedName(t *testing.T) {

	res, err := ParseDistinguishedName("CN=GOPKI , O=Cryptable , C=BE")
	if err != nil {
		t.Error("ParseDistinguishedName: ", err)
		return
	}

	if len(res) != 3 {
		t.Error("ParseDistinguishedName: failed with attribute length ", len(res))
		return
	}

	if res[0].key != "CN" ||
		res[0].value != "GOPKI" ||
		res[0].next != nil {
		t.Error("ParseDistinguishedName: first value failed ")
		return
	}

	if res[1].key != "O" ||
		res[1].value != "Cryptable" ||
		res[1].next != nil {
		t.Error("ParseDistinguishedName: second value failed ")
		return
	}

	if res[2].key != "C" ||
		res[2].value != "BE" ||
		res[2].next != nil {
		t.Error("ParseDistinguishedName: second value failed ")
		return
	}

	res, err = ParseDistinguishedName("CN=GOPKI , O=\"CN=Test , O=\\\"Organisation, system\\\"\" , C=BE")
	if err != nil {
		t.Error("ParseDistinguishedName: ", err)
		return
	}

	if len(res) != 3 {
		t.Error("ParseDistinguishedName: failed with attribute length ", len(res))
		return
	}

	if res[0].key != "CN" ||
		res[0].value != "GOPKI" ||
		res[0].next != nil {
		t.Error("ParseDistinguishedName: first value failed ")
		return
	}

	if res[1].key != "O" ||
		res[1].value != "\"CN=Test , O=\\\"Organisation, system\\\"\"" ||
		res[1].next != nil {
		t.Error("ParseDistinguishedName: second value failed ")
		return
	}

	if res[2].key != "C" ||
		res[2].value != "BE" ||
		res[2].next != nil {
		t.Error("ParseDistinguishedName: second value failed ")
		return
	}
}

func TestConvertStringToOID(t *testing.T) {
	data := "OID.1.2.3.4"
	oidRef := asn1.ObjectIdentifier{1,2,3,4}

	oid, err := convertStringToOID(data)
	if err != nil {
		t.Error("convertStringToOID failed: " + err.Error())
		return
	}
	if ! oidRef.Equal(oid) {
		t.Error("convertStringToOID failed: oids not equal")
		return
	}
}

func TestConvertDNToPKIXName1(t *testing.T) {

	pkixName, err := ConvertDNToPKIXName("CN=GOPKI , O=Cryptable , C=BE")
	if err != nil {
		t.Error("ConvertDNToPKIXName failed: " + err.Error())
		return
	}
	if pkixName.CommonName != "GOPKI" {
		t.Error("ConvertDNToPKIXName failed: common name " + pkixName.CommonName)
		return
	}
	if pkixName.Organization[0] != "Cryptable" {
		t.Error("ConvertDNToPKIXName failed: organization " + pkixName.Organization[0])
		return
	}
	if pkixName.Country[0] != "BE" {
		t.Error("ConvertDNToPKIXName failed: country " + pkixName.Country[0])
		return
	}
}

func TestConvertDNToPKIXName2(t *testing.T) {

	pkixName, err := ConvertDNToPKIXName("CN=GOPKI , O=Cryptable , E=test@cryptable.org")
	if err != nil {
		t.Error("ConvertDNToPKIXName failed: " + err.Error())
		return
	}
	if pkixName.CommonName != "GOPKI" {
		t.Error("ConvertDNToPKIXName failed: common name " + pkixName.CommonName)
		return
	}
	if pkixName.Organization[0] != "Cryptable" {
		t.Error("ConvertDNToPKIXName failed: organization " + pkixName.Organization[0])
		return
	}
	if pkixName.Names[0].Value != "test@cryptable.org" ||
		! pkixName.Names[0].Type.Equal(EMAIL) {
		t.Error("ConvertDNToPKIXName failed: " + fmt.Sprintf("%v", pkixName.Names[0].Value))
		return
	}
}

func TestConvertDNToPKIXName3(t *testing.T) {

	pkixName, err := ConvertDNToPKIXName("CN=GOPKI , O=Cryptable , OID.1.2.3.4=custom")
	if err != nil {
		t.Error("ConvertDNToPKIXName failed: " + err.Error())
		return
	}
	if pkixName.CommonName != "GOPKI" {
		t.Error("ConvertDNToPKIXName failed: common name " + pkixName.CommonName)
		return
	}
	if pkixName.Organization[0] != "Cryptable" {
		t.Error("ConvertDNToPKIXName failed: organization " + pkixName.Organization[0])
		return
	}
	if pkixName.Names[0].Value != "custom" ||
		! pkixName.Names[0].Type.Equal(asn1.ObjectIdentifier{1,2,3,4}) {
		t.Error("ConvertDNToPKIXName failed: " + fmt.Sprintf("%v", pkixName.Names[0].Value))
		return
	}
}