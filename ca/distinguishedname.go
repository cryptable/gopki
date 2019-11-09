package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"log"
	"strconv"
	"strings"
)

/*
Parsing is according to the RFC 1779, though probably we will have deviate from it in the real world
Experience will tell ;-)
*/

/*
   <special> ::= "," | "=" | <CR> | "+" | "<" |  ">"
            | "#" | ";"
 */
func isSpecial(data string) (b bool) {

	if data[0] == ',' ||
		data[0] == '=' ||
		data[0] == '\n' ||
		data[0] == '+' ||
		data[0] == '<' ||
		data[0] == '>' ||
		data[0] == '#' ||
		data[0] == ';' {
		return true
	}
	return false
}

func isHex(data string) (b bool) {
	if isDigit(data) ||
		data[0] == 'A' || data[0] == 'a' ||
		data[0] == 'B' || data[0] == 'b' ||
		data[0] == 'C' || data[0] == 'c' ||
		data[0] == 'D' || data[0] == 'd' ||
		data[0] == 'E' || data[0] == 'e' ||
		data[0] == 'F' || data[0] == 'f' {
		return true
	}

	return false
}

/*
   <pair> ::= "\" ( <special> | "\" | '"')
 */
func isPair(data string) (b bool) {
	if len(data) > 1 &&
		data[0] == '\\' &&
		(isSpecial(data[1:]) ||
			data[1] == '\\' ||
			data[1] == '"') {
		return true
	}
	return false
}

/*
   <pair> ::= "\" ( <special> | "\" | '"')
*/
func getPair(data string) (s string, err error) {
	if len(data) > 1 &&
		data[0] == '\\' &&
		(isSpecial(data[1:]) ||
			data[1] == '\\' ||
			data[1] == '"') {
		res := data[0:2]
		return res, nil
	}
	return "", errors.New("No a valid pair")
}

/*
   <stringchar> ::= any character except <special> or "\" or '"'
 */
func isStringChar(data string) (b bool) {
	if data[0] == '\\' ||
		data[0] == '"' ||
		isSpecial(data) {
		return false
	}

	return true
}

/*
   <digit> ::= digits 0-9
 */
func isDigit(data string) (b bool) {
	if data[0] >= '0' &&
		data[0] <= '9' {
		return true
	}
	return false
}

/*
   <digitstring> ::= 1*<digit>
 */
func getDigitString(data string) (s string, w int) {
	digit := ""
	width := 0

	for ; width < len(data); {
		if !isDigit(data[width:]) {
			break
		}
		digit += data[width:(width+1)]
		width++
	}

	return digit, width
}

/*
   <string> ::= *( <stringchar> | <pair> )
            | '"' *( <stringchar> | <special> | <pair> ) '"'
            | "#" <hex>
 */
func getString(data string) (s string, w int, err error) {
	res := ""
	width := 0

	if data[0] == '"' {
		res += data[0:1]
		width++
		for ; width < len(data); {
			// end quote (TODO set after for loop)
			if data[width] == '"' {
				res += data[width:(width+1)]
				width++
				break
			}
			// special and stringchar (1 char only)
			if isStringChar(data[width:]) ||
				isSpecial(data[width:]) {
				res += data[width:(width+1)]
				width++
				continue
			}
			// pair (2 characters)
			if isPair(data[width:]) {
				tmp, _ := getPair(data[width:])
				res += tmp
				width += 2
				continue
			}
			// something wrong
			break
		}

		if data[width-1] != '"' {
			return res, width, errors.New("missing qoute")
		}

		return res, width, nil
	}

	// Hex code
	if data[0] == '#' {
		res += data[width:(width+1)]
		width++
		for ; width < len(data); {
			if ! isHex(data[width:]) {
				break
			}
			res += data[width:(width+1)]
			width++
		}
		if len(res) == 1 {
			return res, width, errors.New("missing hex number")
		}
		return res, width, nil
	}

	// Normal string
	for ; width < len(data); {
		if !(isStringChar(data[width:]) ||
			 isPair(data[width:])) {
			break
		}
		res += data[width:(width+1)]
		width++
	}
	// remove the trailing space, but keep width
	res = strings.TrimRight(res, " ")
	width = len(res)
	// remove the leading space, normally remove by optional spaces
	res = strings.TrimLeft(res, " ")

	return res, width, nil
}

/*
<oid> ::= <digitstring> | <digitstring> "." <oid>
*/
func getOID(oid string) (s string, w int, err error) {

	res, width := getDigitString(oid)
	if width == 0 {
		return "", 0, errors.New("no oid")
	}
	for ; width < len(oid); {
		if oid[width] != '.' {
			break
		}
		width++
		nb, wl := getDigitString(oid[width:])
		if wl == 0 {
			return "", 0, errors.New("missing number")
		}
		res = res + "." + nb
		width += wl
	}

	return res, width, nil
}

/*
	<keychar> ::= letters, numbers, and space
*/
func isKeyChar(data string) (bool) {
	if (data[0] >= 'A' && data[0] <= 'Z') ||
		(data[0] >= 'a' && data[0] <= 'z') ||
		isDigit(data) {
		return true
	}
	return false
}

/*
   <key> ::= 1*( <keychar> ) | "OID." <oid> | "oid." <oid>
*/
func getKey(data string) (s string, w int, err error) {
	res := ""
	width := 0

	for ; width <len(data); {
		if !isKeyChar(data[width:]) {
			break
		}
		res += data[width:(width+1)]
		width++
	}

	if width == 0 {
		return "", 0, errors.New("not an attribute key")
	}

	if width == 3 &&
		(res == "OID" ||
		res == "oid" ) {
		if width < len(data) && data[width] == '.' {
			tmp, wl, err := getOID(data[4:])
			if err != nil {
				return "", 0, errors.New("not a valid attribute key: invalid OID")
			}
			res = res + "." + tmp
			width = width + 1 + wl
		}
	}
	return res, width, nil
}

/*
<optional-space> ::= ( <CR> ) *( " " )
 */

func optionalSpaces(data string) (w int) {
	width := 0

	for i := 0; i < len(data); i++ {
		if data[i] != ' ' {
			break
		}
		width++
	}

	return width
}

/*
<separator> ::=  "," | ";"
 */
func isSeperator(data string) (b bool) {
	return data[0] == ',' || data[0] == ';'
}

type Attribute struct {
	key string
	value string
	next *Attribute
}

/*
<attribute> ::= <string>
| <key> <optional-space> "=" <optional-space> <string>
*/
func getAttribute(data string) (attr *Attribute, w int, err error) {
	width := 0

	resKey, w1, err := getKey(data)
	if err != nil {
		return  nil, 0, errors.New("getKey failed:" + err.Error())
	}
	width += w1
	ws1 := optionalSpaces(data[width:])
	width += ws1
	if width == len(data) {
		return &Attribute{ "", resKey, nil }, width, nil
	}
	if data[width] != '=' {
		return nil, 0, errors.New("getKey failed: missing '=' sign")
	}
	width++
	ws2 := optionalSpaces(data[width:])
	width += ws2
	resValue, w2, err := getString(data[width:])
	width += w2
	if err != nil {
		return nil, 0, errors.New("getString failed:" + err.Error())
	}
	return &Attribute{ resKey, resValue, nil } , width, nil
}

/*
<name-component> ::= <attribute>
| <attribute> <optional-space> "+"
<optional-space> <name-component>
*/
func getNameComponent(data string) (attrs *Attribute, width int, err error) {

	attr, width, err := getAttribute(data)
	if err != nil {
		return nil, 0, errors.New("nameComponent failed: " + err.Error())
	}
	attrN := &(attr.next)
	for ; width < len(data); {
		ws := optionalSpaces(data[width:])
		width += ws
		if (len(data) > width) &&
			(data[width] != '+') {
			break
		}
		width++
		ws = optionalSpaces(data[width:])
		width += ws
		if len(data) == width {
			return nil, 0, errors.New("nameComponent failed: missing attribute")
		}
		tmpAttr, wl, err := getAttribute(data[width:])
		if err != nil {
			return nil, 0, errors.New("nameComponent failed: " + err.Error())
		}
		width += wl
		*attrN = tmpAttr
		attrN = &(tmpAttr.next)
	}

	return attr, width, nil
}

/*
<spaced-separator> ::= <optional-space>
<separator>
<optional-space>
*/
func spacedSeperator(data string) (w int, err error) {
	width := optionalSpaces(data)
	if ! isSeperator(data[width:]) {
		return 0, errors.New("missing seperator")
	}
	width++
	width = width + optionalSpaces(data[width:])
	return width, nil
}

/*
<name> ::= <name-component> ( <spaced-separator> )
          | <name-component> <spaced-separator> <name>
 */
func ParseDistinguishedName(data string) (attr []*Attribute, err error){
	res := make([]*Attribute, 1)
	width := 0

	res[0], width, err = getNameComponent(data)
	if err != nil {
		return nil, errors.New("parseDistinguishedName failed: " + err.Error())
	}

	for ; width < len(data); {
		ws, err := spacedSeperator(data[width:])
		if err != nil {
			return nil, errors.New("parseDistinguishedName failed: " + err.Error())
		}
		width += ws
		if len(data) == width {
			break
		}
		tmpRes, ws, err := getNameComponent(data[width:])
		if err != nil {
			return nil, errors.New("parseDistinguishedName failed: " + err.Error())
		}
		res = append(res, tmpRes)
		width += ws
	}

	return res, nil
}

/*
type	description	OID
C	countryName	2.5.4.6
CN	commonName	2.5.4.3
DC	domainComponent	0.9.2342.19200300.100.1.25
E	emailAddress (deprecated)	1.2.840.113549.1.9.1
G or GN	givenName	2.5.4.42
L	localityName	2.5.4.7
O	organizationName	2.5.4.10
OU	organizationalUnit	2.5.4.11
SERIALNUMBER	serialNumber	2.5.4.5
SN	surname	2.5.4.4
ST or S	stateOrProvinceName	2.5.4.8
STREET	streetAddress	2.5.4.9
T or TITLE	title	2.5.4.12
UID	userID	0.9.2342.19200300.100.1.1
*/
var DC = asn1.ObjectIdentifier { 0, 9, 2342, 19200300, 100, 1, 25 }
var EMAIL = asn1.ObjectIdentifier { 1, 2, 840, 113549, 1, 9, 1 }
var GN = asn1.ObjectIdentifier { 2, 5, 4, 42 }
var SN = asn1.ObjectIdentifier { 2, 5, 4, 4 }
var ST = asn1.ObjectIdentifier { 2, 5, 4, 8 }
var TITLE = asn1.ObjectIdentifier { 2, 5, 4, 12 }
var UID = asn1.ObjectIdentifier { 0, 9, 2342, 19200300, 100, 1, 1 }

func convertStringToOID(oid string) (o asn1.ObjectIdentifier, e error) {
	res := []int{}

	if (strings.ToUpper(oid[0:4]) != "OID.") {
		return nil, errors.New("invalid oid string")
	}
	numbers :=  strings.Split(oid[4:], ".")
	for i:=0; i<len(numbers); i++ {
		nbr, err := strconv.Atoi(numbers[i])
		if err != nil {
			return nil, err
		}
		res = append(res, nbr)
	}

	return res, nil
}

// TODO: Refactor the function
func ConvertDNToPKIXName(dn string) (p *pkix.Name, e error) {
	attrs, err := ParseDistinguishedName(dn)

	if err != nil {
		log.Fatal("Unable to convert Distinguished Name: " + err.Error())
		return nil, err
	}

	pkixName := pkix.Name{}
	for i := 0; i < len(attrs); i++ {
		if strings.ToUpper(attrs[i].key) == "C" {
			pkixName.Country = append(pkixName.Country, attrs[i].value)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "CN" {
			pkixName.CommonName = attrs[i].value
			continue
		}
		if strings.ToUpper(attrs[i].key) == "DC" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  DC,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "E" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  EMAIL,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "GN" ||
			strings.ToUpper(attrs[i].key) == "G" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  GN,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "L" {
			pkixName.Locality = append(pkixName.Locality, attrs[i].value)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "O" {
			pkixName.Organization = append(pkixName.Organization, attrs[i].value)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "OU" {
			pkixName.OrganizationalUnit = append(pkixName.OrganizationalUnit, attrs[i].value)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "SERIALNUMBER" {
			pkixName.SerialNumber = attrs[i].value
		}
		if strings.ToUpper(attrs[i].key) == "SN" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  SN,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "ST" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  ST,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "STREET" {
			pkixName.StreetAddress = append(pkixName.StreetAddress, attrs[i].value)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "T" ||
			strings.ToUpper(attrs[i].key) == "TITLE" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  TITLE,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		if strings.ToUpper(attrs[i].key) == "UID" {
			pkixAttr := pkix.AttributeTypeAndValue{
				Type:  UID,
				Value: attrs[i].value,
			}
			pkixName.Names = append(pkixName.Names, pkixAttr)
			continue
		}
		oid, err := convertStringToOID(attrs[i].key)
		if err != nil {
			return nil, err
		}
		pkixAttr := pkix.AttributeTypeAndValue{
			Type:  oid,
			Value: attrs[i].value,
		}
		pkixName.Names = append(pkixName.Names, pkixAttr)
	}

	return &pkixName, nil
}