package gopki

import (
	"errors"
)

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
	if len(data) > 0 &&
		data[0] == '\\' &&
		isSpecial(data[1:]) {
		return true
	}
	return false
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

	for i := 0; i < len(data); i++ {
		if !isDigit(data[i:]) {
			break
		}
		digit += data[i:(i+1)]
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
		for i := 0; i < len(data); i += 1 {
			if !(isStringChar(data[i:]) ||
				 isSpecial(data[i:]) ||
				 isPair(data[i:])) {
				break
			}
			res += data[i:(i+1)]
			width++
		}
		if  len(data) == width ||
			data[width] != '"' {
			return res, width, errors.New("missing qoute")
		}

		res += data[width:(width+1)]
		width++

		return res, width, nil
	}

	if data[0] == '#' {
		for i := 0; i < len(data); i += 1 {
			if !(data[0] == '#' ||
				isHex(data)) {
				break
			}
			res += data[i:(i+1)]
			width++
		}
		if len(data) == 1 {
			return res, width, errors.New("missing hexadecimal number")
		}
		return res, width, nil
	}

	for i := 0; i < len(data); i += 1 {
		if !(isStringChar(data[i:]) ||
			 isPair(data[i:])) {
			break
		}
		width++
	}

	return res, width, nil
}

/*
<oid> ::= <digitstring> | <digitstring> "." <oid>
*/
func getOId(oid string) (s string, w int, err error) {

	res, width := getDigitString(oid)
	if width == 0 {
		return "", 0, errors.New("No oid")
	}
	for i, w := 0, 0; i < len(oid[width:]); i += w {
		if oid[i] == '.' {
			nb, wl := getDigitString(oid)
			if wl == 0 {
				return "", 0, errors.New("missing OID number")
			}
			res = res + "." + nb
			w += wl + 1
		}
		width += w
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

	for i:=0; i<len(data); i++ {
		if !isKeyChar(data[i:]) {
			break
		}
		res += data[i:(i+1)]
		width++
	}

	if width == 0 {
		return "", 0, errors.New("not an attribute key")
	}

	if width > 4 &&
		(res[0:4] == "OID." ||
		res[0:4] == "oid." ) {
		_, _, err := getOId(res[4:])
		if err != nil {
			return "", 0, errors.New("not a valid attribute key: invalid OID")
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
func nameComponent(data string) (attrs *Attribute, width int, err error) {

	attr, width, err := getAttribute(data)
	if err != nil {
		return nil, 0, errors.New("nameComponent failed: " + err.Error())
	}
	attrN := &(attr.next)
	for i, w := 0, 0; i < len(data[width:]); i = w {
		ws := optionalSpaces(data[i:])
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
		w = width
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

	res[0], width, err = nameComponent(data)
	if err != nil {
		return nil, errors.New("parseDistinguishedName failed: " + err.Error())
	}

	for i, w := 0, 0; i < len(data[width:]); i = w {
		ws, err := spacedSeperator(data[width:])
		if err != nil {
			return nil, errors.New("parseDistinguishedName failed: " + err.Error())
		}
		width += ws
		if len(data) == width {
			break
		}
		tmpRes, ws, err := nameComponent(data[width:])
		if err != nil {
			return nil, errors.New("parseDistinguishedName failed: " + err.Error())
		}
		res = append(res, tmpRes)
		width += ws
		w = width
	}

	return res, nil
}