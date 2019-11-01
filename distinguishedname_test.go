package gopki

import "testing"

func TestParseDistinguishedName(t *testing.T) {
	res, err := ParseDistinguishedName("CN=GOPKI , O=Cryptable , C=BE")
	if err != nil {
		t.Error("ParseDistinguishedName: ", err)
		return
	}

	print("Key :" + res[0].key)
	print("Value :" + res[0].value)
	if len(res) != 3 {
		t.Error("ParseDistinguishedName: ", len(res))
		return
	}
}
