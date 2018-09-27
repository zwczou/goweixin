package goweixin

import (
	"testing"
)

func TestToData(t *testing.T) {
	var in1 = struct {
		A int `xml:"a"`
		B string
		C int `xml:"c,omitempty"`
		D int `xml:"-"`
		E interface{}
		F bool `xml:"f,omitempty"`
	}{
		A: 1,
		B: "2",
		C: 3,
		D: 4,
		E: nil,
		F: true,
	}
	params1 := ToData(in1, "xml")
	if len(params1) != 5 {
		t.FailNow()
	}
	if params1["B"] != "2" || params1["a"] != "1" {
		t.FailNow()
	}
	if params1["E"] != "" || params1["f"] != "true" {
		t.FailNow()
	}
}
