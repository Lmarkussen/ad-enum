package main

import "testing"

func pxeOptions(a, b string) []byte {
	payload := make([]byte, 240)
	envelope := make([]byte, 2+48+2+len(a))
	envelope[0], envelope[1] = 2, 48
	envelope[51] = byte(len(a))
	copy(envelope[52:], a)
	payload = append(payload, 243, byte(len(envelope)))
	payload = append(payload, envelope...)
	payload = append(payload, 252, byte(len(b)))
	payload = append(payload, []byte(b)...)
	payload = append(payload, 255)
	return payload
}

func TestParseOptionsReturnsServerSuppliedSMSTempPaths(t *testing.T) {
	got, err := parseOptions(pxeOptions(`\SMSTemp\fixture.boot.var`, `\SMSTemp\fixture.boot.bcd`))
	if err != nil || got[0] != `\SMSTemp\fixture.boot.var` || got[1] != `\SMSTemp\fixture.boot.bcd` {
		t.Fatalf("paths=%q err=%v", got, err)
	}
}

func TestParseOptionsRejectsUnboundedPath(t *testing.T) {
	if _, err := parseOptions(pxeOptions(`\SMSTemp\..\fixture.boot.var`, `\SMSTemp\fixture.boot.bcd`)); err == nil {
		t.Fatal("accepted traversal path")
	}
}
