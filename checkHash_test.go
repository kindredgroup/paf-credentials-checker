package main

import (
	"testing"
)

func TestCheckMD5RAW(t *testing.T) {
	// test case is "password"
	// we assume the extract function is working correctly as it's covered by another test...
	testCase := "MD5:5f4dcc3b5aa765d61d8327deb882cf99"
	goodPassword := "password"
	badPassword := "bad password"

	hash := extractMD5RAW(testCase)
	if !checkMD5RAW(hash, goodPassword) {
		t.Errorf("Expected true for check of %s against %s", goodPassword, testCase)
	}

	if checkMD5RAW(hash, badPassword) {
		t.Errorf("Expected false for check of %s against %s", badPassword, testCase)
	}

}
