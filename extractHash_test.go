package main

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestExtractMD5RAW(t *testing.T) {
	// test case is "password"
	testCase := "MD5:5f4dcc3b5aa765d61d8327deb882cf99"
	decodedHash, err := hex.DecodeString("5f4dcc3b5aa765d61d8327deb882cf99")
	check(err)
	testHash := Hash{decodedHash, SaltList{}, MD5RAW, "", ""}

	hash := extractMD5RAW(testCase)
	if !reflect.DeepEqual(testHash, hash) {
		t.Errorf("Expected hash value %x, got %x", testHash.Hash, hash.Hash)
	}

}
