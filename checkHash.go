package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

func checkMD5RAW(hash Hash, password string) bool {
	md := md5.Sum([]byte(password))
	if bytes.Equal(hash.Hash, md[:]) {
		return true
	}

	return false
}

func checkMD5SaltPreSHA1SaltPre(hash Hash, password string) bool {
	// md5(salt1.sha1(salt2.password)) with upper hex output for hashes
	var innerBuffer bytes.Buffer
	var externalBuffer bytes.Buffer

	innerBuffer.Write(hash.Salts[1])
	innerBuffer.WriteString(password)
	innerSum := sha1.Sum(innerBuffer.Bytes())
	hexInnerSum := strings.ToUpper(hex.EncodeToString(innerSum[:]))

	externalBuffer.Write(hash.Salts[0])
	externalBuffer.WriteString(hexInnerSum)
	md := md5.Sum(externalBuffer.Bytes())

	if bytes.Equal(hash.Hash, md[:]) {
		return true
	}

	return false
}
