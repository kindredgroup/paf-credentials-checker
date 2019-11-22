package main

import (
	"encoding/hex"
	"strings"
)

func detectHash(data string) int {
	switch {
	case data == "MD5":
		return MD5RAW
	case data == "MD5spSHA1sp":
		return MD5SaltPreSHA1SaltPre
	default:
		return UNKNOWN

	}
}

func extractTokens(hashType int, data string) Hash {
	switch hashType {
	case MD5RAW:
		return extractMD5RAW(data)
	case MD5SaltPreSHA1SaltPre:
		return extractMD5SaltPreSHA1SaltPre(data)
	default:
		return Hash{[]byte(""), SaltList{}, UNKNOWN, "", ""}
	}
}

func extractMD5RAW(data string) Hash {
	split := strings.Split(data, ":")
	encodedHash := split[1]
	decodedHash, err := hex.DecodeString(encodedHash)
	check(err)

	hash := Hash{decodedHash, SaltList{}, MD5RAW, "", ""}

	return hash
}

func extractMD5SaltPreSHA1SaltPre(data string) Hash {
	// md5(salt1.sha1(salt2.password)) with upper hex output for sha1 hash
	// Salts are taken from the outer layer to the inner one, e.g. type:hash:salt1:salt2
	split := strings.Split(data, ":")
	encodedHash := split[1]
	decodedHash, err := hex.DecodeString(encodedHash)
	check(err)

	hash := Hash{decodedHash, SaltList{Salt(split[2]), Salt(split[3])}, MD5SaltPreSHA1SaltPre, "", ""}

	return hash
}
