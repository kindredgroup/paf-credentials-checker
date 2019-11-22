package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Definition of different supported verbose hash types
const (
	MD5RAW                = iota
	MD5SaltPreSHA1SaltPre = iota
	UNKNOWN               = iota
)

// Salt is an alias to []bytes
type Salt []byte

// SaltList is just a slice of Salts
type SaltList []Salt

// Hash structure contains the fields extracted from the credentials
type Hash struct {
	Hash        []byte
	Salts       SaltList
	Type        int
	InternalID0 string
	InternalID1 string
}

// HashList is a list containing Hash structures, it's used in the map table to contain all the credentials belonging to a specific ID
type HashList []Hash

// HashMap is a lookup table containing internal hashed credentials belonging to a specific ID
type HashMap map[string]HashList

// Credentials is a structure extending the Hash one with a candidate password
type Credentials struct {
	Hash     Hash
	Password string
}

var wgWrite sync.WaitGroup
var wgCrack sync.WaitGroup

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func loadCredentials(credentials *HashMap, filename string) int {
	fmt.Println("[*] Loading credentials")
	f, err := os.Open(filename)
	check(err)
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// expected format for internal credentials file
		// data format : internalID0:InternalID1:mapping_id:hashtype:hash:[salt[:salt[:...]]
		//  data fields:      0            1        2       3      4     5
		count++
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 250 {
			continue
		}
		data := strings.Split(line, ":")
		// detect hashtype
		pwstate := data[3]
		hashType := detectHash(pwstate)
		// extract tokens
		hash := extractTokens(hashType, strings.Join(data[3:], ":"))
		if hash.Hash == nil {
			continue
		}

		// add to HashMap
		internalID0 := data[0]
		internalID1 := data[1]
		hash.InternalID0 = internalID0
		hash.InternalID1 = internalID1
		mappingID := data[2]
		(*credentials)[mappingID] = append((*credentials)[mappingID], hash)

	}

	fmt.Println("[+] Credentials loaded")

	return count
}

func crackHash(hash Hash, password string) bool {
	switch hash.Type {
	case MD5RAW:
		return checkMD5RAW(hash, password)
	case MD5SaltPreSHA1SaltPre:
		return checkMD5SaltPreSHA1SaltPre(hash, password)
	default:
		return false

	}

}

func microCracker(credentials chan Credentials, writer chan string) {
	defer wgCrack.Done()

	for cred := range credentials {
		hash := cred.Hash
		password := cred.Password
		isCracked := crackHash(hash, password)
		if isCracked {
			var buffer bytes.Buffer

			buffer.WriteString(hash.InternalID0)
			buffer.WriteString(",")
			buffer.WriteString(hash.InternalID1)
			buffer.WriteString("\n")

			writer <- buffer.String()
		}
	}
}

func microWriter(writer chan string, filename string, cracked *int) {
	crackedFile, err := os.Create(filename)
	check(err)
	defer crackedFile.Close()
	defer wgWrite.Done()

	var tmpBuffer bytes.Buffer
	tmpBuffer.WriteString("internal_id_0,internal_id_1\n")
	crackedFile.Write(tmpBuffer.Bytes())

	for line := range writer {
		*cracked++
		crackedFile.WriteString(line)
	}
}

func processFile(dictName string, processed *int, found *int, cracked *int, credChan chan Credentials, credentials HashMap) {
	dictFile, err := os.Open(dictName)
	check(err)
	defer dictFile.Close()

	scanner := bufio.NewScanner(dictFile)
	scannerBuffer := make([]byte, 32*1024*1024)
	scanner.Buffer(scannerBuffer, 32*1024*1024)
	fmt.Println("[*] Cracking time")

	for scanner.Scan() {
		*processed++

		data := scanner.Text()
		if len(data) > 250 {
			continue
		}

		split := strings.Split(data, ":")
		mappingID := split[0]
		password := strings.Join(split[1:], "")

		if _, exist := credentials[mappingID]; exist {
			*found++

			hashes := credentials[mappingID]

			for _, hash := range hashes {
				credentials := Credentials{hash, password}
				credChan <- credentials
			}
		}
		if (*processed % 1000000) == 0 {
			fmt.Printf("[*] Processed %d | Found %d | Cracked %d\n", *processed, *found, *cracked)
		}

	}

	fmt.Print("[+] Reached end of source file\n")

}

func runCracker(credentials HashMap, dictNames []string, crackedName string) {
	fmt.Println("[*] Initialising cracker")
	processed := 0
	found := 0
	cracked := 0

	credChan := make(chan Credentials, 4096)
	writeChan := make(chan string, 4096)
	for i := 0; i < 30; i++ {
		wgCrack.Add(1)
		go microCracker(credChan, writeChan)
	}

	wgWrite.Add(1)
	go microWriter(writeChan, crackedName, &cracked)

	for _, dictName := range dictNames {
		processFile(dictName, &processed, &found, &cracked, credChan, credentials)
	}

	fmt.Print("[+] Reached end of source file list, waiting for goroutines to finish their work\n")
	close(credChan)
	wgCrack.Wait()
	close(writeChan)
	wgWrite.Wait()

	fmt.Printf("[+] Processed %d | Found %d | Cracked %d\n", processed, found, cracked)
}

func main() {
	credFile := flag.String("creds", "credentials.txt", "File containing credentials to check")
	crackedFile := flag.String("outfile", "cracked.txt", "File that will contain the list of cracked accounts")
	flag.Parse()

	dictFiles := flag.Args()

	if len(dictFiles) < 1 {
		fmt.Print("Please provide at least one input file at the end of command line\n")
		os.Exit(-1)
	}

	credentials := make(HashMap)

	// load credentials in memory
	count := loadCredentials(&credentials, *credFile)
	fmt.Printf("[+] Loaded %d credentials\n", count)

	// run through wordlist
	runCracker(credentials, dictFiles, *crackedFile)
}
