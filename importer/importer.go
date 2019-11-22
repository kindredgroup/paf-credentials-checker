package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

const charsToKeep = 6

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	inputFile := flag.String("input", "combo.txt", "Source file containing combo list to anonymise")
	outputFile := flag.String("output", "anonymised_combo.txt", "Output file that will be written with anonymised data")

	flag.Parse()

	fmt.Println("[*] Opening input file")
	fi, err := os.Open(*inputFile)
	check(err)
	defer fi.Close()

	fmt.Println("[*] Opening output file")
	fo, err := os.Create(*outputFile)
	check(err)
	defer fo.Close()

	processed := 0
	bytesWritten := 0
	scanner := bufio.NewScanner(fi)
	scannerBuffer := make([]byte, 32*1024*1024)
	scanner.Buffer(scannerBuffer, 32*1024*1024)
	fmt.Println("[*] Processing input file")

	for scanner.Scan() {

		data := scanner.Text()
		if len(data) > 250 {
			continue
		}

		split := strings.Split(data, ":")
		id := split[0]
		password := strings.Join(split[1:], "")
		var idBuffer bytes.Buffer

		idBuffer.WriteString(id)
		hash := md5.Sum(idBuffer.Bytes())
		truncatedHash := hex.EncodeToString(hash[:])

		var writeBuffer bytes.Buffer
		writeBuffer.WriteString(truncatedHash[:charsToKeep])
		writeBuffer.WriteString(":")
		writeBuffer.WriteString(password)
		writeBuffer.WriteString("\n")

		nBytes, err := fo.Write(writeBuffer.Bytes())
		check(err)

		processed++
		bytesWritten += nBytes

		if (processed % 1000000) == 0 {
			fmt.Printf("[*] Processed %d rows, written %d bytes\n", processed, bytesWritten)
		}

	}

	fo.Sync()
	fmt.Printf("[+] Processed %d rows, written %d bytes\n", processed, bytesWritten)

}
