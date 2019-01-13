/*
Tool decrypts SAML assertions. We currently use the sha1 algorithm.
If that changes, we can update to whichever algorithm is needed.
Supports standards of aes-128, aes-192, and aes-256.
*/

package main

import (
	"./lib/crypto"
	"./lib/decode"
	"./lib/xmlparse"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"
)

var (
	file              string
	key_location = "PRIVATE_KEY_HERE"
)

//decode & decrypt SAML assertions
func main() {

	//pass in assertion.xml
	assertion := checkArgs()

	//parse xml file for encrypted key and assertion
	_, encrypted_key, encrypted_assertion, err := parseXML(assertion)

	//get private key
	priv_key := getPrivKey(key_location)

	//base64 encrypted key to hex
	encrypted_key_base64, err := decode.Base64ToString(string(encrypted_key))
	check("Error decoding encrypted key %s\n", err)

	//decrypt key
	decrypted_key, err := crypto.DecryptOAEPsha1(priv_key, encrypted_key_base64)
	check("Encrypted key failed to decrypt: %s\n", err)
	decrypted_hex_key := decode.ByteToHexString([]byte(decrypted_key))

	//decode base64 assertion
	base64_assertion, err := decode.Base64ToString(encrypted_assertion)
	check("Invalid Base64 => %s\n", err)
	enc_assertion_hex := decode.ByteToHexString(base64_assertion)

	//decode key
	enc_key, err := decode.HexStringToByte(decrypted_hex_key)
	check("Error decoding decrypted key %s\n", err)

	//hex decode assertion
	cipher_text, err := decode.HexStringToByte(enc_assertion_hex)
	check("Error decoding decrypted key %s\n", err)

	//decrypt assertion
	decrypted_saml_assertion, err := crypto.DecryptSAML(enc_key, cipher_text)
	check("Error decrypting SAML assertion %s\n", err)

	//write decrypted output to file
	saml_contents := []byte(decrypted_saml_assertion)

	//TODO: parse `xml:"Issuer"` for assigning unique file name

	//for now, we'll use a Unix timestamp
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	err = ioutil.WriteFile(timestamp+"_decrypted_assertion.xml", saml_contents, 0644)
	check("Error writing decrypted assertion to file %s\n", err)
}

func getPrivKey(file string) *rsa.PrivateKey {

	//open priv key file
	parsed_priv_key, err := openReadClose(file)

	//parse key out
	privKey, err := crypto.ParsePKCS8Key([]byte(parsed_priv_key))
	check("Private key failed to parse %s\n", err)

	key := privKey.(*rsa.PrivateKey) //TODO: provide methods for interface so rsa pkg isn't needed

	return key
}

func parseXML(file string) (string, string, string, error) {

	//open xml file
	xmlFile, err := os.Open(file)
	check("Failed opening => %s\n", err)
	defer xmlFile.Close()

	//read xml file
	b, err := ioutil.ReadAll(xmlFile)
	check("Failed reading => %s\n", err)

	//parse issuer, assertion and key
	issuer, encrypted_key, encrypted_assertion, err := xmlparse.Parse(b)
	check("Invalid XML => %s\n", err)

	return issuer, encrypted_key, encrypted_assertion, err
}

func checkArgs() string {

	if (len(os.Args) < 2) || (len(os.Args) > 2) {
		fmt.Println("No assertion.xml file passed in. Exiting.")
		os.Exit(2)
	}
	file = os.Args[1]

	return file
}

//handle errors
func check(message string, err error) {

	if err != nil {
		log.Printf(message, err)
		os.Exit(1)
	}
}

func openReadClose(s string) ([]byte, error) {

	//open contents file
	file, err := os.Open(s)
	check("Failed reading file %s", err)
	defer file.Close()

	//read contents as alias []uint8 for bytes and return
	b, err := ioutil.ReadAll(file)

	return b, err
}
