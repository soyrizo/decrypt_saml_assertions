package xmlparse

import (
	"encoding/xml"
	"strings"
)

var (
	blob Blob
)

//Encrypted Assertion
type EncryptedAssertion struct {
	EncryptedData EncryptedData
}

type EncryptedData struct {
	//EncryptionMethod   EncryptionMethod
	KeyInfo            KeyInfo
	EncryptedAssertion string `xml:"CipherData>CipherValue"`
}

//Encrypted Key
type KeyInfo struct {
	KeyInfo      string `xml:"KeyInfo>CipherData>CipherValue"`
	EncryptedKey EncryptedKey
}

type EncryptedKey struct {
	EncryptedKey     string
	CipherValue      string `xml:"CipherData>CipherValue"`
	EncryptionMethod ClientEncryptionMethod
}

type ClientEncryptionMethod struct {
	EncryptionMethod string
	DigestMethod     DigestMethod
}

//Client's encryption algorithm (SHA1 vs SHA256)
type DigestMethod struct {
	DigestMethod string `xml:"Algorithm,attr"`
}

//XML Blob
type Blob struct {
	Issuer             string `xml:"Issuer"`
	EncryptedAssertion EncryptedAssertion
}

//Parse all the things
func Parse(b []byte) (string, string, string, error) {

	err := xml.Unmarshal(b, &blob)
	issuer := blob.Issuer
	encrypted_key := blob.EncryptedAssertion.EncryptedData.KeyInfo.EncryptedKey.CipherValue
	encrypted_assertion := blob.EncryptedAssertion.EncryptedData.EncryptedAssertion

	return RemoveWhitespace(issuer), RemoveWhitespace(encrypted_key), RemoveWhitespace(encrypted_assertion), err
}

//Removes crud if we get passed non-xml formats...like .rtf
func RemoveWhitespace(s string) string {

	trimmed := strings.TrimSpace(s)
	no_spaces := strings.Replace((trimmed), " ", "", -1)

	return no_spaces
}
