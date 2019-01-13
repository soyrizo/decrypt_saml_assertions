package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"log"
)

var (
	label = []byte("") //label is an empty string by default
	sha_1 = sha1.New()
	rng   = rand.Reader
)

//decrypt with sha1 algorithm
func DecryptOAEPsha1(priv *rsa.PrivateKey, encryptedMsg []byte) ([]byte, error) {

	decrypted_str, err := rsa.DecryptOAEP(sha_1, rng, priv, encryptedMsg, label)

	return decrypted_str, err
}

//grab private key
func ParsePKCS8Key(privKey []byte) (key interface{}, err error) {

	block, _ := pem.Decode(privKey)
	parse_result, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	keys := parse_result.(*rsa.PrivateKey)

	return keys, nil
}

//Decrypt SAML assertion
func DecryptSAML(keys, cipher_text []uint8) ([]uint8, error) {

	//create block cipher
	block, err := aes.NewCipher(keys)
	if len(cipher_text) < aes.BlockSize {
		log.Printf("Assertion cipher too short.")
		return nil, err
	}

	//init vector and cipher text taken based on block size
	iv := cipher_text[:aes.BlockSize]
	cipher_text = cipher_text[aes.BlockSize:]
	if len(cipher_text)%aes.BlockSize != 0 {
		log.Printf("cipher_text is not a multiple of the block size")
		return nil, err
	}

	//decrypt the assertion
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipher_text, cipher_text)

	return cipher_text, nil
}
