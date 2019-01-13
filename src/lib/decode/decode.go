package decode

import (
	"encoding/base64"
	"encoding/hex"
)

//decode base64 to []byte(string)
func Base64ToString(s string) ([]byte, error) {

	data, err := base64.StdEncoding.DecodeString(s)

	return data, err
}

//encode []byte(string) to string(base64)
func StringToBase64(b []byte) string {

	data := base64.StdEncoding.EncodeToString(b)

	return data
}

//encode []byte(string) to hexidecimal string
func ByteToHexString(b []byte) string {

	data := hex.EncodeToString(b)

	return data
}

//decode string to []byte(hex)
func HexStringToByte(s string) ([]byte, error) {

	data, err := hex.DecodeString(s)

	return data, err
}
