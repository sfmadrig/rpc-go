package config

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Decrypt ciphertext using AES-GCM with the provided key
func Decrypt(cipherText string, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Read encrypted data from file and decrypt it
func ReadAndDecryptFile(filePath string, key []byte) (Configuration, error) {
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return Configuration{}, err
	}

	decryptedData, err := Decrypt(string(encryptedData), key)
	if err != nil {
		return Configuration{}, err
	}

	var configuration Configuration
	err = yaml.Unmarshal(decryptedData, &configuration)
	if err != nil {
		return Configuration{}, err
	}

	return configuration, nil
}
