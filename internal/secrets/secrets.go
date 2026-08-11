// Package secrets manages the encrypted secrets file format.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"
)

const (
	defaultFile        = "secrets.json"
	defaultEnvironment = "local"
	saltSize           = 16
	keySize            = 32
)

var ErrEnvironmentNotFound = errors.New("secrets environment does not exist")

func Environment() string {
	if environment := os.Getenv("ENV"); environment != "" {
		return environment
	}
	return defaultEnvironment
}

func FilePath() string {
	if path := os.Getenv("TAJNIKI_FILE"); path != "" {
		return path
	}
	return defaultFile
}

func Load(contents []byte, password, environment string) (map[string]string, error) {
	var encryptedGroups map[string]map[string]string
	if err := json.Unmarshal(contents, &encryptedGroups); err != nil {
		return nil, fmt.Errorf("read secrets JSON: %w", err)
	}

	encrypted, ok := encryptedGroups[environment]
	if !ok || encrypted == nil {
		return nil, fmt.Errorf("%w: %q", ErrEnvironmentNotFound, environment)
	}

	values := make(map[string]string, len(encrypted))
	for key, value := range encrypted {
		plain, err := decrypt(value, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt %q: %w", key, err)
		}
		values[key] = plain
	}
	return values, nil
}

func Save(contents []byte, password, environment string, values map[string]string) ([]byte, error) {
	encryptedGroups := make(map[string]map[string]string)
	if len(contents) != 0 {
		if err := json.Unmarshal(contents, &encryptedGroups); err != nil {
			return nil, fmt.Errorf("read secrets JSON: %w", err)
		}
		if encryptedGroups == nil {
			return nil, errors.New("secrets JSON must be an object")
		}
	}

	encrypted := make(map[string]string, len(values))
	for key, value := range values {
		ciphertext, err := encrypt(value, password)
		if err != nil {
			return nil, fmt.Errorf("encrypt %q: %w", key, err)
		}
		encrypted[key] = ciphertext
	}
	encryptedGroups[environment] = encrypted

	updated, err := json.MarshalIndent(encryptedGroups, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("create secrets JSON: %w", err)
	}
	return append(updated, '\n'), nil
}

func encrypt(value, password string) (string, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	payload := append(salt, nonce...)
	payload = gcm.Seal(payload, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func decrypt(encoded, password string) (string, error) {
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("value is not valid encrypted data")
	}
	if len(payload) < saltSize {
		return "", errors.New("value is not valid encrypted data")
	}
	key, err := deriveKey(password, payload[:saltSize])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < saltSize+gcm.NonceSize()+gcm.Overhead() {
		return "", errors.New("value is not valid encrypted data")
	}
	plain, err := gcm.Open(nil, payload[saltSize:saltSize+gcm.NonceSize()], payload[saltSize+gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New("password is not correct or encrypted data is damaged")
	}
	return string(plain), nil
}

func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 32768, 8, 1, keySize)
}
