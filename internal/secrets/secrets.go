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
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

const (
	defaultFile = "secrets/local.json"
	saltSize    = 16
	keySize     = 32
)

func LoadFromEnvironment() (map[string]string, error) {
	return Load(FilePath(), os.Getenv("TAJNIKI_SECRET"))
}

func FilePath() string {
	if path := os.Getenv("TAJNIKI_FILE"); path != "" {
		return path
	}
	return defaultFile
}

func Load(path, password string) (map[string]string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}

	var encrypted map[string]string
	if err := json.Unmarshal(contents, &encrypted); err != nil {
		return nil, fmt.Errorf("read secrets JSON: %w", err)
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

func Save(path, password string, values map[string]string) error {
	encrypted := make(map[string]string, len(values))
	for key, value := range values {
		ciphertext, err := encrypt(value, password)
		if err != nil {
			return fmt.Errorf("encrypt %q: %w", key, err)
		}
		encrypted[key] = ciphertext
	}

	contents, err := json.MarshalIndent(encrypted, "", "  ")
	if err != nil {
		return fmt.Errorf("create secrets JSON: %w", err)
	}
	contents = append(contents, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}

	temporary, err := os.CreateTemp(filepath.Dir(path), ".tajniki-*")
	if err != nil {
		return fmt.Errorf("create temporary secrets file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary secrets file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary secrets file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace secrets file: %w", err)
	}
	return nil
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
