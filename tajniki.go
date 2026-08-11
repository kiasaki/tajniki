// Package tajniki loads encrypted secrets from a JSON file.
package tajniki

import (
	"log"
	"os"

	"github.com/kiasaki/tajniki/internal/secrets"
)

// Load reads and decrypts the configured secrets file.
//
// TAJNIKI_FILE sets the file path. The default is secrets/local.json.
// TAJNIKI_SECRET sets the password.
func Read() (map[string]string, error) {
	return secrets.LoadFromEnvironment()
}

func Load() {
	secrets, err := secrets.LoadFromEnvironment()
	if err != nil {
		log.Printf("tajniki: error loading secrets: %v", err)
		os.Exit(1)
		return
	}
	for k, v := range secrets {
		os.Setenv(k, v)
	}
}
