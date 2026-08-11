// Package tajniki loads encrypted secrets from supplied JSON contents.
package tajniki

import (
	"log"
	"os"

	"github.com/kiasaki/tajniki/internal/secrets"
)

// Load decrypts the selected environment from contents.
//
// TAJNIKI_SECRET sets the password. ENV selects the environment and defaults
// to local.
func Load(contents []byte) {
	values, err := secrets.Load(contents, os.Getenv("TAJNIKI_SECRET"), secrets.Environment())
	if err != nil {
		log.Println("tajniki: error loading secrets:", err)
		os.Exit(1)
		return
	}
	for k, v := range values {
		os.Setenv(k, v)
	}
}
