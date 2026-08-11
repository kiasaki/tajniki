// Package tajniki loads encrypted secrets from a JSON file.
package tajniki

import "github.com/kiasaki/tajniki/internal/secrets"

// Load reads and decrypts the configured secrets file.
//
// TAJNIKI_FILE sets the file path. The default is secrets/local.json.
// TAJNIKI_SECRET sets the password.
func Load() (map[string]string, error) {
	return secrets.LoadFromEnvironment()
}
