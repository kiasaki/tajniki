package tajniki

import (
	"testing"

	"github.com/kiasaki/tajniki/internal/secrets"
)

func TestLoadReadsSelectedEnvironmentFromContents(t *testing.T) {
	t.Setenv("TAJNIKI_SECRET", "password")
	t.Setenv("ENV", "production")

	contents, err := secrets.Save(nil, "password", "local", map[string]string{"PORT": "1234"})
	if err != nil {
		t.Fatal(err)
	}
	contents, err = secrets.Save(contents, "password", "production", map[string]string{"PORT": "443"})
	if err != nil {
		t.Fatal(err)
	}

	values, err := Load(contents)
	if err != nil {
		t.Fatal(err)
	}
	if got := values["PORT"]; got != "443" {
		t.Errorf("got %q, want 443", got)
	}
}
