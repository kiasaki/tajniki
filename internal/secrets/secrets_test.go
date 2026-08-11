package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets", "local.json")
	want := map[string]string{
		"DATABASE_PASSWORD": "a secret value",
		"EMPTY":             "",
	}

	if err := Save(path, "password", want); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path, "password")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d values, want %d", len(got), len(want))
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("got %q for %q, want %q", got[key], key, value)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("got file mode %o, want 600", info.Mode().Perm())
	}
}

func TestLoadRejectsWrongPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.json")
	if err := Save(path, "password", map[string]string{"KEY": "value"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "wrong password"); err == nil {
		t.Fatal("Load did not return an error")
	}
}

func TestFilePath(t *testing.T) {
	t.Setenv("TAJNIKI_FILE", "custom.json")
	if got := FilePath(); got != "custom.json" {
		t.Errorf("got %q, want custom.json", got)
	}
	t.Setenv("TAJNIKI_FILE", "")
	if got := FilePath(); got != "secrets/local.json" {
		t.Errorf("got %q, want secrets/local.json", got)
	}
}
