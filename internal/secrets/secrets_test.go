package secrets

import (
	"errors"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	want := map[string]string{
		"DATABASE_PASSWORD": "a secret value",
		"EMPTY":             "",
	}

	contents, err := Save(nil, "password", "local", want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Load(contents, "password", "local")
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
}

func TestSavePreservesOtherEnvironments(t *testing.T) {
	contents, err := Save(nil, "password", "local", map[string]string{"PORT": "1234"})
	if err != nil {
		t.Fatal(err)
	}
	contents, err = Save(contents, "password", "production", map[string]string{"PORT": "443"})
	if err != nil {
		t.Fatal(err)
	}

	for environment, want := range map[string]string{"local": "1234", "production": "443"} {
		values, err := Load(contents, "password", environment)
		if err != nil {
			t.Fatal(err)
		}
		if got := values["PORT"]; got != want {
			t.Errorf("%s PORT = %q, want %q", environment, got, want)
		}
	}
}

func TestLoadRejectsWrongPassword(t *testing.T) {
	contents, err := Save(nil, "password", "local", map[string]string{"KEY": "value"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(contents, "wrong password", "local"); err == nil {
		t.Fatal("Load did not return an error")
	}
}

func TestLoadRejectsUnknownEnvironment(t *testing.T) {
	contents, err := Save(nil, "password", "local", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(contents, "password", "production"); !errors.Is(err, ErrEnvironmentNotFound) {
		t.Fatalf("got %v, want ErrEnvironmentNotFound", err)
	}
}

func TestEnvironment(t *testing.T) {
	t.Setenv("ENV", "production")
	if got := Environment(); got != "production" {
		t.Errorf("got %q, want production", got)
	}
	t.Setenv("ENV", "")
	if got := Environment(); got != "local" {
		t.Errorf("got %q, want local", got)
	}
}

func TestFilePath(t *testing.T) {
	t.Setenv("TAJNIKI_FILE", "custom.json")
	if got := FilePath(); got != "custom.json" {
		t.Errorf("got %q, want custom.json", got)
	}
	t.Setenv("TAJNIKI_FILE", "")
	if got := FilePath(); got != "secrets.json" {
		t.Errorf("got %q, want secrets.json", got)
	}
}
