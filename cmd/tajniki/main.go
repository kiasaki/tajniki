// Command tajniki manages encrypted secrets.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/kiasaki/tajniki/internal/secrets"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tajniki:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("use: tajniki <list|get|set|edit>")
	}

	path := secrets.FilePath()
	password := os.Getenv("TAJNIKI_SECRET")

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("use: tajniki list")
		}
		values, err := secrets.Load(path, password)
		if err != nil {
			return err
		}
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Printf("%s=%s\n", key, values[key])
		}
		return nil

	case "get":
		if len(args) != 2 {
			return errors.New("use: tajniki get KEY")
		}
		values, err := secrets.Load(path, password)
		if err != nil {
			return err
		}
		value, ok := values[args[1]]
		if !ok {
			return fmt.Errorf("key %q does not exist", args[1])
		}
		fmt.Println(value)
		return nil

	case "set":
		if len(args) != 3 {
			return errors.New("use: tajniki set KEY VALUE")
		}
		values, err := loadOrEmpty(path, password)
		if err != nil {
			return err
		}
		values[args[1]] = args[2]
		return secrets.Save(path, password, values)

	case "edit":
		if len(args) != 1 {
			return errors.New("use: tajniki edit")
		}
		return edit(path, password)

	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadOrEmpty(path, password string) (map[string]string, error) {
	values, err := secrets.Load(path, password)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil
	}
	return values, err
}

func edit(path, password string) error {
	values, err := loadOrEmpty(path, password)
	if err != nil {
		return err
	}

	contents, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return fmt.Errorf("create JSON: %w", err)
	}
	contents = append(contents, '\n')

	temporary, err := os.CreateTemp("", "tajniki-*.json")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return fmt.Errorf("set temporary file permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		return errors.New("set EDITOR before you use edit")
	}
	command := exec.Command("sh", "-c", editor+" \"$1\"", "sh", temporaryName)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("run editor: %w", err)
	}

	edited, err := os.ReadFile(temporaryName)
	if err != nil {
		return fmt.Errorf("read edited file: %w", err)
	}
	if err := json.Unmarshal(edited, &values); err != nil {
		return fmt.Errorf("read edited JSON: %w", err)
	}
	if values == nil {
		return errors.New("edited JSON must be an object")
	}
	return secrets.Save(filepath.Clean(path), password, values)
}
