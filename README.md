# tajniki

`tajniki` stores encrypted secrets in a JSON file.

## Library

Set `TAJNIKI_SECRET` to the password. `ENV` selects the secrets group and
defaults to `local`.

Pass the secret file contents to `Load`, typically with `embed`:

```go
import (
    _ "embed"

    "github.com/kiasaki/tajniki"
)

//go:embed secrets.json
var secretContents []byte

tajniki.Load(secretContents)
password := os.Getenv("DATABASE_PASSWORD")
```

## Command line

Install the command with this command:

```sh
go install github.com/kiasaki/tajniki/cmd/tajniki@latest
```

Set `TAJNIKI_SECRET` before you use the command. The command reads and writes
`secrets.json` by default; set `TAJNIKI_FILE` to choose another path. `ENV`
selects the group to manage and defaults to `local`.

The root JSON object contains one object per group. Secret values remain
encrypted:

```json
{
  "local": { "PORT": "<encrypted value>" },
  "production": {}
}
```

```sh
tajniki set DATABASE_PASSWORD secret
tajniki get DATABASE_PASSWORD
tajniki list
tajniki edit
```

`tajniki edit` uses `EDITOR`. It opens decrypted JSON for the selected group
and encrypts the values when the editor exits.
