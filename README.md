# tajniki

`tajniki` stores encrypted secrets in a JSON file.

## Library

Set `TAJNIKI_SECRET` to the password. Set `TAJNIKI_FILE` to select a file.
The default file is `secrets/local.json`.

```go
values, err := tajniki.Load()
if err != nil {
    // Handle the error.
}
password := values["DATABASE_PASSWORD"]
```

## Command line

Install the command with this command:

```sh
go install github.com/kiasaki/tajniki/cmd/tajniki@latest
```

Set `TAJNIKI_SECRET` before you use the command.

```sh
tajniki set DATABASE_PASSWORD secret
tajniki get DATABASE_PASSWORD
tajniki list
tajniki edit
```

`tajniki edit` uses `EDITOR`. It opens decrypted JSON. It encrypts the values when the editor exits.
