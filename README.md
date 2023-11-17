# Prerequisites

Needs .NET 8

# How to run

  ```bash
  cd src
  dotnet run -- "my-bitwarden-connection-string"
  ```

This tool outputs a CSV-able output with the following columns

- `UserId` the Id of the user which the row is about
- `MasterPasswordKeyRingId` the GUID id of the key used to encrypt the MasterPassword column, or null if a key could not be determined
  - This could be because it wasn't encrypted or a key id could not be found.
- `MasterPasswordKeyStatus` the status of the key used for encrypting the MasterPassword column.
- `KeyKeyRingId` the GUID id of the key used to encrypt the Key column, or null if a key could not be determined
  - This could be because it wasn't encrypted or a key id could not be found.
- `KeyKeyStatus` the status of the key used for encrypting the Key column.
