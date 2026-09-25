# Keyring fixtures

Written by gnome-keyring 48.0 (Debian trixie) itself, not by hand, for
`tests/desktop/keyring-format-test.sh`, which holds the desktop gate's keyring
classifier (`surfaces-check.sh` group 8k) to the formats the daemon really
writes.

- `login.keyring.b64`: the binary, encrypted format. The login keyring the
  daemon created on `gnome-keyring-daemon --unlock` with the password
  `fixture-password`; it holds no items. Base64, because it is binary.
- `unprotected.keyring`: the plaintext `[keyring]` format. A collection
  created with an empty master password through the daemon's
  `CreateWithMasterPassword` D-Bus method, which is what an application
  asking for a keyring gets when the person leaves the password empty: the
  file every stored secret would then be written into in the clear.
