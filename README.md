# kc

A tiny macOS CLI for storing passwords and other secrets in a keychain — like
`security add-generic-password`, but without the length limits and without
leaking the secret into your shell history or `ps` output.

## Why

`security add-generic-password` has two bad options for the secret itself:

- `-w <password>` puts it on the command line (visible in `ps`, shell history).
- `-w` with no value prompts interactively — but the prompt silently truncates
  secrets at **128 characters**. The only remaining alternative, `-X <hex>`,
  still puts the secret on argv, which again leaks.

`kc` reads the secret from stdin or from an unlimited-length no-echo prompt, and
stores it by calling the Security framework directly. Long secrets (tokens, PEM
keys, etc.) round-trip intact.

## Install

```
brew install wheelerlaw/tap/kc
```

Or build from source (only Xcode Command Line Tools needed):

```
make build
```

## Usage

```
# Pipe a secret in (strips one trailing newline, like `security -w` piped input)
pbpaste | kc set -s my-service -a my-account

# Interactive prompt (unlimited length, echo disabled)
kc set -s my-service -a my-account

# -u is an alias for -a
kc set -s my-service -u my-account

# -a is optional on set: the account defaults to $USER
kc set -s my-service

# Read it back
kc get -s my-service -a my-account

# Update in place
printf 'new-value' | kc set -s my-service -a my-account -U

# Delete
kc delete -s my-service -a my-account

# Target a specific keychain file
kc set -s svc -a acct -k /tmp/scratch.keychain-db
```

`set` requires `-s <service>`; `get`/`delete` need at least one of `-s`/`-a`
and match on whichever you give. A handy pattern is one service holding many
named secrets:

```
kc set -s env -a NPM_TOKEN     # paste the token
kc get -s env -a NPM_TOKEN     # -> token
kc delete -s env               # removes one matching item at a time
```

Options for `set`: `-l <label>` (defaults to service), `-j <comment>`,
`-D <kind>`, `-U` (update existing — the item's existing access list is kept,
so `-T`/`-A` have no effect on an update), `-T <app_path>` (trust an extra
application, repeatable), `-A` (any application may read without warning, like
`security -A`).

Items are stored in the file-based keychain with an ACL trusting `kc` itself and
`/usr/bin/security`, so `security find-generic-password -w` can read them too.

## Note on upgrades

After `brew upgrade`, the first `kc get` may trigger a one-time "kc wants to
access data" prompt — the binary is ad-hoc signed, so its code identity changes
each build. `security find-generic-password -w` keeps working silently
regardless, since `/usr/bin/security` is a trusted application on the item.

## License

MIT — see [LICENSE](LICENSE).
