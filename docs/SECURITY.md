# Credential storage and hardening

How the Update Server stores authentication material, and what changed.

## What is stored, and in what form

| credential | storage | form |
|---|---|---|
| operator password | `data/operators.json` | Argon2id hash (unchanged) |
| dashboard session token | `data/sessions.json` | SHA-256 digest |
| enrollment token | `data/tokens.json` | SHA-256 digest |
| SSH provisioning credential | `data/credentials.json` | plaintext, `0600`; redacted from API responses |
| CA / server / signing private key | key dir | PEM, `0600` |

The raw value of a session or enrollment token is never written to disk. It
exists only in the response to the login or enrollment request that created
it, and in the agent's own configuration.

### Why SHA-256 and not Argon2 for tokens

Argon2 is deliberately slow, which is the right trade for a human-chosen
password. Session and enrollment tokens are 256 bits from the OS CSPRNG:
there is no dictionary to attack, and the only thing that protects them is the
entropy. Stretching buys nothing and costs latency on every authenticated
request. Operator passwords keep Argon2id.

Digests are compared in constant time, and token lookup scans every stored
entry rather than short-circuiting on the first match, so neither the
response time nor the comparison count reveals which entry matched.

## Sessions

Sessions are written to `data/sessions.json` and survive a server restart.
Expired sessions are dropped on load and on access.

- TTL is 24 hours.
- `logout` removes the session immediately, and the removal is persisted.
- Deleting an operator revokes all of their sessions.
- Creating an operator requires a password of at least 12 characters.

Sessions are bearer credentials: whoever holds the token is the operator.
Treat the `sessions.json` file as sensitive, and log out rather than relying
on the TTL to end a session on a shared console.

## Enrollment tokens

Enrollment tokens are stored hashed and verified by hashing the presented
value. Existing deployments are **migrated automatically**: on startup, any
`tokens.json` entry that is not already a digest is hashed in place and
rewritten. Agents holding the old plaintext token keep working — verification
accepts both forms during the migration window.

You do not need to re-enroll agents after upgrading.

### Rotating the enrollment token

`AIRGAP_ENROLL_TOKEN` is authoritative. Whatever value is set there is
registered as an accepted token on startup, so rotating is just a matter of
changing the environment and restarting:

```sh
AIRGAP_ENROLL_TOKEN='<new token>' airgap-server
```

The previous token remains valid — it is still in the store as a digest.
Revoking it is a deliberate manual step (see below), so that rotating the
token does not immediately break every agent mid-deployment.

This authority is also what makes the system usable now that tokens are
stored hashed: there is no longer a plaintext entry in `tokens.json` to edit
by hand, and no endpoint to add one. The environment variable is the
supported way in.

To revoke a token completely, remove its `sha256:` entry from
`tokens.json` while the server is stopped, then restart. The digest is
`sha256:` followed by the hex SHA-256 of the raw token.

### Breaking change: provisioning now needs `AIRGAP_ENROLL_TOKEN`

Provisioning an agent over SSH writes the enrollment token into the agent's
start script. That requires the **raw** token, which cannot be recovered from
a stored digest — by design, so that read access to the store does not yield a
usable enrollment credential.

The server therefore reads the raw token from its own environment, and
verifies it against the stored digests before using it:

```sh
AIRGAP_ENROLL_TOKEN='<the enrollment token>' airgap-server
```

If the variable is unset, or set to a token the server does not accept,
provisioning fails with an explicit error. That check is deliberate: without
it, a mismatched token would install agents that could never enroll, and the
only symptom would be a fleet of agents refusing to come up.

The default bootstrap token remains `airgap-bootstrap` for a fresh
installation. **Change it before the server is reachable by anything you do
not control**, and set `AIRGAP_ENROLL_TOKEN` to the new value.

## File permissions

On startup the server tightens the store directory to `0700` and every
private key file to `0600`. Permissions are only ever tightened, never
loosened. Private state (`operators.json`, `sessions.json`, `tokens.json`,
`credentials.json`) is written through a temp file and renamed into place, so
a crash mid-write cannot leave a truncated or world-readable file behind.

The server logs a warning for anything it cannot correct automatically, such
as key material still sitting in the store directory.

## Key material location

Private keys live outside the store directory. See
[`keys/KEY-MANAGEMENT.md`](../keys/KEY-MANAGEMENT.md) for the layout, the
`AIRGAP_KEY_DIR` override, and the first-startup migration of legacy keys.

## Encryption at rest

Not performed by the application. The server verifies the store and key
directories are on an encrypted volume and warns when they are not; set
`AIRGAP_REQUIRE_ENCRYPTION=1` to make that a startup requirement. Full setup
in [`docs/ENCRYPTION.md`](ENCRYPTION.md).

## Environment variables

| variable | purpose |
|---|---|
| `AIRGAP_ENROLL_TOKEN` | raw enrollment token; registered on startup and required for SSH provisioning |
| `AIRGAP_ADMIN_PASSWORD` | initial password for the bootstrap `admin` operator |
| `AIRGAP_STORE_DIR` | state directory (default `data`) |
| `AIRGAP_KEY_DIR` | private key directory (default `<store>-keys`) |
| `AIRGAP_REQUIRE_ENCRYPTION` | refuse to start on an unencrypted volume |

## Threat model notes

These controls defend against: an attacker reading files off the disk or a
backup; a web path traversal confined to the store directory; a low-privilege
local account on the host; and accidental secret leakage through a commit or a
log line.

They do **not** defend against: an attacker with root on the host while the
volume is unlocked; a compromised server process (which holds the CA key in
memory while running); or an operator who leaks their own token. For those,
the answer is the HSM/TPM migration in `keys/KEY-MANAGEMENT.md`.
