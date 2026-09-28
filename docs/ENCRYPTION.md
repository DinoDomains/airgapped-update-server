# Encryption at rest

The Update Server stores operator records, enrollment-token digests, session
digests, SSH provisioning credentials, CA private keys, and signing keys.
This document covers how those are protected on disk.

## The short version

The application does **not** encrypt the store. Encryption at rest is a
property of the filesystem underneath it, and it is handled by the host, not
by the server binary. What the server does is:

1. keep secret files owner-only (`0600`) and secret directories owner-only
   (`0700`) — see [fsguard](../crates/server/src/fsguard.rs);
2. keep private key material **outside** the web-facing store directory;
3. verify at startup that the store and key directories are on an encrypted
   volume, and say so loudly when they are not.

Point 3 is a check, not a control. If you need the guarantee, set it up
below.

## Why the server does not encrypt files itself

A per-file encryption scheme would need a master key. Where would that live?
On the same host, in the same threat domain as the thing it protects. If an
attacker can read your store directory, they can read the decryption key
sitting next to it, and the encryption buys nothing against exactly the
scenario that motivates it.

Whole-volume encryption (LUKS/dm-crypt) puts the key in the kernel keyring,
released during boot by the initramfs. Stealing a file off a running, unlocked
system is far harder than stealing a file from a backup or a decommissioned
disk — and that is the threat the store actually has. So: encrypt the volume,
not the files.

## Setting up LUKS

For a dedicated data partition mounted at `/var/lib/airgap-server`:

```sh
# One-time: create the encrypted container on a new partition.
cryptsetup luksFormat --type luks2 /dev/sdX1
cryptsetup open /dev/sdX1 airgap-data

# Format once, then close.
mkfs.ext4 /dev/mapper/airgap-data
cryptsetup close airgap-data
```

Add to `/etc/crypttab` so it unlocks at boot:

```
airgap-data  UUID=<uuid-from-luksFormat>  none  luks,discard
```

Add to `/etc/fstab`:

```
/dev/mapper/airgap-data  /var/lib/airgap-server  ext4  defaults,nodev,nosuid  0 2
```

Then point the server at the two directories:

```sh
AIRGAP_STORE_DIR=/var/lib/airgap-server/data \
AIRGAP_KEY_DIR=/var/lib/airgap-server/keys \
airgap-server
```

`AIRGAP_KEY_DIR` is a separate directory so the key material is not reachable
by anything that walks the store tree. The two may live on the same encrypted
volume; separating them is about *path* isolation, not a second disk.

### Boot-order warning

If the encrypted volume is not mounted, the server will start against an
empty store and **mint a brand-new CA**. Every already-enrolled agent will
then reject the server as `BadSignature` and refuse to talk to it. This is a
long-standing sharp edge, not something this change introduced, but it becomes
much more likely once a volume has to be unlocked.

Guard it. Either:

- add `x-systemd.requires-mounts-for=/var/lib/airgap-server` to the server's
  unit so systemd refuses to start it if the mount is absent; or
- make the mount a hard dependency of the service and fail closed.

Check it after a reboot, before you trust the host:

```sh
systemctl is-active airgap-server
findmnt /var/lib/airgap-server
```

## Making the check mandatory

By default an unencrypted store produces a startup **warning** and the server
runs anyway. That default is deliberate: ZFS native dataset encryption, and
some hardware-encrypted block devices, are invisible to the mount-table check,
and a hard failure would lock an operator out of a server that is in fact
correctly protected.

Once you have verified encryption out-of-band, make it a startup requirement:

```sh
AIRGAP_REQUIRE_ENCRYPTION=1
```

Now the server refuses to start if it cannot confirm an encrypted volume for
both the store and key directories. Use this in production once the volume is
set up; leave it off only while you are still getting the layout in place.

## What the check can and cannot see

It parses `/proc/mounts` and looks for dm-crypt/LUKS markers: a `crypt`
filesystem type, a `/dev/mapper/...crypt...` device, or a device/option
string containing `luks` or `crypt`. The most specific matching mount point
wins, so a store on a dedicated mount is judged on that mount, not on `/`.

It cannot see:

- ZFS native dataset encryption, or any filesystem-level encryption that does
  not label its mount as dm-crypt;
- full-disk encryption presented as an ordinary block device with no `crypt`
  marker in the device name;
- a `tmpfs` or bind mount layered over the real data.

Treat the warning as "no evidence found", not as "proven unencrypted".

## Backups

`airgap-server backup <store-dir> <out.tar.gz>` writes a gzipped tar of the
state directory. That archive is **not** encrypted by the server — it
contains the same sensitive material as the store.

Keep backups on encrypted media, and treat the archive as a secret:

- do not leave `.tar.gz` backups in a home directory or a synced folder;
- encrypt the archive before it leaves the host, e.g.

  ```sh
  gpg --symmetric --cipher-algo AES256 openupdater-backup.tar.gz
  ```

- verify the restore path on a scratch machine, not only the backup. A backup
  you have never restored is a guess.

## Related

- [`keys/KEY-MANAGEMENT.md`](../keys/KEY-MANAGEMENT.md) — rotation and
  compromise response for signing keys.
- [`crates/server/src/encryption.rs`](../crates/server/src/encryption.rs) —
  the detection code.
