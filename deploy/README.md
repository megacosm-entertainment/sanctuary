# Deploying Sanctuary

The reference small deployment: the gateway and a realm as separate
containers, linked by the realm protocol over mTLS (docs/protocol.md).

```bash
scripts/compose.sh                # local identities (made on first use)
scripts/compose.sh -doppler stg   # settings and identities from Doppler
```

Then connect a MUD client to `localhost:9000` (telnet), `localhost:9010`
(telnet over TLS) or `https://localhost:9020/` (the browser test page).
The host ports are `PUBLISH_TELNET`, `PUBLISH_TELNETS` and `PUBLISH_WS`;
the Doppler `stg` config sets them to 19000, 19010 and 19020 so staging can
run beside a devcontainer that already forwards 9000-9020.

## What runs

| Service | Image | Ports | Talks to |
| --- | --- | --- | --- |
| `gateway` | `docker/runtime/Dockerfile` | 9000, 9010, 9020 published | realms, on 9030 inside the compose network only |
| `realm-stub` | the same image | none | the gateway's realm port |

The runtime image is `scratch` plus two static binaries: no shell, no
package manager, no compilers, an unprivileged user. Containers run
read-only with every capability dropped. The development image
(`docker/dev`) is never used to run a server.

## Settings

Each program reads its settings from, in increasing precedence:

1. built-in defaults,
2. its env file (`deploy/gateway.env`, `deploy/realm-stub.env`),
3. the environment,
4. command-line flags.

Every setting has one name in three forms: the flag `-realm-listen`, the
variable `SANCTUARY_REALM_LISTEN`, and the file line
`SANCTUARY_REALM_LISTEN=:9030`. `sanctuary-gateway -help` and
`sanctuary-realm -help` list them all. At startup each program logs every
setting that is not at its default, and where it came from.

Because the environment overrides the files, a secrets manager needs no
special support when running the binaries directly:

```bash
doppler run --project sanctuary-gateway --config dev -- sanctuary-gateway
scripts/run.sh -doppler dev      # both processes, in the devcontainer
```

Only `SANCTUARY_*` variables are read; anything else in the environment,
such as `DOPPLER_TOKEN`, is ignored and never logged.

Compose does not pass the host environment into containers, so each
service reads two env files: `deploy/<service>.env` (the same everywhere,
in git) and `.dev/env/<service>.env` (identities, pins and anything else
that differs per environment). `scripts/devkeys.sh` writes the second from
local identities; `scripts/compose.sh -doppler stg` serves it from Doppler
with `doppler run --mount`, as an ephemeral file that exists only while
compose runs.

### Doppler layout

| Project | Configs | Holds |
| --- | --- | --- |
| `sanctuary-gateway` | `dev`, `stg` | `SANCTUARY_REALM_LISTEN`, `REALM_CERT`, `REALM_KEY`, `REALM_PINS` (`stub=sha256/...`), `STUB_REALM`, `LOG_LEVEL`; `PUBLISH_*` in `stg` |
| `sanctuary-stub-realm` | `dev`, `stg` | `SANCTUARY_GATEWAY`, `GATEWAY_PINS`, `CERT`, `KEY`, `ID`, `NAME`, `LOG_LEVEL` |

Separate projects because the two programs share setting names (`NAME`,
`LOG_LEVEL`) with different values. `scripts/doppler-seed.sh dev|stg`
fills a config with working defaults: `dev` uses the identities in
`.dev/keys`, `stg` generates its own and keeps no local copy. Rerunning it
rotates the keys. It refuses production.

### Secrets

Private keys are *secret* settings. They can be given:

- as a path, in any source: `SANCTUARY_REALM_KEY_FILE=/run/secrets/...`, or
  the flag `-realm-key /path`, as a Docker or Kubernetes secret mount
  provides;
- as content, from the environment only: `SANCTUARY_REALM_KEY="-----BEGIN
  PRIVATE KEY-----..."`, as a secrets manager injects it. compose.yaml and
  `run.sh -doppler` use this.

Secret content is refused in a config file (files get committed) and has no
flag form (flags show in `ps`). It is never logged: the startup report
shows `[secret]`.

## Keys and trust

`scripts/devkeys.sh` makes a pinned identity for the gateway and for the
stub realm, in `.dev/keys` (git-ignored). Each side trusts the other's
public-key pin (`*.pin`). On the gateway each realm pin also names the
realm its key is for (`SANCTUARY_REALM_PINS=stub=sha256/...`): a key may
register only as its own realm (protocol.md §3). For a real deployment, either make identities on
each host with `-gen-identity PREFIX` and exchange the pins, or issue
certificates from a CA (cert-manager, for example) and set
`SANCTUARY_REALM_CA` on the gateway and `SANCTUARY_GATEWAY_CA` on realms
(a CA-issued realm may register only as its certificate's Common Name or
a DNS name); pins and a CA may be used together.


## Realms on other hosts

A realm needs only the gateway's address and pin. To run one elsewhere,
bind the gateway's `SANCTUARY_REALM_LISTEN` to a private address, keep that
port off the internet (firewall or network policy), and point the realm's
`SANCTUARY_GATEWAY` at it. File-based storage is single-host, so a realm
that moves between hosts will need a networked storage backend once
realms persist anything (design §04).
