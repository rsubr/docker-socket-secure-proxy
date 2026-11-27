# docker-socket-secure-proxy

A read-only proxy for the Docker Engine API socket that **redacts environment
variables and secrets from responses**. Standard library only (Go 1.27.4,
`encoding/json/jsontext`), a single static binary.

Compared to [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
(which filters by endpoint but returns container env vars, swarm tokens, etc. verbatim),
this proxy also rewrites the JSON that it lets through. It is a generic reverse proxy over
the unix socket, not an emulation: the Docker CLI, Traefik and other clients see the real
API, including the `/v1.xx/` prefix and headers such as `Api-Version`.

## Usage

```sh
make build                      # bin/docker-socket-secure-proxy (static, stripped)
LISTEN_ADDR=127.0.0.1:2375 ./bin/docker-socket-secure-proxy
docker -H tcp://127.0.0.1:2375 ps
```

Flags: `-listen`, `-socket`, `-healthcheck` (HEAD `/_ping` on the local listener, exit 0/1;
for images without curl, needs `PING` enabled).

Go version: built and tested with Go 1.27.4. `encoding/json/v2`/`jsontext` work in this
toolchain without `GOEXPERIMENT`; on older toolchains use `GOEXPERIMENT=jsonv2 make build`.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:2375` | listen address |
| `DOCKER_SOCKET` | `/var/run/docker.sock` | upstream socket |
| `CONTAINERS` `IMAGES` `NETWORKS` `VOLUMES` `SERVICES` `TASKS` `NODES` `INFO` `VERSION` `EVENTS` `PING` | `1` | allowed read endpoints |
| `SWARM` `SECRETS` `CONFIGS` `PLUGINS` `DISTRIBUTION` `SYSTEM` `EXEC` | `0` | opt-in (`/swarm`, `/secrets`, `/configs`, `/plugins`, `/distribution`, `/system/df`, `/exec/{id}/json`) |
| `LOGS` | `0` | container/service/task logs, **passed through unredacted** (see below) |
| `REDACT_LABELS` | `0` | redact every label value (breaks Traefik routing) |
| `REDACT_LABEL_KEYS` | none | regexes (newline or `;;` separated); label values whose key matches are redacted |
| `REDACT_PATTERNS` | none | regexes; matches inside any JSON string value become `REDACTED` |
| `MAX_BODY_BYTES` | `67108864` | max buffered JSON response |
| `REQUEST_TIMEOUT` | `60s` | upstream timeout for non-streaming requests |
| `LOG_LEVEL` | `info` | slog level |

## What is blocked

* Every method except `GET` and `HEAD` (405), any request body, any `Upgrade`/hijack.
* Allowlist only: unknown paths are denied (403). Paths are cleaned (`..`, `//`) and the
  cleaned path is what is checked and forwarded.
* Even though they are GET: `/containers/{id}/archive`, `/export`, `/attach*`, `/top`,
  `/images/get`, `/images/{name}/get` (tarball export), `/images/search`, `/swarm/unlockkey`,
  `/plugins/privileges`, `/session`, and everything not listed in the table above.
* **Logs** are off by default. When `LOGS=1` the multiplexed log stream is forwarded as is;
  redacting a binary-framed stream reliably is not possible, so enable only if logs are
  trusted not to contain secrets.
* Fail closed: a JSON response that cannot be parsed returns 502; responses with any
  content type other than JSON/NDJSON (plus `/_ping` text, plain-text daemon errors, and
  opt-in logs) are refused with 502. Streaming JSON (`/events`, `/containers/{id}/stats`)
  is redacted per object and flushed immediately; a parse error aborts the stream.

## What is redacted

All values keep their exact text (big integers, number formatting, key order); only the
strings below change.

* **Env**: every array under a key named `Env`/`Envs`/`Environment` (container, image,
  service/task `ContainerSpec`, exec, plugin settings): `KEY=anything` becomes `KEY=REDACTED`.
  All values, no heuristics.
* **Key names** (case-insensitive substring): `password`, `passwd`, `secret`, `token`,
  `api_key`/`apikey`/`api-key`, `private_key`, `credential`, `signingca*`, `unlockkey`,
  `trustroot`, `auth`, `authconfig`, `auths`, `x-registry*`. Strings below such a key (also
  inside objects/arrays, e.g. `JoinTokens`, `AuthConfig`, `IdentityToken`,
  `CredentialSpec`) become `REDACTED`. Name references (`Secrets`, `SecretName`,
  `SecretID`) are kept. `Spec.Data` (swarm config/secret payload) is redacted.
* **Command lines** (`Cmd`, `Entrypoint`, `Args`, `Command`, `CreatedBy`, healthcheck
  `Test`, `Shell`, exec `Arguments`, event `Action`): heuristics, best effort:
  `NAME=value` where the name looks sensitive or is UPPER_CASE, `--password x` /
  `--token=x` style flags, `scheme://user:pass@host`, `Bearer/Basic <token>`,
  Dockerfile `ENV/ARG` instructions in image history. `sleep 3600` or `--log-level=debug`
  are untouched.
* **Private keys**: any string containing a PEM private key block.
* **Labels** (and event `Attributes`): kept by default because Traefik needs them; key-name
  rules are not applied to label keys. Use `REDACT_LABEL_KEYS` / `REDACT_PATTERNS` /
  `REDACT_LABELS`.

## Traefik

```yaml
services:
  socket-proxy:
    image: docker-socket-secure-proxy   # your build
    environment: { CONTAINERS: 1, NETWORKS: 1, SERVICES: 1, TASKS: 1, EVENTS: 1, VERSION: 1, INFO: 1, PING: 1 }
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    networks: [proxy]
    healthcheck: { test: ["CMD", "/docker-socket-secure-proxy", "--healthcheck"] }
  traefik:
    image: traefik:v3
    command: ["--providers.docker.endpoint=tcp://socket-proxy:2375", "--providers.docker.exposedbydefault=false"]
    networks: [proxy]
networks: { proxy: { internal: true } }
```

## Caveats

* Do not expose the proxy port beyond trusted networks: there is no authentication.
* **Labels are not redacted by default.** Traefik basic-auth hashes
  (`traefik.http.middlewares.x.basicauth.users=user:hash`) are visible to anything that can
  read the proxy. Use `REDACT_LABEL_KEYS='basicauth|password|secret'` (Traefik itself reads
  labels via the same proxy, so this would also break those middlewares; run Traefik against
  the real socket or keep such values in files/secrets instead).
* Heuristics on command lines are imperfect; secrets passed as positional arguments or in
  unusual forms will not be caught. Env values and key-name rules are the strong guarantees.
* Bind mount paths, image names, networks, IPs and similar metadata are not secret-redacted.

## Development

```sh
make test      # unit tests (race)
make e2e       # needs local docker; runs scripts/e2e.sh (proxy on :9999)
```
