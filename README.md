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
./bin/docker-socket-secure-proxy                  # listens on :2375 (Docker's default unencrypted port)
PORT=8080 ./bin/docker-socket-secure-proxy        # or --port 8080
LISTEN_ADDR=127.0.0.1:2375 ./bin/docker-socket-secure-proxy
docker -H tcp://127.0.0.1:2375 ps
```

Flags: `--listen`, `--port`, `--socket`, `--healthcheck` (HEAD `/_ping` on the local listener,
exit 0/1; for images without curl, needs `PING` enabled).

Listen address precedence: `--listen` flag, then `LISTEN_ADDR`, then default `:2375`. The port
is then overridden if set: `--port` flag, then `PORT`. A port replaces only the port of the
listen address and keeps its host, so `LISTEN_ADDR=127.0.0.1:2375 PORT=8080` listens on
`127.0.0.1:8080`. `--healthcheck` uses the same resolved address, so it follows `PORT` too.

Go version: built and tested with Go 1.27.4. `encoding/json/v2`/`jsontext` work in this
toolchain without `GOEXPERIMENT`; on older toolchains use `GOEXPERIMENT=jsonv2 make build`.

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:2375` | listen address (host and port) |
| `PORT` | none | listen port; replaces the port of `LISTEN_ADDR` (`--port` overrides it) |
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

## Docker

The image is `gcr.io/distroless/static-debian12:nonroot` (no shell, one static binary, uid 65532,
multi-arch amd64/arm64). The socket is usually `root:docker` mode 660, so the container user must
join the socket's group; `--group-add` / `group_add` takes the numeric GID
(`stat -c %g /var/run/docker.sock`). Use a read-only rootfs and drop capabilities.

```sh
docker run -d --name socket-proxy -p 127.0.0.1:2375:2375 \
  --group-add "$(stat -c %g /var/run/docker.sock)" --read-only --cap-drop ALL \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e CONTAINERS=1 -e PING=1 youruser/docker-socket-secure-proxy
```

Compose with Traefik:

```yaml
services:
  socket-proxy:
    image: youruser/docker-socket-secure-proxy
    group_add: ["999"]            # GID of /var/run/docker.sock on the host
    read_only: true
    cap_drop: [ALL]
    environment: { CONTAINERS: 1, NETWORKS: 1, SERVICES: 1, TASKS: 1, EVENTS: 1, VERSION: 1, INFO: 1, PING: 1 }
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]
    networks: [proxy]
    # HEALTHCHECK is built in (--healthcheck, needs PING=1)
  traefik:
    image: traefik:v3
    command: ["--providers.docker.endpoint=tcp://socket-proxy:2375", "--providers.docker.exposedbydefault=false"]
    networks: [proxy]
networks: { proxy: { internal: true } }
```

Build locally: `docker build -t docker-socket-secure-proxy .` (BuildKit needed for multi-arch;
`scripts/e2e-container.sh` runs a redaction check against the built image).

### CI and Docker Hub

`.github/workflows/ci.yml` runs vet, tests and a static build check on push/PR.
`.github/workflows/release.yml` builds `linux/amd64` (ubuntu-latest) and `linux/arm64`
(native `ubuntu-24.04-arm` runner, no QEMU) in a matrix, pushes each by digest, then a `merge`
job publishes the multi-arch manifest (`X.Y.Z`, `X.Y`, `latest` on `v*.*.*` tags, `edge` on
main; SBOM and provenance attached). It runs on those tags, on pushes to main and on manual
dispatch.

#### Docker Hub push setup

1. Create a Docker Hub account and a repository named `docker-socket-secure-proxy`
   (e.g. `rsubr/docker-socket-secure-proxy`) at <https://hub.docker.com>.
2. Create an access token: Account settings, Personal access tokens, Generate new token,
   scope **Read & Write**. Copy it; it is shown once.
3. Add GitHub repository secrets (Settings, Secrets and variables, Actions, New repository
   secret), or with the CLI:
   ```sh
   gh secret set DOCKERHUB_USERNAME --body rsubr
   gh secret set DOCKERHUB_TOKEN        # paste the token when prompted
   ```
4. Optional: set a repository variable `DOCKERHUB_IMAGE` (Settings, Secrets and variables,
   Actions, Variables), e.g. `myorg/docker-socket-secure-proxy`, or
   `gh variable set DOCKERHUB_IMAGE --body myorg/docker-socket-secure-proxy`. Default is
   `<DOCKERHUB_USERNAME>/docker-socket-secure-proxy`.
5. Trigger a release: `git tag v0.1.0 && git push origin v0.1.0`, or run the workflow manually
   (Actions, Release, Run workflow, or `gh workflow run release.yml`). A push to main publishes
   the `edge` tag.
6. Verify: the Actions run shows both `build` jobs and `merge` green; then
   `docker buildx imagetools inspect rsubr/docker-socket-secure-proxy:0.1.0` lists
   `linux/amd64` and `linux/arm64`, and `docker run --rm rsubr/docker-socket-secure-proxy:0.1.0 --help`
   starts the image.

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
make e2e       # needs local docker; runs scripts/e2e.sh (proxy on :19376; override with `PORT=`)
```

## License

BSD 3-Clause, see [LICENSE](LICENSE). Copyright (c) 2026, rsubr.
