# pingjack

An educational demonstration of **OS command injection** (`CWE-78`, `A03:2021 - Injection`), built
around a fictional fleet link check API.

> **Local educational material.** Everything here - the operators, the fleet, the tokens, and the
> "sensitive" fixture - is invented. The demonstration runs only inside its own disposable
> container, performs no network access, and is not intended to run anywhere else.

## Requirements

Docker Compose. Nothing else: Python, the project dependencies, `uv`, pytest, Ruff, and mypy all
run inside the container.

## Verify

```sh
docker compose run --rm verify
```

That single command runs Ruff, mypy, and the test suite inside the image, with container networking
disabled. GitHub Actions runs the same command.

## Run the secure service

```sh
docker compose up --build
```

That starts the secure application - and only the secure application - on `127.0.0.1:8000`. It runs
from the built image rather than your working copy, so pass `--build` after changing code. Its
generated OpenAPI documentation is at `http://127.0.0.1:8000/docs`.

Two fictional operators are configured, with unmistakably fake demo tokens:

```sh
curl -X POST http://127.0.0.1:8000/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret' \
  -H 'Content-Type: application/json' \
  -d '{"host":"relay-7.internal.test"}'

curl http://127.0.0.1:8000/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret'
```

A submitted host must satisfy a strict syntax rule **and** be a fleet member, both checked before
any process is created. Anything else gets the same generic `400` regardless of which check refused
it; the reason exists only in the structured JSON event the server writes to its own log
(`docker compose logs secure`).

## Run the vulnerable service

> **The vulnerable application is deliberately broken.** It executes whatever you submit. It is
> local educational code, it runs only inside this container against invented fixtures, and it must
> never be deployed anywhere.

Starting it takes **two** deliberate actions — enabling the profile *and* acknowledging what it is:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build
```

With either action missing it refuses to start and says which one is absent. It listens on
`127.0.0.1:8001`.

```sh
curl -X POST http://127.0.0.1:8001/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret' \
  -H 'Content-Type: application/json' \
  -d '{"host":"relay-7.internal.test; cat /srv/netops/fleet_deploy.key"}'
```

That returns an ordinary-looking `201 Created` whose probe output contains both the link-check
result **and** the contents of the fictional key fixture — because the `;` was parsed as shell
syntax rather than treated as part of a hostname. Sending the same value to the secure service on
port `8000` returns a generic `400`.

## What is here so far

- The fictional **Meridian Fleet Operations** fleet - four invented hosts under the reserved
  `.test` domain - and its fictional operators.
- The append-only **check record** model: a UUID identifier, the submitted host value, the probe
  output, an exit status, and the owning operator.
- `fleetprobe`, the **bundled probe utility**. The project ships its own probe instead of calling a
  system network tool, so its output is fully determined by its arguments:

  ```sh
  fleetprobe --count 3 relay-7.internal.test
  fleetprobe --count 1 --config /path/to/profile relay-7.internal.test
  ```

  It prints a banner, optionally echoes the `--config` file on one line, then prints one result
  line per count for a fleet host - or a single unreachable line for anything else, exiting `1`.
  It reads no clock, uses no randomness, and never touches the network, so identical arguments
  always produce identical bytes. The `--config` flag is a deliberate operational affordance and
  becomes important later in the demonstration.
- A fictional sensitive fixture at `/srv/netops/fleet_deploy.key`, baked into the image, whose own
  contents state that it is fictional and not a key.
- The **secure check service**: demo bearer authentication, the strict hostname rule plus fleet
  allowlist, argument-vector probe invocation, the append-only check lifecycle, per-operator check
  history, and the structured rejection audit event.

- The **vulnerable check service**: identical in every respect except that it interpolates the
  submitted host into a command string and hands it to a shell — plus the two-action opt-in gate
  that keeps it out of the default path.

The remaining application, the comparison CLI, and the walkthrough arrive in the slices that
follow.
