# pingjack

An educational demonstration of **OS command injection** (`CWE-78`, `A03:2021 - Injection`), built
around a fictional fleet link check API.

Three services expose an identical API and differ in exactly one way: how each turns a submitted
hostname into the command it asks the operating system to run. One hands the value to a shell, one
removes the shell but still lets the value become arguments, and one validates before any process
exists. Sending the same request to all three, side by side, is the lesson.

> **Read this before running anything.**
>
> - This is **local educational material**, not a product. Everything in it — the operators, the
>   fleet, the tokens, the "sensitive" fixture — is invented.
> - Two of the three services are **intentionally vulnerable**. They execute what you submit. They
>   are deliberately hard to start by accident, and they must never be deployed anywhere.
> - Everything runs **locally, in disposable containers**, via Docker Compose. Published ports are
>   bound to `127.0.0.1`, and no component makes any outbound network connection.
> - There is **no hosted service** here, nothing to sign up for, and no image or package published
>   anywhere. Nothing in this repository is production-safe or intended for production use, and
>   none of it makes any such claim.

## Start here

**[WALKTHROUGH.md](WALKTHROUGH.md)** is the guided tour: the vocabulary, shell strings versus
argument vectors, all four demonstrated outcomes with the output you should expect, why denylisting
metacharacters is the weaker control, and things to try yourself. It assumes no prior knowledge of
command injection and no reading of this repository's source.

The rest of this file is the short version.

## Requirements

Docker Compose. Nothing else: Python, the project dependencies, `uv`, pytest, Ruff, and mypy all
run inside the container.

## See the whole thing in one command

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo
```

That starts all three services inside one disposable container against fresh temporary databases,
drives them over real localhost HTTP, prints a verdict for each, and cleans up after itself. It
takes a couple of seconds. Add `--verbose` for the HTTP exchange and the probe output:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo pingjack-demo --verbose
```

Or drive it yourself with `pingjack-demo --interactive`, which asks which service to use and which
payload to send.

The run ends like this:

```
  vulnerable  VULNERABLE - a shell parsed the submitted value, and the injected command ran
  naive       STILL VULNERABLE - no shell was involved, and the fixture leaked anyway
  secure      SECURE - both payloads refused before any process existed, history untouched
```

The demo carries the same two-action gate as the services it starts, so it is not a way around
them. Its container has no network at all — only a loopback interface — so every request it makes
provably stays inside it.

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

## Run the naive service

The same two actions start the naive argv-only application on `127.0.0.1:8002` — it is covered by
the `vulnerable` profile too:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build
```

It uses **no shell at all**, so the payload above is inert here:

```sh
curl -X POST http://127.0.0.1:8002/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret' \
  -H 'Content-Type: application/json' \
  -d '{"host":"relay-7.internal.test; cat /srv/netops/fleet_deploy.key"}'
```

The `;` is just a character inside one literal argument — the probe reports the whole thing as an
unreachable host and nothing is disclosed. Now send this instead:

```sh
curl -X POST http://127.0.0.1:8002/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret' \
  -H 'Content-Type: application/json' \
  -d '{"host":"--config /srv/netops/fleet_deploy.key"}'
```

`201 Created`, and the fictional key fixture is in the output again — this time with no shell
anywhere. The submitted value was appended to the probe's *arguments*, so it handed the probe an
option to honour. **Removing the shell was necessary. It was not sufficient.** Only validating the
input closes this, which is what the secure service on port `8000` does.

## What is in here

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

- The **naive check service**: no shell, no validation — immune to the metacharacter payload and
  still disclosing the same fixture through argument injection.

- The **comparison CLI** (`pingjack-demo`), the one-shot disposable demo container, and the
  security regression matrix covering all three services.
- The **walkthrough** in [WALKTHROUGH.md](WALKTHROUGH.md).

## Contributing and security

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to run the gate and the
safety rules a change must not break.

Before reporting a security issue, read [SECURITY.md](SECURITY.md). The command-injection flaw in
the vulnerable and naive services is the subject being taught, not a bug; a vulnerability that is
*not* that one has a private reporting path.

## Licence

[MIT](LICENSE). Provided as-is, with no warranty and no support, compatibility, or
production-readiness commitment of any kind.
