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

The applications, the comparison CLI, and the walkthrough arrive in the slices that follow.
