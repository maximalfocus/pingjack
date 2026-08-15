# Contributing

Contributions are welcome. This is a teaching repository, so the bar for a good change is a little
unusual: it should make the lesson clearer or more honest, without making the demonstration less
safe to run.

## Running things

Everything lives in the container. You need Docker Compose and nothing else — no Python on your
machine, no virtualenv, no installed packages.

```sh
docker compose run --rm verify                                        # Ruff, mypy, and the tests
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo   # the whole comparison
```

The verification gate runs with container networking disabled, so anything that reaches for the
network fails there rather than in review. CI runs that same command; there is no separate CI
toolchain to keep in step.

## What a good change looks like

- **Keep the three services different in exactly one way.** They share a service layer and differ
  only in how each builds the probe invocation. That single axis is the whole lesson; anything that
  blurs it costs more than it adds.
- **Prove behaviour at the boundary.** Unit tests are welcome, but a claim about container startup,
  port publishing, or the opt-in gate needs a test that actually exercises it — or, where that is
  impossible, a note in the pull request saying what you ran by hand and what you saw.
- **Keep the regression matrix green and meaningful.** `tests/test_regression_matrix.py` is the
  file that must never go red. If a change makes one of its assertions untrue, that is the finding,
  not an inconvenience.
- **Match the surrounding style.** Ruff and mypy `strict` both run over `src` and `tests`.

## Safety rules

These are not negotiable, because the project is only defensible while they hold:

1. **The unsafe services stay gated.** Starting the vulnerable or naive service must keep requiring
   both deliberate actions — the Compose profile *and* `ALLOW_VULNERABLE_DEMO=true`. Do not add a
   third way in, and do not make the demo container a way around them.
2. **Everything stays fictional.** No real hostnames, organizations, people, credentials, or
   operational details, in code, tests, documentation, commit messages, or issues. The fleet lives
   under the reserved `.test` domain; any fixture standing in for a secret must say in its own
   contents that it is fictional.
3. **Nothing reaches the network.** No component — service, probe, test, or demo — may make an
   outbound connection, and every published port stays bound to `127.0.0.1`.
4. **The probe stays a constant.** No configuration value or request field may choose which
   executable runs, in any of the three services.
5. **No deployment.** This project is not hosted and does not publish an image or a package. Please
   do not add configuration that implies otherwise.

## Reporting problems

For an ordinary bug or an idea, open an issue. If you think you have found a vulnerability that is
*not* the one being demonstrated, read [SECURITY.md](SECURITY.md) first — it explains which is
which and gives a private reporting path.

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
