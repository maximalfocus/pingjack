# Walkthrough: turning a hostname field into command execution

> **Everything here is invented.** Meridian Fleet Operations does not exist. Its four hosts live
> under the reserved `.test` domain and resolve to nothing. The "deploy key" is a text file that
> says, in its own contents, that it is a fictional demo fixture. Nothing in this project touches
> anything outside its own container.
>
> **The vulnerable and naive services are deliberately broken.** They are local educational code.
> Do not deploy them, anywhere, for any reason.

You do not need to read any source code to follow this. You need Docker Compose and about five
minutes.

---

## 1. The scenario

Meridian Fleet Operations runs an internal link-check API. An authenticated operator posts a
hostname; the server runs a probe utility against it and stores the result.

```
POST /checks   {"host": "relay-7.internal.test"}   →   201 Created + the probe's output
GET  /checks                                       →   that operator's own check history
```

Three services expose that exact same API. They differ in **one** thing: how each one turns the
submitted host into the command it asks the operating system to run.

| Service | Port | How it builds the invocation |
|---|---|---|
| `vulnerable` | 8001 | pastes the value into a command string, hands it to a shell |
| `naive` | 8002 | no shell — but appends the unvalidated value to the probe's arguments |
| `secure` | 8000 | validates first, then runs a fixed argument vector |

That single difference is the whole lesson.

---

## 2. The vocabulary

The flaw is **OS command injection**, also called **shell injection** or just **command
injection**. It is `CWE-78` and sits under `A03:2021 — Injection` in the OWASP Top Ten.

In plain language:

> **Command injection is what happens when user input becomes part of the command the server runs,
> instead of staying data the command is given.**

Hold on to that distinction — *part of the command* versus *data the command is given*. Everything
below is an illustration of it.

### Shell strings versus argument vectors

There are two ways to run a program.

**As an argument vector.** You hand the operating system a list: the program, then each argument as
its own separate item.

```
["fleetprobe", "--count", "1", "relay-7.internal.test"]
   program        arg 1   arg 2         arg 3
```

The boundaries between arguments are decided *by you*, in your program, before the operating system
ever sees them. Nothing inside an argument can create a new boundary. If argument 3 happened to be
`relay-7.internal.test; rm -rf /`, it would still be *one argument* — a very strange hostname that
the probe would simply fail to reach.

**As a shell string.** You hand a shell one long string and ask it to figure out what you meant.

```
sh -c "fleetprobe --count 1 relay-7.internal.test"
```

The shell now has a job: parse that text. And the shell's grammar has *operators* — characters that
mean something structural rather than literal:

| Character | What the shell does with it |
|---|---|
| `;` | end this command, start another one |
| `&&` `\|\|` | run another command conditionally |
| `\|` | pipe this command's output into another |
| `` ` `` `$( )` | run this and substitute the result |
| `&` | run in the background |
| `>` `<` | redirect to or from a file |

Any of those inside your string is *syntax*, not text. So if part of that string came from a user,
the user gets to write shell syntax. That is the entire vulnerability.

---

## 3. Run it

One command runs all three services against fresh state, sends the payloads, and prints a verdict
for each:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo
```

Starting anything intentionally vulnerable takes **two deliberate actions** — the Compose profile
*and* the `ALLOW_VULNERABLE_DEMO=true` acknowledgement. Leave either out and the service refuses to
start and tells you which one is missing. That is on purpose: this code should be hard to run by
accident.

Add `--verbose` to see the full HTTP exchange and the complete probe output:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo pingjack-demo --verbose
```

The container starts the services itself against fresh temporary databases, talks to them over its
own loopback interface, and deletes everything on the way out. It has no network beyond loopback,
so nothing it does can reach off the machine.

---

## 4. The four outcomes

### Outcome 1 — the vulnerable service: a semicolon becomes a second command

Submitted:

```
relay-7.internal.test; cat /srv/netops/fleet_deploy.key
```

The server builds one string and hands it to a shell:

```
/bin/sh -c '/usr/local/bin/fleetprobe --count 1 relay-7.internal.test; cat /srv/netops/fleet_deploy.key'
```

Read that as the shell reads it. There is no hostname containing a semicolon here. There are **two
commands**: run the probe, then `cat` a file. The shell obligingly runs both, and their combined
output is what the server stores and returns.

```
  response          : HTTP 201
  probe output      : the link check reply, and the contents of the fictional key fixture
  check record      : created
  fixture disclosed : YES
```

Notice what the client sees: `201 Created`. An ordinary success. Nothing in the response says
anything went wrong, and the file's contents are sitting in the stored check record for anyone who
reads that operator's history later.

**Why it happened:** the submitted value stopped being data and became part of the command.

### Outcome 2 — the naive service: the shell is gone, and so is this attack

Someone reads about command injection and removes the shell. The probe is now invoked as an
argument vector. Send the exact same payload to port 8002:

```
  submitted         : relay-7.internal.test; cat /srv/netops/fleet_deploy.key
  server constructed: /usr/local/bin/fleetprobe --count 1 'relay-7.internal.test; cat /srv/netops/fleet_deploy.key'
  response          : HTTP 201
  probe output      : an unreachable report only
  check record      : created
  fixture disclosed : no
```

The whole payload — semicolon and all — arrived as **one argument**. No shell parsed it, so there
was no grammar for `;` to be part of. The probe treated it as a hostname, failed to reach it, and
said so. Nothing was disclosed.

That is a real fix for a real attack. It is also not enough.

### Outcome 3 — the naive service again: argument injection

The value is still appended to the probe's arguments without validation, and this probe — like
plenty of real tools — accepts a `--config` option that echoes a file. So submit an option instead
of a hostname:

```
--config /srv/netops/fleet_deploy.key
```

```
  server constructed: /usr/local/bin/fleetprobe --count 1 --config /srv/netops/fleet_deploy.key
  response          : HTTP 201
  probe output      : the contents of the fictional key fixture
  check record      : created
  fixture disclosed : YES
```

The same file comes back, through an ordinary `201`, with **no shell involved anywhere**.

The attacker no longer controls *what program runs* — but still controls *what that program is
told to do*. Every argument the attacker can add is a feature of the target program they get to
use. This is **argument injection**, and it is why "we removed the shell" is a fix for one attack
rather than a fix for the class.

> **Removing the shell was necessary. It was not sufficient.**

### Outcome 4 — the secure service: validate first, and keep working

The secure service applies two controls, in this order, **before any process exists**:

1. the value must match a strict hostname syntax rule; then
2. it must be a member of the fleet allowlist.

Only then does it run a fixed argument vector — the host as one positional argument, no `--config`,
a fixed argument count.

Send it either payload:

```
  submitted         : relay-7.internal.test; cat /srv/netops/fleet_deploy.key
  server constructed: (nothing - refused before any process was created)
  response          : HTTP 400
  probe output      : (none - no process ran)
  check record      : none created
  fixture disclosed : no
```

```
  submitted         : --config /srv/netops/fleet_deploy.key
  server constructed: (nothing - refused before any process was created)
  response          : HTTP 400
  probe output      : (none - no process ran)
  check record      : none created
  fixture disclosed : no
```

Both refusals are **byte-for-byte identical**. The client cannot tell whether the value failed the
syntax rule or merely was not in the fleet — that distinction would leak which hosts exist. No
process started. No record was created. The operator's history is byte-for-byte what it was before.

Where did the reason go? To the server, as one structured JSON event:

```json
{"action": "check.submit", "event": "check.rejected", "operator_id": "operator-alpha",
 "outcome": "rejected", "rejection_class": "hostname_syntax",
 "request_id": "9fda2d6a-4fa0-4d04-bb5e-ff4454d91500",
 "submitted_value": "relay-7.internal.test; cat /srv/netops/fleet_deploy.key",
 "submitted_value_length": 55, "submitted_value_truncated": false}
```

You can watch these with `docker compose logs secure`. The event carries a correlation id that is
also returned to the client in the `X-Request-ID` header, names the operator and the rejection
class, and records the submitted value only length-capped and with control characters escaped. It
never contains probe output, fixture contents, tokens, or authorization headers.

And the feature still works. A real fleet host goes straight through:

```
  submitted         : relay-7.internal.test
  server constructed: /usr/local/bin/fleetprobe --count 1 relay-7.internal.test
  response          : HTTP 201
  probe output      : the link check reply only
  check record      : created
```

Exactly one new record. Validation did not break the product; it just stopped answering questions
nobody should be asking.

---

## 5. Why not just block the dangerous characters?

The tempting fix is a **denylist**: reject any value containing `;`, `&`, `|`, `` ` ``, `$`, and so
on. It is the weaker control, for reasons that compound:

- **You have to be right about every character, forever.** The denylist is a claim that you have
  enumerated every character with structural meaning — in every shell, in every locale, under every
  quoting context, plus newlines, carriage returns, and whatever the next version adds. Miss one
  and the control is gone.
- **It only defends the attack you thought of.** Outcome 3 contains no shell metacharacters at all.
  `--config /srv/netops/fleet_deploy.key` passes any metacharacter denylist you care to write, and
  still reads the file.
- **It defends the wrong boundary.** A denylist tries to make dangerous input safe. The real
  problem is that input reached a place where it could be dangerous.
- **It fails open.** Anything you did not anticipate is accepted by default.

An **allowlist** inverts every one of those. The secure service does not ask "is this value
dangerous?" — a question you can be wrong about. It asks "is this value one of the small set I
recognise as valid?" — a question with a definite answer. Lowercase letters, digits, and interior
hyphens, in labels, within length limits; then membership of a four-host fleet. Everything else is
refused, including things nobody has thought of yet. It **fails closed**.

The ordering matters too: validation happens *before* a process is created, not after. A check that
runs after the damage is not a control.

## 6. What to take away

1. Running a command with arguments is not the same as asking a shell to interpret a string. Know
   which one you are doing.
2. Prefer the argument vector. Never build a command string out of user input.
3. But removing the shell only closes shell injection. If the user can still add arguments, they
   can still use the target program's features against you.
4. Validate the input against an allowlist of what is valid, before any process exists. Denylisting
   dangerous characters is the weaker control and fails open.
5. Refuse identically and generically to the client; keep the reason on the server, in a structured
   event, with the untrusted value bounded and escaped.

---

## 7. Poke at it yourself

Start the services and leave them running:

```sh
# the secure service alone, on 127.0.0.1:8000
docker compose up --build

# plus the two intentionally vulnerable ones, on :8001 and :8002
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up --build
```

Each service serves its generated OpenAPI documentation locally — open
`http://127.0.0.1:8000/docs` (or `:8001/docs`, `:8002/docs`) in a browser, or fetch
`http://127.0.0.1:8000/openapi.json`.

Two fictional operators exist, with unmistakably fake tokens:

```sh
curl -X POST http://127.0.0.1:8001/checks \
  -H 'Authorization: Bearer demo-token-alpha-not-a-real-secret' \
  -H 'Content-Type: application/json' \
  -d '{"host":"relay-7.internal.test; cat /srv/netops/fleet_deploy.key"}'
```

Things worth trying: send that same payload to `:8000` and `:8002`; try `--config` against all
three; try `relay-9.internal.test`, which is a perfectly well-formed hostname that is not in the
fleet; try a request with no `Authorization` header at all. Watch `docker compose logs secure` while
you do it.

Stop everything with:

```sh
docker compose --profile vulnerable down -v
```

## 8. Run the tests

The security properties are all asserted, and the whole toolchain lives in the image:

```sh
docker compose run --rm verify
```

That runs Ruff, mypy, and the test suite — including the regression matrix that proves the
vulnerable disclosure, the naive immunity, the naive argument-injection disclosure, the secure
byte-identical refusal with untouched history, that the rejection class leaks through neither the
response nor its timing, and that the probe is byte-deterministic and never touches the network. It
runs with container networking disabled, so anything reaching for the network fails loudly.
