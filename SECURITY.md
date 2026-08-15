# Security policy

This project is a deliberately vulnerable teaching exercise. That makes "is this a security bug?"
an unusually confusing question here, so this document answers it directly.

## The flaw in this repository is the product

Two of the three services ship a real, working vulnerability on purpose:

- the **vulnerable** service interpolates the submitted host into a command string and hands it to
  a shell, so a shell metacharacter runs an injected command; and
- the **naive** service uses no shell, but appends the unvalidated submitted value to the probe's
  arguments, so an attacker-chosen option is honoured.

**Please do not report these.** They are the subject being taught, they are documented in
[WALKTHROUGH.md](WALKTHROUGH.md), and the tests assert that they still work. The same goes for the
demo bearer tokens, which are constants in this repository and protect nothing, and for the
fictional "key" fixture, which is a text file that says so in its own contents.

The **secure** service is different. It is the demonstration of the fix, and it is meant to hold.

## What is worth reporting

Anything that is *not* the lesson. For example:

- a way to make the **secure** service run an injected command, disclose the fixture, create a
  record from a rejected submission, or reveal which check refused a submission;
- anything that escapes the demo container or affects the machine running it;
- anything that reaches the network — no component here should make any outbound connection;
- a way to start one of the intentionally vulnerable services without both deliberate opt-in
  actions; or
- a real credential, personal datum, or non-fictional detail that has ended up in this repository
  or its history.

## How to report

Use **[private vulnerability reporting](https://github.com/maximalfocus/pingjack/security/advisories/new)**
on this repository. That opens a report only the maintainer can see.

Please do not open a public issue for anything in the list above. For ordinary bugs, feature ideas,
and questions about the teaching material, a public issue is exactly right.

A useful report says what you did, what happened, and what you expected instead. Please keep any
proof of concept inside the project's own container and against its own fixtures.

## Scope and expectations

This is educational material published as-is under the [MIT License](LICENSE). It is not a service
and nothing here is hosted. There is no support commitment, no response-time undertaking, no
release schedule, and no compatibility guarantee — the licence's warranty disclaimer is the whole
of it. Reports are read and handled on a best-effort basis, and you are welcome to fix something
yourself; see [CONTRIBUTING.md](CONTRIBUTING.md).
