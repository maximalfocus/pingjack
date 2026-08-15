"""The comparison engine.

Everything here works against ``httpx`` clients it is handed, and never touches the terminal. The
one-shot demo passes clients pointed at real local servers; tests pass clients wired straight to the
applications. Neither path needs terminal input, so the engine is directly testable.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import httpx

from pingjack.apps import naive, secure, vulnerable
from pingjack.fleet import FLEET_DEPLOY_KEY_PATH, FLEET_HOSTS, is_fleet_host
from pingjack.hostname import is_valid_hostname

SECURE = "secure"
VULNERABLE = "vulnerable"
NAIVE = "naive"
APPLICATIONS = (VULNERABLE, NAIVE, SECURE)

FLEET_HOST = FLEET_HOSTS[0]
METACHARACTER_PAYLOAD = f"{FLEET_HOST}; cat {FLEET_DEPLOY_KEY_PATH}"
ARGUMENT_PAYLOAD = f"--config {FLEET_DEPLOY_KEY_PATH}"

#: Present in the fixture and in nothing else, so its appearance in a response is proof of
#: disclosure.
FIXTURE_MARKER = "FICTIONAL DEMO FIXTURE"

NOTHING_CONSTRUCTED = "(nothing - refused before any process was created)"

NO_PROBE_RAN = "(none - no process ran)"
REPLY_AND_FIXTURE = "the link check reply, and the contents of the fictional key fixture"
FIXTURE_ONLY = "the contents of the fictional key fixture"
REPLY_ONLY = "the link check reply only"
UNREACHABLE_ONLY = "an unreachable report only"


def summarise_probe_output(output: str, *, disclosed: bool) -> str:
    """Say in one line what the probe actually printed, so the reader need not read it."""
    if not output:
        return NO_PROBE_RAN
    # Anchored to the start of a line: "no reply from" also contains "reply from".
    replied = any(line.startswith("reply from") for line in output.splitlines())
    if disclosed:
        return REPLY_AND_FIXTURE if replied else FIXTURE_ONLY
    return REPLY_ONLY if replied else UNREACHABLE_ONLY


def constructed_invocation(application: str, host: str) -> str:
    """Render exactly what ``application`` builds for ``host``.

    This calls the same builder the running application calls, with the same input, so what is
    shown is what the server constructed. The secure application refuses before building anything,
    which is itself the thing worth showing.
    """
    if application == VULNERABLE:
        return f"/bin/sh -c {shlex.quote(vulnerable.build_command(host))}"
    if application == NAIVE:
        return shlex.join(naive.build_argv(host))
    if is_valid_hostname(host) and is_fleet_host(host):
        return shlex.join(secure.build_argv(host))
    return NOTHING_CONSTRUCTED


@dataclass(frozen=True, slots=True)
class Exchange:
    """One submission and what came back."""

    application: str
    submitted: str
    status_code: int
    body: str
    constructed: str
    output: str
    disclosed_fixture: bool
    record_created: bool
    probe_summary: str


@dataclass(frozen=True, slots=True)
class ApplicationResult:
    """Everything one application did during the comparison."""

    application: str
    exchanges: tuple[Exchange, ...]
    records_before: int
    records_after: int
    history_unchanged_by_rejections: bool

    @property
    def disclosed(self) -> bool:
        """Whether the fictional fixture leaked through any response."""
        return any(exchange.disclosed_fixture for exchange in self.exchanges)

    @property
    def verdict(self) -> str:
        if self.application == VULNERABLE:
            return (
                "VULNERABLE - a shell parsed the submitted value, and the injected command ran"
                if self.disclosed
                else "UNEXPECTED - no disclosure"
            )
        if self.application == NAIVE:
            return (
                "STILL VULNERABLE - no shell was involved, and the fixture leaked anyway"
                if self.disclosed
                else "UNEXPECTED - no disclosure"
            )
        return (
            "SECURE - both payloads refused before any process existed, history untouched"
            if not self.disclosed and self.history_unchanged_by_rejections
            else "UNEXPECTED - the secure application did not hold"
        )


@dataclass(frozen=True, slots=True)
class Report:
    """The whole comparison."""

    results: tuple[ApplicationResult, ...]

    def by_application(self, application: str) -> ApplicationResult:
        for result in self.results:
            if result.application == application:
                return result
        raise KeyError(application)

    @property
    def demonstrates_every_outcome(self) -> bool:
        """Whether all four required outcomes were observed in this run."""
        secure_result = self.by_application(SECURE)
        return (
            self.by_application(VULNERABLE).disclosed
            and self.by_application(NAIVE).disclosed
            and not secure_result.disclosed
            and secure_result.history_unchanged_by_rejections
            and secure_result.records_after == secure_result.records_before + 1
            and any(exchange.status_code == 201 for exchange in secure_result.exchanges)
        )


def _headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _history(client: httpx.Client, token: str) -> str:
    response = client.get("/checks", headers=_headers(token))
    response.raise_for_status()
    return response.text


def _count(body: str) -> int:
    parsed = json.loads(body)
    return len(parsed) if isinstance(parsed, list) else 0


def submit(client: httpx.Client, application: str, host: str, token: str) -> Exchange:
    """Submit one host to one application and record what came back."""
    response = client.post("/checks", json={"host": host}, headers=_headers(token))
    body = response.text
    created = response.status_code == 201
    output = str(response.json().get("output", "")) if created else ""
    disclosed = FIXTURE_MARKER in body
    return Exchange(
        application=application,
        submitted=host,
        status_code=response.status_code,
        body=body,
        constructed=constructed_invocation(application, host),
        output=output,
        disclosed_fixture=disclosed,
        record_created=created,
        probe_summary=summarise_probe_output(output, disclosed=disclosed),
    )


#: What each application is asked to submit, in the order the narrative tells it.
SUBMISSIONS: Mapping[str, tuple[str, ...]] = {
    VULNERABLE: (METACHARACTER_PAYLOAD,),
    NAIVE: (METACHARACTER_PAYLOAD, ARGUMENT_PAYLOAD),
    SECURE: (METACHARACTER_PAYLOAD, ARGUMENT_PAYLOAD),
}


def _run_unsafe(client: httpx.Client, application: str, token: str) -> ApplicationResult:
    before = _history(client, token)
    exchanges = tuple(submit(client, application, host, token) for host in SUBMISSIONS[application])
    after = _history(client, token)
    return ApplicationResult(
        application=application,
        exchanges=exchanges,
        records_before=_count(before),
        records_after=_count(after),
        history_unchanged_by_rejections=before == after,
    )


def _run_secure(client: httpx.Client, token: str) -> ApplicationResult:
    """Both payloads are refused, then a legitimate check proves the feature still works."""
    before = _history(client, token)
    rejections = tuple(submit(client, SECURE, host, token) for host in SUBMISSIONS[SECURE])
    after_rejections = _history(client, token)
    legitimate = submit(client, SECURE, FLEET_HOST, token)
    after_legitimate = _history(client, token)
    return ApplicationResult(
        application=SECURE,
        exchanges=(*rejections, legitimate),
        records_before=_count(before),
        records_after=_count(after_legitimate),
        # Byte-for-byte, not merely the same count.
        history_unchanged_by_rejections=before == after_rejections,
    )


def run_scripted_comparison(clients: Mapping[str, httpx.Client], token: str) -> Report:
    """Exercise all three applications in one deterministic run."""
    results: list[ApplicationResult] = [
        _run_unsafe(clients[VULNERABLE], VULNERABLE, token),
        _run_unsafe(clients[NAIVE], NAIVE, token),
        _run_secure(clients[SECURE], token),
    ]
    return Report(results=tuple(results))


def submissions_for(application: str) -> Sequence[str]:
    """Return the payloads the scripted run sends to ``application``."""
    return SUBMISSIONS[application]
