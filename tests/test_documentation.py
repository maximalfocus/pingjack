"""The documentation is part of the deliverable, so it is asserted like the code.

These checks are deliberately coarse: they prove the required subjects are covered and that nothing
which belongs to a later stage has crept in. They cannot judge whether the prose is any good.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WALKTHROUGH = (ROOT / "WALKTHROUGH.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
DOCUMENTS = {"WALKTHROUGH.md": WALKTHROUGH, "README.md": README}


def flowing(text: str) -> str:
    """Collapse Markdown wrapping so a sentence can be matched across line breaks."""
    return " ".join(text.replace(">", " ").split()).lower()


def test_the_walkthrough_exists_and_is_substantial() -> None:
    assert len(WALKTHROUGH.splitlines()) > 150


@pytest.mark.parametrize(
    "subject",
    [
        "CWE-78",
        "A03:2021",
        "command injection",
        "shell injection",
        "argument vector",
        "argument injection",
        "allowlist",
        "denylist",
    ],
)
def test_the_walkthrough_covers_the_required_terminology(subject: str) -> None:
    assert subject in WALKTHROUGH


def test_the_walkthrough_explains_shell_strings_versus_argument_vectors() -> None:
    assert "Shell strings versus argument vectors" in WALKTHROUGH
    for operator in (";", "&&", "`", "$("):
        assert operator in WALKTHROUGH


def test_the_walkthrough_says_why_denylisting_is_the_weaker_control() -> None:
    assert "weaker control" in WALKTHROUGH
    assert "fails open" in WALKTHROUGH
    assert "fails closed" in WALKTHROUGH


def test_the_walkthrough_reaches_all_four_outcomes() -> None:
    for outcome in ("Outcome 1", "Outcome 2", "Outcome 3", "Outcome 4"):
        assert outcome in WALKTHROUGH


@pytest.mark.parametrize(
    "command",
    [
        "ALLOW_VULNERABLE_DEMO=true docker compose --profile demo run --rm demo",
        "docker compose run --rm verify",
        "docker compose up --build",
    ],
)
def test_the_walkthrough_gives_the_commands(command: str) -> None:
    assert command in WALKTHROUGH


def test_the_walkthrough_covers_local_openapi_exploration() -> None:
    assert "openapi.json" in WALKTHROUGH
    assert "127.0.0.1:8000/docs" in WALKTHROUGH


def test_the_walkthrough_states_the_expected_outcomes() -> None:
    for expected in ("HTTP 201", "HTTP 400", "fixture disclosed : YES", "fixture disclosed : no"):
        assert expected in WALKTHROUGH


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_every_document_warns_the_unsafe_services_must_not_be_deployed(document: str) -> None:
    text = flowing(DOCUMENTS[document])

    assert "local educational" in text
    assert "deliberately broken" in text
    assert "must never be deployed" in text or "do not deploy" in text


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_no_document_claims_a_license_or_a_public_release(document: str) -> None:
    text = DOCUMENTS[document]

    for claim in ("MIT License", "SPDX", "open source", "open-source", "publicly available"):
        assert claim not in text, f"{document} makes a publication claim: {claim}"


def test_no_license_file_is_present_yet() -> None:
    assert not (ROOT / "LICENSE").exists()
    assert not (ROOT / "LICENSE.md").exists()


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_documented_hosts_stay_inside_the_reserved_test_domain(document: str) -> None:
    text = DOCUMENTS[document]

    assert "internal.test" in text
    for real_looking in (".com", ".net", ".org", ".io"):
        assert real_looking not in text, f"{document} names a real-looking domain: {real_looking}"
