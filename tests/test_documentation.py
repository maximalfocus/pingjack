"""The documentation is part of the deliverable, so it is asserted like the code.

These checks are deliberately coarse: they prove the required subjects are covered and that nothing
which belongs to a later stage has crept in. They cannot judge whether the prose is any good.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WALKTHROUGH = (ROOT / "WALKTHROUGH.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
CONTRIBUTING = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
SECURITY = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
LICENSE = (ROOT / "LICENSE").read_text(encoding="utf-8")
DOCUMENTS = {"WALKTHROUGH.md": WALKTHROUGH, "README.md": README}
PUBLIC_DOCUMENTS = {
    "WALKTHROUGH.md": WALKTHROUGH,
    "README.md": README,
    "CONTRIBUTING.md": CONTRIBUTING,
    "SECURITY.md": SECURITY,
}


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


def test_the_license_is_the_canonical_mit_text_with_accurate_attribution() -> None:
    assert LICENSE.startswith("MIT License")
    assert "Copyright (c) 2026 maximalfocus" in LICENSE
    for clause in (
        "Permission is hereby granted, free of charge",
        "The above copyright notice and this permission notice shall be included in all",
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND',
    ):
        assert clause in LICENSE


def test_package_metadata_declares_the_same_spdx_license() -> None:
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'license = "MIT"' in metadata
    assert 'license-files = ["LICENSE"]' in metadata


def test_the_readme_points_at_the_license_and_the_two_policies() -> None:
    for link in ("(LICENSE)", "(CONTRIBUTING.md)", "(SECURITY.md)"):
        assert link in README


@pytest.mark.parametrize(
    "statement",
    [
        "educational",
        "intentionally vulnerable",
        "Docker Compose",
        "no hosted service",
        "must never be deployed",
    ],
)
def test_the_readme_states_the_public_operating_boundary(statement: str) -> None:
    assert statement in " ".join(README.replace(">", " ").split())


def test_the_readme_no_longer_reads_as_work_in_progress() -> None:
    for phrase in (
        "so far",
        "arrives in the slice",
        "slices that follow",
        "Private implementation",
    ):
        assert phrase not in README


def test_the_security_policy_separates_the_taught_flaw_from_real_ones() -> None:
    flowed = flowing(SECURITY)

    assert "do not report these" in flowed
    assert "the flaw in this repository is the product" in flowed
    # ...and names what a genuine finding would look like.
    assert "escapes the demo container" in flowed
    assert "secure" in flowed


def test_the_security_policy_gives_a_non_public_reporting_path() -> None:
    assert "security/advisories/new" in SECURITY
    assert "private vulnerability reporting" in flowing(SECURITY)
    assert "do not open a public issue" in flowing(SECURITY)


def test_contribution_guidance_covers_the_gate_and_the_safety_rules() -> None:
    flowed = flowing(CONTRIBUTING)

    assert "docker compose run --rm verify" in CONTRIBUTING
    assert "allow_vulnerable_demo=true" in flowed
    assert "everything stays fictional" in flowed
    assert "no deployment" in flowed


@pytest.mark.parametrize("document", sorted(PUBLIC_DOCUMENTS))
def test_no_public_document_promises_support_or_production_readiness(document: str) -> None:
    flowed = flowing(PUBLIC_DOCUMENTS[document])

    for promise in (
        "production-ready",
        "production ready",
        "supported release",
        "response time of",
        "within 24 hours",
        "service level agreement",
        "sla",
    ):
        assert promise not in flowed, f"{document} promises: {promise}"


@pytest.mark.parametrize("document", sorted(PUBLIC_DOCUMENTS))
def test_no_public_document_references_private_companion_material(document: str) -> None:
    flowed = flowing(PUBLIC_DOCUMENTS[document])

    # Deliberately generic: naming the companion here would make this guard the disclosure it
    # exists to prevent, and the bare term catches any reference to a requirements document.
    for term in ("prd", "progress.md", "/users/", "private repository"):
        assert term not in flowed, f"{document} references private material: {term}"


@pytest.mark.parametrize("document", sorted(PUBLIC_DOCUMENTS))
def test_the_only_external_host_referenced_is_this_repository(document: str) -> None:
    allowed = (
        "https://github.com/maximalfocus/pingjack/",
        "http://127.0.0.1:",
        "http://localhost:",
    )

    for url in re.findall(r"https?://[^\s)>\"'`]+", PUBLIC_DOCUMENTS[document]):
        assert url.startswith(allowed), f"{document} links off to a third party: {url}"


@pytest.mark.parametrize("document", sorted(DOCUMENTS))
def test_documented_hosts_stay_inside_the_reserved_test_domain(document: str) -> None:
    text = DOCUMENTS[document]

    assert "internal.test" in text
    for real_looking in (".com", ".net", ".org", ".io"):
        assert real_looking not in text, f"{document} names a real-looking domain: {real_looking}"
