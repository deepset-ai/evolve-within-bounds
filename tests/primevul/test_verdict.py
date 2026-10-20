# SPDX-FileCopyrightText: 2026-present deepset GmbH <info@deepset.ai>
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from security_agent.primevul.verdict import extract_json_object, normalize_cwe, parse_strict, parse_verdict

VERDICT = {"is_vulnerable": True, "cwe": "cwe-787", "vulnerable_lines": [3], "rationale": " unbounded copy "}


@pytest.mark.parametrize(
    "raw, expected", [("787", "CWE-787"), ("cwe-787", "CWE-787"), ("CWE 787", "CWE-787"), ("", None), (None, None)]
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_strict_json_is_normalized():
    verdict = parse_verdict(json.dumps(VERDICT))
    assert verdict == {
        "is_vulnerable": True,
        "cwe": "CWE-787",
        "vulnerable_lines": [3],
        "rationale": "unbounded copy",
        "parse_error": False,
    }


def test_verdict_in_a_code_fence_after_prose():
    text = "Let me think.\n```json\n" + json.dumps(VERDICT) + "\n```"
    assert parse_verdict(text)["cwe"] == "CWE-787"
    assert parse_strict(text)["parse_error"]


def test_the_last_verdict_wins_when_the_model_revises():
    draft = {**VERDICT, "is_vulnerable": True}
    final = {**VERDICT, "is_vulnerable": False, "cwe": None, "vulnerable_lines": []}
    text = f"Draft: {json.dumps(draft)} On reflection the check holds. {json.dumps(final)}"
    assert parse_verdict(text)["is_vulnerable"] is False


def test_a_verdict_cut_off_by_one_character_is_repaired():
    text = json.dumps(VERDICT)[:-1]
    assert parse_verdict(text)["is_vulnerable"] is True


def test_an_object_missing_a_key_still_counts():
    verdict = parse_verdict('{"is_vulnerable": false}')
    assert verdict["parse_error"] is False
    assert verdict["is_vulnerable"] is False


@pytest.mark.parametrize(
    "text", ["", "I think it is vulnerable.", '{"verdict": "yes"}', "(the model returned no text)"]
)
def test_no_verdict_is_a_parse_error(text):
    verdict = parse_verdict(text)
    assert verdict["parse_error"] is True
    assert verdict["is_vulnerable"] is None


def test_extract_ignores_braces_inside_strings():
    text = 'prose {"a": "}"} more prose {"is_vulnerable": false, "rationale": "x {y}"'
    assert json.loads(extract_json_object(text))["rationale"] == "x {y}"
