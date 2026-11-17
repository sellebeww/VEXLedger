# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Oracle: every expectation was derived BY HAND from the OSV schema "Evaluation"
section and the ecosystem version specs, independently of the other tests in this directory.
Each case runs the production path parse_purl -> parse_record -> local_match.
Verdicts: A = AFFECTED, N = NOT_AFFECTED, U = UNKNOWN. OSV records are SYNTHETIC."""

import pytest

from vexledger.domain.matching import local_match
from vexledger.domain.osv_model import parse_record
from vexledger.domain.purl import parse_purl


def rec(eco, name, events, rtype="ECOSYSTEM", versions=None, rid="X-1"):
    aff = {"package": {"ecosystem": eco, "name": name}}
    if events is not None:
        aff["ranges"] = [{"type": rtype, "events": events}]
    if versions is not None:
        aff["versions"] = versions
    return {"id": rid, "affected": [aff]}


def verdict(purl, record):
    res = local_match(parse_purl(purl), [parse_record(record)])
    return {"AFFECTED": "A", "NOT_AFFECTED": "N", "UNKNOWN": "U"}[res.groups[0].verdict.value]


def INTRO(v):
    return {"introduced": v}


def F(v):
    return {"fixed": v}


def L(v):
    return {"last_affected": v}


def LIM(v):
    return {"limit": v}


cases = []


def add(label, purl, record, expected):
    cases.append((label, purl, record, expected))


# ---------- PyPI (PEP 440), hand-derived ----------
def P(v):
    return f"pkg:pypi/Foo_Bar@{v}"  # spelling normalised to foo-bar


def pr(ev, **k):
    return rec("PyPI", "foo-bar", ev, **k)


add("pypi fixed boundary exclusive", P("1.0.0"), pr([INTRO("0"), F("1.0.0")]), "N")
add("pypi just below fixed", P("0.9.9"), pr([INTRO("0"), F("1.0.0")]), "A")
add("pypi rc below final", P("1.0.0rc1"), pr([INTRO("0"), F("1.0.0")]), "A")
add("pypi post above introduced", P("1.0.0.post1"), pr([INTRO("1.0.0"), F("1.0.1")]), "A")
add("pypi dev below final", P("1.0.1.dev0"), pr([INTRO("0"), F("1.0.1")]), "A")
add("pypi epoch dominates", P("1!0.5"), pr([INTRO("0"), F("2.0")]), "N")
add("pypi last_affected inclusive", P("1.2.3"), pr([INTRO("0"), L("1.2.3")]), "A")
add("pypi post above last_affected", P("1.2.3.post1"), pr([INTRO("0"), L("1.2.3")]), "N")
add("pypi 1.0 equals fixed 1.0.0", P("1.0"), pr([INTRO("0"), F("1.0.0")]), "N")
add("pypi invalid version never affected", P("not-a-version"), pr([INTRO("0")]), "U")
add("pypi listed version exact", P("1.0.0"), pr(None, versions=["1.0.0"]), "A")
add("pypi two intervals (gap)", P("1.7"), pr([INTRO("1.0"), F("1.5"), INTRO("2.0"), F("2.5")]), "N")
add(
    "pypi two intervals (second)",
    P("2.2"),
    pr([INTRO("1.0"), F("1.5"), INTRO("2.0"), F("2.5")]),
    "A",
)
add("pypi unsorted events", P("1.5"), pr([F("2.0"), INTRO("1.0")]), "A")
add("pypi introduced a1, a2 inside", P("2.0.0a2"), pr([INTRO("2.0.0a1"), F("2.0.0")]), "A")
add("pypi below introduced", P("0.9"), pr([INTRO("1.0")]), "N")
add("pypi limit exclusive", P("2.0"), pr([INTRO("0"), LIM("2.0")]), "N")
add("pypi no fixed unbounded", P("99.0"), pr([INTRO("1.0")]), "A")
add(
    "pypi GIT only is not a verdict",
    P("1.0"),
    rec("PyPI", "foo-bar", [INTRO("0")], rtype="GIT"),
    "U",
)
add("pypi other package name no match", "pkg:pypi/other@1.0", pr([INTRO("0")]), "N")


# ---------- npm (SemVer 2.0), hand-derived ----------
def N(v):
    return f"pkg:npm/%40Scope/Pkg@{v}"  # scope normalised to lowercase


def nr(ev, **k):
    return rec("npm", "@scope/pkg", ev, **k)


add(
    "npm prerelease inside",
    N("1.0.0-beta.2"),
    nr([INTRO("1.0.0-beta.1"), F("1.0.0")], rtype="SEMVER"),
    "A",
)
add("npm beta.11 above beta.5", N("1.0.0-beta.11"), nr([INTRO("0"), F("1.0.0-beta.5")]), "N")
add("npm beta.2 below beta.5", N("1.0.0-beta.2"), nr([INTRO("0"), F("1.0.0-beta.5")]), "A")
add(
    "npm alpha.1 below alpha.beta", N("1.0.0-alpha.1"), nr([INTRO("0"), F("1.0.0-alpha.beta")]), "A"
)
add(
    "npm alpha.beta equals fixed",
    N("1.0.0-alpha.beta"),
    nr([INTRO("0"), F("1.0.0-alpha.beta")]),
    "N",
)
add("npm build ignored at fixed", N("1.0.0+build5"), nr([INTRO("0"), F("1.0.0")]), "N")
add("npm build ignored at last_affected", N("1.0.0+build"), nr([INTRO("0"), L("1.0.0")]), "A")
add("npm numeric not lexical", N("10.0.0"), nr([INTRO("0"), F("9.0.0")]), "N")
add("npm two-part version invalid", N("1.0"), nr([INTRO("0")]), "U")
add("npm leading zero invalid", N("01.0.0"), nr([INTRO("0")]), "U")
add("npm rc.1 equals fixed", N("1.0.0-rc.1"), nr([INTRO("0"), F("1.0.0-rc.1")]), "N")
add("npm beta below fixed rc.1", N("1.0.0-beta"), nr([INTRO("0"), F("1.0.0-rc.1")]), "A")
add("npm limit exclusive (at)", N("2.0.0"), nr([INTRO("0"), LIM("2.0.0")]), "N")
add("npm limit (below)", N("1.5.0"), nr([INTRO("0"), LIM("2.0.0")]), "A")
add("npm unsorted events", N("1.5.0"), nr([F("2.0.0"), INTRO("1.0.0")]), "A")
add("npm introduced==fixed same version", N("1.0.0"), nr([INTRO("1.0.0"), F("1.0.0")]), "N")
add("npm unscoped name mismatch", "pkg:npm/pkg@1.0.0", nr([INTRO("0")]), "N")
add("npm numeric id below alnum id", N("1.0.0-1"), nr([INTRO("0"), F("1.0.0-a")]), "A")


# ---------- Go ----------
def G(v):
    return f"pkg:golang/github.com/Masterminds/semver@{v}"


def gr(ev, **k):
    return rec("Go", "github.com/Masterminds/semver", ev, **k)


add("go v-prefix vs plain OSV", G("v1.2.3"), gr([INTRO("0"), F("1.2.4")]), "A")
add(
    "go case-preserved (lowercase OSV name differs)",
    G("v1.2.3"),
    rec("Go", "github.com/masterminds/semver", [INTRO("0")]),
    "N",
)
add(
    "go pseudo before dated pseudo",
    G("v0.0.0-20191109021931-daa7c04131f5"),
    gr([INTRO("0"), F("0.0.0-20200101000000-aaaaaaaaaaaa")]),
    "A",
)
add(
    "go pseudo after dated pseudo",
    G("v0.0.0-20210101000000-bbbbbbbbbbbb"),
    gr([INTRO("0"), F("0.0.0-20200101000000-aaaaaaaaaaaa")]),
    "N",
)
add("go +incompatible below fixed", G("v2.0.0+incompatible"), gr([INTRO("0"), F("2.0.1")]), "A")
add("go +incompatible equals fixed", G("v2.0.0+incompatible"), gr([INTRO("0"), F("2.0.0")]), "N")
add("go rc below release", G("v1.0.0-rc.1"), gr([INTRO("0"), F("1.0.0")]), "A")
add("go versions[] without v", G("v1.2.3"), gr(None, versions=["1.2.3"]), "A")
add(
    "go post-release pseudo before next",
    G("v1.2.4-0.20190101000000-abcdef123456"),
    gr([INTRO("1.2.3"), F("1.2.4")]),
    "A",
)
add("go v1.2 shorthand not guessed", G("v1.2"), gr([INTRO("0")]), "U")
add("go limit", G("v1.9.0"), gr([INTRO("1.0.0"), LIM("2.0.0")]), "A")
add("go below introduced", G("v0.9.0"), gr([INTRO("1.0.0")]), "N")


# ---------- Maven (ComparableVersion), hand-derived ----------
def M(v):
    return f"pkg:maven/org.example/lib@{v}"


def mr(ev, **k):
    return rec("Maven", "org.example:lib", ev, **k)


L4S = [INTRO("2.0-beta9"), F("2.3.1"), INTRO("2.4"), F("2.12.2"), INTRO("2.13.0"), F("2.15.0")]
add("maven 1.0 equals fixed 1.0.0", M("1.0"), mr([INTRO("0"), F("1.0.0")]), "N")
add("maven snapshot below release", M("1.0-SNAPSHOT"), mr([INTRO("0"), F("1.0")]), "A")
add("maven alpha below beta", M("1.0-alpha-1"), mr([INTRO("0"), F("1.0-beta-1")]), "A")
add("maven rc1 below release", M("1.0-rc1"), mr([INTRO("0"), F("1.0")]), "A")
add("maven sp1 above release", M("1.0-sp1"), mr([INTRO("0"), F("1.0")]), "N")
add("maven .final equals release", M("1.0.final"), mr([INTRO("0"), F("1.0")]), "N")
add("maven -ga equals release", M("1.0-ga"), mr([INTRO("0"), F("1.0")]), "N")
add("maven 1.0-1 above 1.0", M("1.0-1"), mr([INTRO("0"), F("1.0")]), "N")
add("maven numeric 2.10 above 2.9", M("2.10"), mr([INTRO("0"), F("2.9")]), "N")
add("maven milestone below rc", M("1.0-m1"), mr([INTRO("0"), F("1.0-rc1")]), "A")
add("maven unknown qualifier above release", M("1.0-foo"), mr([INTRO("0"), F("1.0")]), "N")
add("maven last_affected inclusive", M("1.5"), mr([INTRO("1.0"), L("1.5")]), "A")
add("maven log4shell-shaped (synthetic) in", M("2.14.1"), mr(L4S), "A")
add("maven log4shell-shaped (synthetic) fixed", M("2.15.0"), mr(L4S), "N")
add("maven log4shell-shaped (synthetic) gap", M("2.12.2"), mr(L4S), "N")
add("maven group case-sensitive", "pkg:maven/Org.Example/lib@1.0", mr([INTRO("0")]), "N")


@pytest.mark.parametrize(("label", "purl", "record", "expected"), cases, ids=[c[0] for c in cases])
def test_hand_derived_case(label: str, purl: str, record: dict, expected: str) -> None:  # type: ignore[type-arg]
    assert verdict(purl, record) == expected, label


def test_there_are_at_least_ten_cases_per_ecosystem() -> None:
    for prefix in ("pypi", "npm", "go", "maven"):
        assert sum(1 for c in cases if c[0].startswith(prefix)) >= 10, prefix
