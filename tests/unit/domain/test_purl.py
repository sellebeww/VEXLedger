# Copyright (c) 2026 Vassel Goleyu. MIT License.
import pytest

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.errors import InvalidPurlError
from vexledger.domain.purl import normalize_pypi_name, parse_purl


@pytest.mark.parametrize(
    ("raw", "key", "ref", "osv_name", "eco"),
    [
        (
            "pkg:pypi/Django_Rest.Framework@3.0",
            "pypi/django-rest-framework",
            "pypi/django-rest-framework@3.0",
            "django-rest-framework",
            Ecosystem.PYPI,
        ),
        ("pkg:pypi/A__b--C...d@1", "pypi/a-b-c-d", "pypi/a-b-c-d@1", "a-b-c-d", Ecosystem.PYPI),
        (
            "pkg:PyPI/Requests@2.31.0",
            "pypi/requests",
            "pypi/requests@2.31.0",
            "requests",
            Ecosystem.PYPI,
        ),
        ("pkg:npm/Left-Pad@1.3.0", "npm/left-pad", "npm/left-pad@1.3.0", "left-pad", Ecosystem.NPM),
        (
            "pkg:npm/%40Angular/Core@17.0.0",
            "npm/%40angular/core",
            "npm/%40angular/core@17.0.0",
            "@angular/core",
            Ecosystem.NPM,
        ),
        (
            "pkg:npm/@angular/core@17.0.0",
            "npm/%40angular/core",
            "npm/%40angular/core@17.0.0",
            "@angular/core",
            Ecosystem.NPM,
        ),
        (
            "pkg:maven/org.Apache.Commons/Commons-IO@2.11.0",
            "maven/org.Apache.Commons/Commons-IO",
            "maven/org.Apache.Commons/Commons-IO@2.11.0",
            "org.Apache.Commons:Commons-IO",
            Ecosystem.MAVEN,
        ),
        (
            "pkg:golang/github.com/Masterminds/Semver/v3@v3.1.0",
            "golang/github.com/Masterminds/Semver/v3",
            "golang/github.com/Masterminds/Semver/v3@v3.1.0",
            "github.com/Masterminds/Semver/v3",
            Ecosystem.GO,
        ),
        (
            "pkg:golang/golang.org/x/text@v0.3.7",
            "golang/golang.org/x/text",
            "golang/golang.org/x/text@v0.3.7",
            "golang.org/x/text",
            Ecosystem.GO,
        ),
    ],
)
def test_normalization_per_type(
    raw: str, key: str, ref: str, osv_name: str, eco: Ecosystem
) -> None:
    p = parse_purl(raw)
    assert p.component_key == key
    assert p.component_ref == ref
    assert p.osv_name == osv_name
    assert p.ecosystem is eco
    assert p.supported
    assert p.original == raw


def test_maven_is_case_sensitive_and_go_keeps_case() -> None:
    assert (
        parse_purl("pkg:maven/Org.X/Lib@1").component_key
        != parse_purl("pkg:maven/org.x/lib@1").component_key
    )
    assert parse_purl("pkg:golang/github.com/Foo/Bar@v1.0.0").name == "Bar"


def test_qualifiers_and_subpath_kept_but_not_in_key() -> None:
    p = parse_purl("pkg:maven/org.x/lib@1.0?type=jar&classifier=sources#a/b")
    assert p.component_key == "maven/org.x/lib"
    assert p.component_ref == "maven/org.x/lib@1.0"
    assert p.qualifiers == (("classifier", "sources"), ("type", "jar"))
    assert p.subpath == "a/b"
    assert p.original.endswith("#a/b")


def test_version_is_optional_and_ref_is_none_without_it() -> None:
    p = parse_purl("pkg:pypi/foo")
    assert p.version is None
    assert p.component_ref is None


def test_same_key_regardless_of_version_or_spelling() -> None:
    a = parse_purl("pkg:pypi/Foo_Bar@1.0")
    b = parse_purl("pkg:pypi/foo-bar@2.0?x=y")
    assert a.component_key == b.component_key
    assert a.component_ref != b.component_ref


def test_unsupported_ecosystem_is_explicit() -> None:
    p = parse_purl("pkg:deb/debian/curl@7.0?arch=i386")
    assert p.ecosystem is None
    assert not p.supported
    assert p.osv_name is None
    assert p.component_key == "deb/debian/curl"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "pkg:",
        "pkg:pypi/",
        "pkg:bogus",
        "not a purl",
        "pypi/foo@1",
        "pkg:maven/lib@1",
        "pkg:pypi/ns/foo@1",
        "pkg:npm/a%2Fb@1",
    ],
)
def test_invalid_purls_raise_typed_error(raw: str) -> None:
    with pytest.raises(InvalidPurlError):
        parse_purl(raw)


def test_round_trip_is_stable() -> None:
    p = parse_purl("pkg:npm/%40Scope/Name@1.0.0?a=b#sub")
    again = parse_purl(f"pkg:{p.component_ref}")
    assert again.component_ref == p.component_ref


@pytest.mark.parametrize(
    ("raw", "expected"), [("Foo_Bar", "foo-bar"), ("a.b_c-d", "a-b-c-d"), ("a--b", "a-b")]
)
def test_normalize_pypi_name(raw: str, expected: str) -> None:
    assert normalize_pypi_name(raw) == expected
