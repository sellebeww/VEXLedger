# SBOM fixtures

## Real (generated, not hand-written)
Generated on 2026-11-16 from this project's own Python environment with
`cyclonedx-bom` 8.0.1 (`cyclonedx-py`):

```sh
uv run cyclonedx-py environment --sv 1.4 --of JSON -o tests/fixtures/sboms/uv-env-1.4.cdx.json
uv run cyclonedx-py environment --sv 1.5 --of JSON -o tests/fixtures/sboms/uv-env-1.5.cdx.json
uv run cyclonedx-py environment --sv 1.6 --of JSON -o tests/fixtures/sboms/uv-env-1.6.cdx.json
uv run cyclonedx-py environment --pyproject pyproject.toml --mc-type application --sv 1.6 \
    --of JSON -o tests/fixtures/sboms/uv-env-1.6-with-root.cdx.json
```

The package list reflects the dev environment at generation time. Tests use these files only
to exercise parsing and import; no test claims anything about vulnerabilities of these packages.
These SBOMs carry no component hashes.

## Not generated
An npm SBOM (`@cyclonedx/cyclonedx-npm`) was NOT produced: it needs running a package
downloaded by `npx`, which was not done in this environment. To add one:
`cd web && npx @cyclonedx/cyclonedx-npm --output-file ../tests/fixtures/sboms/web-npm.cdx.json package.json`.

## Synthetic
Hand-built documents (hashes, nested components, duplicates, dangling references, components
without purl, hostile shapes) are assembled in `tests/unit/test_sbom_import.py`; they are NOT
real tool output.
