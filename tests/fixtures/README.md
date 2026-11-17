# Test fixtures

## osv_synthetic/

**SYNTHETIC. These are NOT recordings from the OSV.dev API.** They were assembled by hand to
follow the OSV schema (https://ossf.github.io/osv-schema/) so domain logic can be tested offline.
Ids such as `CVE-2099-*`, `GHSA-synt-*` and package names such as `synthetic-pkg` are made up;
nothing here says anything about a real package or vulnerability.

Recorded fixtures (real API responses, with capture date) will live in a separate `osv_recorded/`
directory when they exist. None exist yet.
