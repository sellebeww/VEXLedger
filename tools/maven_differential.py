# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Owner-run differential test: our Maven comparator against Apache's real ComparableVersion.

NOT RUN yet (the sandbox refused to execute downloaded Java).
It downloads maven-artifact from Maven Central, checks the SHA-1 Central publishes, compiles a
tiny harness with your JDK, compares random version pairs and exits 1 on any mismatch.

    uv run python tools/maven_differential.py [--version 3.9.9] [--pairs 30000]
"""

import argparse
import hashlib
import random
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

from vexledger.domain.ecosystem import Ecosystem
from vexledger.domain.versions import scheme_for

BASE = "https://repo1.maven.org/maven2/org/apache/maven/maven-artifact"
HARNESS = """
import java.nio.file.*;
import org.apache.maven.artifact.versioning.ComparableVersion;
public class Cmp {
  public static void main(String[] a) throws Exception {
    StringBuilder sb = new StringBuilder();
    for (String line : Files.readAllLines(Paths.get(a[0]))) {
      String[] p = line.split("\\t", -1);
      int c = new ComparableVersion(p[0]).compareTo(new ComparableVersion(p[1]));
      sb.append(Integer.signum(c)).append('\\n');
    }
    Files.writeString(Paths.get(a[1]), sb.toString());
  }
}
"""
QUALIFIERS = [
    "alpha",
    "beta",
    "rc",
    "cr",
    "snapshot",
    "final",
    "ga",
    "release",
    "sp",
    "m",
    "a",
    "b",
]


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 - fixed https host
        return bytes(r.read())


def token(rng: random.Random) -> str:
    r = rng.random()
    if r < 0.55:
        return str(rng.choice([0, 0, 1, 1, 2, 3, 9, 10, 11, 20, 100]))
    if r < 0.8:
        return rng.choice([*QUALIFIERS, "foo"])
    return rng.choice(QUALIFIERS) + str(rng.randint(0, 12))


def version(rng: random.Random) -> str:
    out = token(rng)
    if out[0].isalpha():
        out = f"{rng.randint(0, 3)}.{out}"
    for _ in range(rng.randint(0, 4)):
        out += rng.choice([".", "-", "."]) + token(rng)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="3.9.9")
    ap.add_argument("--pairs", type=int, default=30000)
    args = ap.parse_args()
    jar_url = f"{BASE}/{args.version}/maven-artifact-{args.version}.jar"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        jar = work / "ma.jar"
        jar.write_bytes(fetch(jar_url))
        expected = fetch(jar_url + ".sha1").decode().split()[0]
        actual = hashlib.sha1(jar.read_bytes()).hexdigest()  # noqa: S324 - matches Central's sha1
        if expected != actual:
            print(f"SHA-1 mismatch: {expected} != {actual}")
            return 2
        (work / "Cmp.java").write_text(HARNESS)
        rng = random.Random(20261117)  # noqa: S311 - reproducible test data
        pairs = [(version(rng), version(rng)) for _ in range(args.pairs)]
        (work / "pairs.tsv").write_text("".join(f"{a}\t{b}\n" for a, b in pairs))
        javac = ["javac", "-cp", str(jar), "-d", str(work), str(work / "Cmp.java")]
        subprocess.run(javac, check=True)
        java = ["java", "-cp", f"{jar}:{work}", "Cmp", str(work / "pairs.tsv"), str(work / "o.txt")]
        subprocess.run(java, check=True)
        reference = (work / "o.txt").read_text().split()
    scheme = scheme_for(Ecosystem.MAVEN)
    bad = [
        (a, b, ref)
        for (a, b), ref in zip(pairs, reference, strict=True)
        if str(scheme.compare(a, b)) != ref
    ]
    for a, b, ref in bad[:20]:
        print(f"MISMATCH {a!r} vs {b!r}: java={ref} ours={scheme.compare(a, b)}")
    print(f"{len(pairs)} pairs, {len(bad)} mismatches (maven-artifact {args.version})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
