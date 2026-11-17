# Copyright (c) 2026 Vassel Goleyu. MIT License.
import json
from pathlib import Path

import pytest

from vexledger.domain.osv_model import OsvRecord, parse_record

FIXTURES = Path(__file__).parents[2] / "fixtures" / "osv_synthetic"


@pytest.fixture
def load_record():  # type: ignore[no-untyped-def]
    def _load(record_id: str) -> OsvRecord:
        return parse_record(json.loads((FIXTURES / f"{record_id}.json").read_text()))

    return _load
