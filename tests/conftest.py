from __future__ import annotations

import random

import pytest

from workbench.db.base import SyncSessionLocal
from workbench.db.models import WorkbenchStateRow


@pytest.fixture
def isolated_state_id():
    """A `workbench_state` row id that is never 1 -- the real app's one and
    only production row.

    WorkbenchState/WorkbenchRuntime persist to Postgres regardless of any
    `path` argument passed in (kept only for display/logging -- see
    control_plane.py). Before `state_id` existed as a real parameter,
    every test that constructed `WorkbenchState(tmp_path / "state.json")`
    or `WorkbenchRuntime()` *looked* isolated via tmp_path but was
    silently reading and writing the actual shared production state.
    That corrupted the real database with undecryptable fake accounts
    during this session -- see MIGRATION_LEDGER.md.

    Random rather than a counter: pytest-xdist or repeated local runs
    could otherwise collide on a small monotonic counter across processes.
    Collision odds against id=1 or another concurrent test run are
    astronomically small at this range.
    """
    state_id = random.randint(10_000_000, 2_000_000_000)
    yield state_id
    with SyncSessionLocal() as db:
        row = db.get(WorkbenchStateRow, state_id)
        if row is not None:
            db.delete(row)
            db.commit()
