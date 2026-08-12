from __future__ import annotations

import asyncio
import os
from typing import Any, Dict

from arq.connections import RedisSettings

from core.tool_check import check_external_tools
from workbench.control_plane import AssessmentRunner, AuditLogger, WorkbenchState, utc_now_iso


async def run_assessment_job(
    ctx: Dict[str, Any],
    base_config: Dict[str, Any],
    assessment: Dict[str, Any],
    account: Dict[str, Any],
    account_credentials: Dict[str, Any],
    validations: Dict[str, Any],
) -> None:
    """ARQ job entrypoint. Runs in the worker process/container.

    Constructs its own WorkbenchState + AssessmentRunner -- both are plain
    Postgres clients with no in-process affinity (Phase 1), so this is safe
    to do fresh per job, same as the web process does per request. Calls
    the exact same _run_assessment_body/_mark_stage/_initialize_run/etc.
    methods that the old threading.Thread target used, so the read side
    (workbench/runtime.py) needs zero changes -- it doesn't know or care
    whether the writer was a thread or a queued job.

    The pipeline itself (core/orchestrator.run_pipeline) is synchronous,
    blocking code (boto3/pandas/networkx) -- run via run_in_executor so it
    doesn't block the worker's event loop.
    """
    runner = AssessmentRunner(WorkbenchState(), audit=AuditLogger())
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        runner._run_assessment_body,
        base_config,
        assessment,
        account,
        account_credentials,
        validations,
    )


async def startup(ctx: Dict[str, Any]) -> None:
    """Reports which collector tools this worker container can actually run
    into the shared workbench_state row, so the Trust Center UI reflects
    the environment that really executes scans instead of doing a
    (wrong-environment) live check from the web process. Runs once per
    worker boot -- container restarts naturally refresh this."""

    def mutate(state):
        state["tool_status"] = check_external_tools()
        state["tool_status_checked_at"] = utc_now_iso()
        return state

    WorkbenchState().update(mutate)


async def shutdown(ctx: Dict[str, Any]) -> None:
    pass


async def shutdown(ctx: Dict[str, Any]) -> None:
    pass


class WorkerSettings:
    functions = [run_assessment_job]
    redis_settings = RedisSettings.from_dsn(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    on_startup = startup
    on_shutdown = shutdown
    # Single-assessment-at-a-time is already enforced by AssessmentRunner.start()
    # checking Postgres state before enqueueing; this is defense-in-depth at
    # the queue level.
    max_jobs = 1
    # The pipeline can run for a long time; ARQ's 5-minute default job_timeout
    # would kill a real assessment mid-run.
    job_timeout = 3600 * 6
    allow_abort_jobs = True
