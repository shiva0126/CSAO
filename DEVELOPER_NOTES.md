# Developer Notes

## Architectural Constraints

- Do not replace the CSAO engines.
- Do not redesign the methodology or assessment pipeline.
- Keep workbench changes as orchestration, persistence, and presentation layers around the existing engines.

## RC Console Design

- FastAPI routes stay thin and delegate to `workbench.runtime.WorkbenchRuntime`.
- Persistent operational state is stored in `output/workbench/state.json`.
- Sensitive cloud account material is encrypted by `workbench.control_plane.AccountVault`.
- Assessment execution is still driven by `AssessmentRunner`, which wraps the existing engines in sequence.

## Hardening Notes

- The workbench server may require unrestricted local socket access in sandboxed environments.
- The logger falls back to non-queued file logging when semaphore creation is blocked.
- The dependency checker now respects the project interpreter for `python3` and `pip3` detection.
- Assessment cancellation is checkpoint-based to avoid interrupting engines mid-operation.
