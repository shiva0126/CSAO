# Deployment Guide

## Intended Deployment Model

CSAO is designed to run inside customer environments using a customer-provided AWS read-only administrative role dedicated to assessment execution.

## Deployment Requirements

- Python environment matching the project requirements
- Local CSAO authentication enabled
- Customer-provided AWS account or role
- Least-privilege policy generated from `Access Requirements`

## Recommended Process

1. Deploy CSAO in the customer environment
2. Create or assume the customer-provided read-only AWS assessment role
3. Import the account into the CSAO Analyst Console
4. Export and review the generated least-privilege policy
5. Run Capability Validation
6. Launch the assessment

## Persistent Service

For host-based deployments, run CSAO under `systemd` so the console starts at boot and is restarted automatically if the process exits.

1. Ensure the virtual environment exists at `venv/` and dependencies are installed.
2. Make the helper scripts executable: `chmod +x scripts/run_workbench.sh scripts/install_systemd_service.sh`
3. Install and start the service: `./scripts/install_systemd_service.sh`
4. Verify the service: `systemctl status csao`
5. Inspect logs if needed: `journalctl -u csao -f`

The installer renders `deploy/systemd/csao.service` into `/etc/systemd/system/csao.service`, enables it on boot, and starts it immediately. The unit runs `scripts/run_workbench.sh` and uses `Restart=always` with a 5-second backoff.

## Health Monitoring

CSAO exposes two built-in health endpoints for ongoing validation:

- `GET /health`
- `GET /health/ui`

Use `./scripts/run_ui_smoke_tests.sh` during deployment validation and `./scripts/ui_watchdog.py --base-url http://127.0.0.1:2909` during development to continuously detect UI regressions, broken assets, auth issues, or route failures.
