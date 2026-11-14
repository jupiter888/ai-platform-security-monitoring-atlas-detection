# Local Operations Runbook

## Status

Tested within the documented local scope. Fresh dependency installation and
344 regression tests passed on macOS with Python 3.11. A controlled shutdown
and existing-state restart passed using the fresh runtime environment.
Credentials, SQLite state, and Docker volumes were preserved. First-use
credential provisioning was not part of this exercise.

The exercised host is an Intel Mac running Docker Desktop.
Prometheus uses host.docker.internal to reach host-run services.
Other platforms require separate validation.

## Dependencies

For a new environment, run from the project root:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install "pip==26.3" "setuptools==84.1.0"
python -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
python -m pip check
python -m unittest discover -s tests -v
```

For an existing environment, activate it without recreating it.
The development lock includes runtime and validation dependencies.
The runtime-only set is requirements-runtime.lock.
Packaging tools are pinned separately and are not covered by application hashes.

## Credentials and State

Required files reside outside the repository under
~/.config/project10/credentials/:

- inference-clients.json
- operators.json
- finding-receiver-key
- telemetry-producers.json
- grafana-admin-password

Preserve existing credentials when resuming the lab.
A new installation requires separate credential provisioning; the commands below
do not provision or rotate credentials.

The credential directory is private. Application credential files use mode 0600.
The Grafana password file uses mode 0444 for container access inside its private
parent directory. Changing that file does not necessarily reset an existing user.

Private SQLite state resides under ~/.local/share/project10/monitoring/.
Preserve it for queued-finding recovery and historical case verification.

## Start the Containers

```bash
docker info --format 'Docker server: {{.ServerVersion}}'
docker compose config --quiet
docker compose up -d
docker compose ps
```

Compose pins the scanned images by digest and preserves named volumes.

```bash
curl --fail --silent --show-error http://127.0.0.1:9090/-/ready
curl --fail --silent --show-error http://127.0.0.1:3100/ready
curl --fail --silent --show-error http://127.0.0.1:3000/api/health
```

Loki may return HTTP 503 during startup. Wait for readiness before experiments.

## Start the Python Services

Use separate terminals in the project root, each with the venv active.
Start exactly one instance of each service in the order below.

Collector:

```bash
python -m src.telemetry.collector
```

Finding receiver:

```bash
python -m uvicorn src.detection.receiver:create_app --factory --host 127.0.0.1 --port 8300 --no-access-log
```

Operator API:

```bash
python -m uvicorn src.detection.operator_api:create_app --factory --host 127.0.0.1 --port 8400 --no-access-log
```

The operator API initializes the case ledger and containment table before first
inference use.

Inference API:

```bash
python -m uvicorn src.inference.api:create_app --factory --host 127.0.0.1 --port 8200 --no-access-log
```

Detector:

```bash
python -m src.detection.monitor
```

If a port is occupied, identify the existing process before stopping anything.
Do not start duplicate services or rerun frozen experiments simply to start the lab.

## Verify Operation

Application health endpoints use ports 8100, 8200, 8300, and 8400.
Detector metrics use port 8500.

Verify collector and detector scrape health, detector query and delivery health,
successful-poll freshness, collector buffering, and pending-outbox counts.

Health endpoints alone do not establish successful detection or storage.

Grafana is at http://127.0.0.1:3000 using the local lab-admin account.
This is separate from Grafana Cloud. Do not place its password in commands,
screenshots, evidence, or repository files.

## Graceful Shutdown

1. Stop inference and the operator API with Ctrl+C to prevent new application events.
2. Keep the collector, Loki, detector, and receiver running while checking backlog.
3. Allow the collector buffer to drain to zero.
4. Allow queued findings to receive storage acknowledgments where possible.
   If delivery cannot complete, record the pending count and preserve the outbox.
5. Stop the detector, then receiver, then collector with Ctrl+C.
6. Check project listeners:

```bash
lsof -nP -iTCP:8100 -iTCP:8200 -iTCP:8300 -iTCP:8400 -iTCP:8500 -sTCP:LISTEN
```

Investigate remaining processes before terminating them. A pipeline using tee
can leave its Python process running.

7. Stop monitoring containers while preserving volumes:

```bash
docker compose down
docker compose ps
```

8. Quit Docker Desktop when other workloads do not need it.
9. Optionally run deactivate in the terminal.

Deactivating a venv does not stop processes. Collector termination loses pending
memory. Durable outbox recovery protects queued findings, not unobserved events.

## Optional Destructive Cleanup

Only after evidence export and review:

```bash
docker compose down --volumes
```

This deletes monitoring volumes, but not host-side credentials or SQLite files.
Do not perform destructive cleanup during the final audit.

## Residual Risks

Vendor container findings remain unresolved. Loki is unauthenticated, and direct
writes bypass collector controls. This is a controlled local laboratory.

See [Container Review](validation/container-dependency-review.md),
[Telemetry Integrity](telemetry-integrity.md), and
[Residual Risks](residual-risks.md).

## Observed Shutdown Failure and Recovery

During the restart exercise, Docker could not stop Grafana because it reported
a zombie container process. Prometheus and Loki were removed successfully.

The failed shutdown was preserved as incomplete evidence. Docker Desktop was
restarted, after which the remaining Grafana container and project network
were removed without requesting volume deletion.

Grafana was subsequently configured with init: true. One controlled stop
completed with exit code 0, and Grafana restarted healthy.

This observation does not establish that init was the sole cause of recovery
or that the failure cannot recur.

For recurrence:

1. Preserve the error and check which project services remain.
2. Record pending telemetry and finding state where available.
3. Restart Docker Desktop, accounting for interruption of other Docker workloads.
4. Verify the engine responds before retrying docker compose down.
5. Do not reset Docker Desktop or delete volumes as a routine recovery step.
6. Verify actual stopped state before recording a successful shutdown.

See the [restart assessment](../evidence/public/service-restart-assessment.json).
