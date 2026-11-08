"""W5 persistent-computer eight-hour soak harness.

Runs against a dedicated disposable PostgreSQL host. It repeatedly launches a real
Chromium persistent context against a loopback fixture, renews a durable fenced
workspace lease, exercises quota reservation/settlement, and persists its progress
atomically so a systemd process restart and one host reboot can resume the same soak.

This is feasibility evidence only. It does not certify production isolation.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from tinlance_agent_platform_budgets import (
    PostgresQuotaLedger,
    QuotaReservationRequest,
    QuotaSettlement,
)
from tinlance_agent_platform_durability import (
    PostgresWorkspaceLeaseStore,
    WorkspaceLease,
)
from tinlance_agent_platform_sandbox import BrowserProfileLease


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = (
            b"<!doctype html><html><head><meta charset='utf-8'></head>"
            b"<body><main id='w5'>Tinlance W5 persistent profile fixture</main></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        return


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(encoded + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    os.chmod(path, 0o600)


def _read_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("W5 state file is not a JSON object")
    return value


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise RuntimeError("host boot identity is unavailable")
    return value


def _lease_from_state(value: dict[str, Any]) -> WorkspaceLease:
    lease = value.get("lease")
    if not isinstance(lease, dict):
        raise ValueError("W5 state does not contain a durable lease")
    return WorkspaceLease(
        tenant_id=UUID(str(lease["tenant_id"])),
        workspace_id=UUID(str(lease["workspace_id"])),
        lease_id=UUID(str(lease["lease_id"])),
        owner_subject_id=str(lease["owner_subject_id"]),
        worker_id=str(lease["worker_id"]),
        fencing_token=int(lease["fencing_token"]),
        expires_at=datetime.fromisoformat(str(lease["expires_at"])),
    )


def _save_lease(state: dict[str, Any], lease: WorkspaceLease) -> None:
    state["lease"] = {
        "tenant_id": str(lease.tenant_id),
        "workspace_id": str(lease.workspace_id),
        "lease_id": str(lease.lease_id),
        "owner_subject_id": lease.owner_subject_id,
        "worker_id": lease.worker_id,
        "fencing_token": lease.fencing_token,
        "expires_at": lease.expires_at.isoformat(),
    }


def _open_or_recover_lease(
    store: PostgresWorkspaceLeaseStore,
    state: dict[str, Any],
    tenant_id: UUID,
    workspace_id: UUID,
    owner: str,
    worker: str,
    *,
    force_reacquire: bool = False,
) -> WorkspaceLease:
    if state.get("lease"):
        prior = _lease_from_state(state)
        if store.assert_active(prior) and not force_reacquire:
            return prior
        if store.assert_active(prior) and force_reacquire:
            if not store.revoke(prior):
                raise RuntimeError("host-restart fencing could not revoke the prior lease")
        state["stale_lease_rejected"] = True
    lease = store.acquire(
        tenant_id,
        workspace_id,
        owner,
        worker,
        lease_seconds=900,
    )
    if lease is None:
        raise RuntimeError("workspace lease is still owned by another live worker")
    _save_lease(state, lease)
    return lease


def _quota_cycle(
    dsn: str,
    tenant_id: UUID,
    agent_id: UUID,
    run_id: UUID,
    workspace_id: UUID,
    iteration: int,
) -> None:
    import psycopg

    key = f"w5-soak-reservation-{iteration:08d}"
    denied_key = f"w5-soak-denied-{iteration:08d}"
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "SELECT set_config('platform.tenant_id', %s, true)",
            (str(tenant_id),),
        )
        ledger = PostgresQuotaLedger(connection)
        request = QuotaReservationRequest(
            tenant_id=tenant_id,
            agent_id=agent_id,
            run_id=run_id,
            action="w5.browser-session",
            resource=f"workspace:{workspace_id}",
            idempotency_key=key,
            concurrency=1,
            tool_calls=1,
            token_units=1,
            cost_units=0.000001,
        )
        reservation_id = ledger.reserve_new(request)

        # A second concurrent reservation must be denied while the first holds
        # the tenant's single concurrency slot. The savepoint keeps the outer
        # reservation transaction usable after the expected quota exception.
        denied = False
        try:
            with connection.transaction():
                ledger.reserve(
                    QuotaReservationRequest(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        run_id=run_id,
                        action="w5.browser-session",
                        resource=f"workspace:{workspace_id}",
                        idempotency_key=denied_key,
                        concurrency=1,
                        tool_calls=0,
                        token_units=0,
                        cost_units=0.0,
                    )
                )
        except psycopg.Error as exc:
            if exc.sqlstate != "P0001":
                raise
            denied = True
        if not denied:
            raise RuntimeError("tenant concurrency quota admitted a second active reservation")

        ledger.settle(
            tenant_id=tenant_id,
            reservation_id=reservation_id,
            actual=QuotaSettlement(
                tool_calls=1,
                token_units=1,
                cost_units=0.000001,
                evidence={"measurement_ref": f"w5-soak:{iteration}"},
            ),
        )
        connection.commit()


def _browser_cycle(
    profile_root: Path,
    tenant_id: str,
    workspace_id: str,
    expected_marker: str | None,
    marker: str,
    fixture_url: str,
) -> None:
    from playwright.sync_api import sync_playwright

    with BrowserProfileLease.acquire(profile_root, tenant_id, workspace_id) as lease:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(lease.profile_path),
                headless=True,
                chromium_sandbox=True,
                accept_downloads=False,
                service_workers="block",
                args=["--disable-dev-shm-usage", "--no-first-run"],
            )
            try:
                page = context.new_page()
                response = page.goto(fixture_url, wait_until="domcontentloaded", timeout=15_000)
                if response is None or response.status != 200:
                    raise RuntimeError("local browser persistence fixture did not load")
                actual_marker = page.evaluate("() => localStorage.getItem('w5-soak-marker')")
                if actual_marker != expected_marker:
                    raise RuntimeError(
                        "persistent browser profile marker was lost or changed across restart"
                    )
                page.evaluate(
                    "(value) => localStorage.setItem('w5-soak-marker', value)",
                    marker,
                )
                page.evaluate(
                    "(value) => localStorage.setItem('w5-soak-heartbeat', value)",
                    _utc_now(),
                )
            finally:
                context.close()


def _schedule_systemd_action(unit: str, action: list[str]) -> None:
    command = [
        "sudo",
        "-n",
        "systemd-run",
        "--on-active=15s",
        f"--unit={unit}",
        "--collect",
        *action,
    ]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)


def run_soak(args: argparse.Namespace) -> dict[str, Any]:
    import psycopg

    tenant_id = UUID(args.tenant_id)
    workspace_id = UUID(args.workspace_id)
    agent_id = UUID(args.agent_id)
    run_id = UUID(args.run_id)
    state_path = Path(args.state_file).resolve()
    profile_root = Path(args.profile_root).resolve()
    evidence_path = Path(args.evidence).resolve()
    dsn = os.environ.get("W5_DATABASE_URL", "")
    if not dsn:
        raise ValueError("W5_DATABASE_URL is required")
    if os.geteuid() == 0:
        raise RuntimeError("W5 browser soak must run as a dedicated non-root user")
    if args.duration_seconds < 600 or args.interval_seconds < 10:
        raise ValueError("soak duration must be >=600 seconds and interval >=10 seconds")

    state = _read_state(state_path)
    if state.get("status") == "passed":
        return state
    if state.get("status") == "failed":
        raise RuntimeError("a prior W5 soak attempt failed; preserve evidence and reset explicitly")

    now = time.time()
    if "started_epoch" not in state:
        state.update(
            {
                "schema_version": 1,
                "phase": "W5",
                "status": "running",
                "started_epoch": now,
                "started_at": _utc_now(),
                "process_start_count": 0,
                "host_restart_count": 0,
                "browser_cycles": 0,
                "quota_iterations": 0,
                "quota_denials": 0,
                "process_restart_scheduled": False,
                "host_reboot_scheduled": False,
                "revocation_completed": False,
                "expiry_completed": False,
                "browser_marker": None,
                "boot_ids": [],
                "workspace_event_count_start": 0,
                "quota_event_count_start": 0,
            }
        )
    state["process_start_count"] = int(state.get("process_start_count", 0)) + 1
    current_boot = _boot_id()
    previous_boot = state.get("last_boot_id")
    if previous_boot and previous_boot != current_boot:
        state["host_restart_count"] = int(state.get("host_restart_count", 0)) + 1
    if current_boot not in state.setdefault("boot_ids", []):
        state["boot_ids"].append(current_boot)
    state["last_boot_id"] = current_boot

    store = PostgresWorkspaceLeaseStore(connection_factory=lambda: psycopg.connect(dsn))
    owner = "tinlance-w5-soak"
    worker = f"w5-worker-{current_boot[:12]}"
    lease = _open_or_recover_lease(
        store,
        state,
        tenant_id,
        workspace_id,
        owner,
        worker,
        force_reacquire=bool(previous_boot and previous_boot != current_boot),
    )
    _save_lease(state, lease)

    with psycopg.connect(dsn) as connection:
        connection.execute(
            "SELECT set_config('platform.tenant_id', %s, true)",
            (str(tenant_id),),
        )
        state["workspace_event_count_start"] = connection.execute(
            "SELECT count(*) FROM platform.workspace_lease_events "
            "WHERE tenant_id = %s AND workspace_id = %s",
            (tenant_id, workspace_id),
        ).fetchone()[0]
        state["quota_event_count_start"] = connection.execute(
            "SELECT count(*) FROM platform.quota_ledger WHERE tenant_id = %s AND run_id = %s",
            (tenant_id, run_id),
        ).fetchone()[0]

    fixture = ThreadingHTTPServer(("127.0.0.1", args.fixture_port), _FixtureHandler)
    fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
    fixture_thread.start()
    fixture_url = f"http://127.0.0.1:{args.fixture_port}/"
    _atomic_json(state_path, state)

    try:
        while True:
            elapsed = time.time() - float(state["started_epoch"])
            if elapsed >= args.duration_seconds:
                break

            if not store.assert_active(lease):
                raise RuntimeError("workspace lease lost before the next soak operation")
            renewed = store.renew(lease, lease_seconds=900)
            lease = WorkspaceLease(
                tenant_id=lease.tenant_id,
                workspace_id=lease.workspace_id,
                lease_id=lease.lease_id,
                owner_subject_id=lease.owner_subject_id,
                worker_id=lease.worker_id,
                fencing_token=lease.fencing_token,
                expires_at=renewed,
            )
            _save_lease(state, lease)

            iteration = int(state["browser_cycles"]) + 1
            pending_marker = state.get("pending_browser_marker")
            marker = str(pending_marker if pending_marker is not None else iteration)
            if pending_marker is None:
                state["pending_browser_marker"] = marker
                _atomic_json(state_path, state)
            _browser_cycle(
                profile_root,
                str(tenant_id),
                str(workspace_id),
                state.get("browser_marker"),
                marker,
                fixture_url,
            )
            _quota_cycle(dsn, tenant_id, agent_id, run_id, workspace_id, iteration)
            state["browser_marker"] = marker
            state.pop("pending_browser_marker", None)
            state["browser_cycles"] = iteration
            state["quota_iterations"] = int(state["quota_iterations"]) + 1
            state["quota_denials"] = int(state["quota_denials"]) + 1
            state["last_heartbeat_at"] = _utc_now()
            _atomic_json(state_path, state)

            if (
                elapsed >= args.duration_seconds * 0.25
                and not state["process_restart_scheduled"]
            ):
                state["process_restart_scheduled"] = True
                _atomic_json(state_path, state)
                _schedule_systemd_action(
                    "tinlance-w5-process-restart",
                    ["/usr/bin/systemctl", "restart", "tinlance-w5-soak.service"],
                )

            if (
                elapsed >= args.duration_seconds * 0.50
                and not state["host_reboot_scheduled"]
            ):
                state["host_reboot_scheduled"] = True
                _atomic_json(state_path, state)
                _schedule_systemd_action(
                    "tinlance-w5-host-reboot",
                    ["/usr/bin/systemctl", "reboot"],
                )

            if (
                elapsed >= args.duration_seconds * 0.70
                and not state["expiry_completed"]
            ):
                expiry_workspace = UUID(args.expiry_workspace_id)
                short_lease = store.acquire(
                    tenant_id,
                    expiry_workspace,
                    owner,
                    "w5-expiry-probe",
                    lease_seconds=60,
                )
                if short_lease is None:
                    raise RuntimeError("could not acquire independent expiry probe lease")
                time.sleep(65)
                if store.assert_active(short_lease):
                    raise RuntimeError("expired workspace lease still passed active assertion")
                replacement = store.acquire(
                    tenant_id,
                    expiry_workspace,
                    owner,
                    "w5-expiry-recovery",
                    lease_seconds=600,
                )
                if replacement is None or replacement.fencing_token <= short_lease.fencing_token:
                    raise RuntimeError("expired lease did not recover with a higher fencing token")
                if store.assert_active(short_lease):
                    raise RuntimeError("stale expiry-probe worker passed after reacquisition")
                if not store.release(replacement):
                    raise RuntimeError("expiry recovery lease cleanup failed")
                state["expiry_completed"] = True
                state["expiry_fencing_token"] = replacement.fencing_token
                _atomic_json(state_path, state)

            if (
                elapsed >= args.duration_seconds * 0.80
                and not state["revocation_completed"]
            ):
                if not store.revoke(lease):
                    raise RuntimeError("active workspace lease was not explicitly revoked")
                if store.assert_active(lease):
                    raise RuntimeError("revoked workspace lease still passed active assertion")
                replacement = store.acquire(
                    tenant_id,
                    workspace_id,
                    owner,
                    "w5-worker-after-revocation",
                    lease_seconds=900,
                )
                if replacement is None or replacement.fencing_token <= lease.fencing_token:
                    raise RuntimeError("revocation recovery did not advance the fencing token")
                if store.assert_active(lease):
                    raise RuntimeError("revoked stale worker passed after reacquisition")
                lease = replacement
                _save_lease(state, lease)
                state["revocation_completed"] = True
                state["revocation_fencing_token"] = replacement.fencing_token
                _atomic_json(state_path, state)

            time.sleep(max(0.0, args.interval_seconds - (time.time() - now)))
            now = time.time()

        if state["process_start_count"] < 2:
            raise RuntimeError("planned supervisor process restart was not observed")
        if state["host_restart_count"] < 1:
            raise RuntimeError("planned host reboot was not observed")
        if not state["expiry_completed"] or not state["revocation_completed"]:
            raise RuntimeError("lease expiry/revocation acceptance probes did not complete")

        if not store.assert_active(lease):
            raise RuntimeError("workspace lease was not active at final cleanup")
        if not store.release(lease):
            raise RuntimeError("workspace lease release did not commit")
        if store.assert_active(lease):
            raise RuntimeError("released workspace lease still passed active assertion")

        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join(timeout=5)
        import shutil

        shutil.rmtree(profile_root, ignore_errors=False)
        if profile_root.exists():
            raise RuntimeError("persistent browser profile cleanup left residual files")

        with psycopg.connect(dsn) as connection:
            connection.execute(
                "SELECT set_config('platform.tenant_id', %s, true)",
                (str(tenant_id),),
            )
            workspace_events = connection.execute(
                "SELECT count(*) FROM platform.workspace_lease_events "
                "WHERE tenant_id = %s AND workspace_id = %s",
                (tenant_id, workspace_id),
            ).fetchone()[0]
            quota_events = connection.execute(
                "SELECT count(*) FROM platform.quota_ledger "
                "WHERE tenant_id = %s AND run_id = %s",
                (tenant_id, run_id),
            ).fetchone()[0]

        if workspace_events <= int(state["workspace_event_count_start"]):
            raise RuntimeError("workspace lease audit history did not advance")
        if quota_events < int(state["quota_event_count_start"]) + 2 * int(state["quota_iterations"]):
            raise RuntimeError("quota reservation/settlement audit continuity is incomplete")

        state.update(
            {
                "status": "passed",
                "finished_at": _utc_now(),
                "elapsed_seconds": round(time.time() - float(state["started_epoch"]), 3),
                "workspace_event_count_end": workspace_events,
                "quota_event_count_end": quota_events,
                "browser_profile_persistence": True,
                "lease_renewal_expiry_revocation_fencing": True,
                "quota_admission_and_settlement": True,
                "append_only_audit_continuity": True,
                "process_restart_verified": state["process_start_count"] >= 2,
                "host_restart_verified": state["host_restart_count"] >= 1,
                "cleanup_verified": not profile_root.exists(),
                "production_certification": False,
            }
        )
        _atomic_json(state_path, state)
        evidence_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _atomic_json(evidence_path, state)
        return state
    except BaseException as exc:
        state.update({"status": "failed", "failed_at": _utc_now(), "failure": str(exc)[:1024]})
        _atomic_json(state_path, state)
        _atomic_json(evidence_path, state)
        raise
    finally:
        fixture.shutdown()
        fixture.server_close()
        fixture_thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the W5 continuous persistent-computer soak.")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--expiry-workspace-id", required=True)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state-file", default="/var/lib/tinlance-w5/state.json")
    parser.add_argument("--profile-root", default="/var/lib/tinlance-w5/profiles")
    parser.add_argument("--evidence", default="/var/lib/tinlance-w5/evidence.json")
    parser.add_argument("--duration-seconds", type=int, default=28_800)
    parser.add_argument("--interval-seconds", type=int, default=300)
    parser.add_argument("--fixture-port", type=int, default=18765)
    args = parser.parse_args()
    result = run_soak(args)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
