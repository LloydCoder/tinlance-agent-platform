from __future__ import annotations

from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "fcp03_linux_dns_egress_lab.sh"
)


def test_dns_readiness_probe_does_not_close_dig_pipe_early() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert (
        'dig @10.203.0.1 allowed.test A +time=1 +tries=1 +short 2>/dev/null '
        '| grep -Fxq "10.203.0.10"'
    ) not in source
    assert (
        'ready_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 allowed.test A '
        '+time=1 +tries=1 +short 2>/dev/null)"'
    ) in source
    assert 'if [[ "$ready_answer" == "10.203.0.10" ]]; then' in source
