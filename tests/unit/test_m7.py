from uuid import uuid4

from tinlance_agent_platform_trajectory.chain import InMemoryTrajectoryStore


def test_trajectory_is_hash_chained() -> None:
    store = InMemoryTrajectoryStore()
    run_id = uuid4()
    first = store.append("t1", run_id, "run.started", "ok")
    second = store.append("t1", run_id, "tool.called", "search")
    assert first.previous_hash == "GENESIS"
    assert second.previous_hash == first.event_hash
    assert store.verify("t1", run_id)
