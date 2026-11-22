"""扫描历史(SQLite):写入、裁剪、取上一次基线、统计。"""

from app.core.history import HistoryStore


def snapshot(job_id, finished, subs, domain="example.com", plan="basic", score=0):
    return {
        "domain": domain,
        "plan": plan,
        "job_id": job_id,
        "finished_at": finished,
        "risk_score": score,
        "degraded": False,
        "total_found": len(subs),
        "total_live": 0,
        "subdomains": list(subs),
        "live_urls": [],
        "takeover_domains": [],
        "ip_assets": [],
    }


async def _store(tmp_path, max_per_domain=10):
    store = HistoryStore(
        path=str(tmp_path / "h.db"), enabled=True, max_per_domain=max_per_domain
    )
    await store.init()
    assert store.enabled is True
    return store


async def test_previous_returns_latest_other_job(tmp_path):
    store = await _store(tmp_path)
    await store.record(snapshot("job-1", 100.0, ["a.x.com"]))
    await store.record(snapshot("job-2", 200.0, ["a.x.com", "b.x.com"]))

    prev = await store.previous("example.com", "basic", "job-2")
    assert prev is not None
    assert prev["job_id"] == "job-1"

    # 语义是"最近一次**不是这条**的扫描"。差异对比总是在任务刚完成时调用,
    # 那时当前 job 就是最新的,因此等价于"上一次"。
    newer = await store.previous("example.com", "basic", "job-1")
    assert newer is not None and newer["job_id"] == "job-2"

    # 库里只有这一次扫描时,没有基线
    single = await _store(tmp_path / "single")
    await single.record(snapshot("only", 1.0, ["a.x.com"]))
    assert await single.previous("example.com", "basic", "only") is None
    await single.close()
    await store.close()


async def test_plan_is_part_of_the_key(tmp_path):
    """Pro 与 Basic 的历史不能互相成为基线 —— 两者的字段集不同。"""
    store = await _store(tmp_path)
    await store.record(snapshot("job-basic", 100.0, ["a.x.com"], plan="basic"))

    assert await store.previous("example.com", "pro", "job-pro") is None
    assert await store.previous("example.com", "basic", "job-pro") is not None
    await store.close()


async def test_recent_is_newest_first_and_light(tmp_path):
    store = await _store(tmp_path)
    for i in range(3):
        await store.record(snapshot(f"job-{i}", 100.0 + i, [f"s{i}.x.com"], score=i * 10))

    rows = await store.recent("example.com")
    assert [r["job_id"] for r in rows] == ["job-2", "job-1", "job-0"]
    assert rows[0]["risk_score"] == 20
    assert "snapshot" not in rows[0]
    await store.close()


async def test_pruning_keeps_only_max_per_domain(tmp_path):
    store = await _store(tmp_path, max_per_domain=2)
    for i in range(5):
        await store.record(snapshot(f"job-{i}", 100.0 + i, [f"s{i}.x.com"]))

    rows = await store.recent("example.com")
    assert len(rows) == 2
    assert {r["job_id"] for r in rows} == {"job-3", "job-4"}
    await store.close()


async def test_domains_are_isolated(tmp_path):
    store = await _store(tmp_path)
    await store.record(snapshot("a1", 1.0, ["x.a.com"], domain="a.com"))
    await store.record(snapshot("b1", 2.0, ["x.b.com"], domain="b.com"))

    assert (await store.previous("a.com", "basic", "a2"))["job_id"] == "a1"
    assert await store.previous("c.com", "basic", "c1") is None
    await store.close()


async def test_stats_counts_scans_and_domains(tmp_path):
    store = await _store(tmp_path)
    await store.record(snapshot("a1", 1.0, [], domain="a.com"))
    await store.record(snapshot("a2", 2.0, [], domain="a.com"))
    await store.record(snapshot("b1", 3.0, [], domain="b.com"))

    stats = await store.stats()
    assert stats["scans"] == 3
    assert stats["domains"] == 2
    await store.close()


async def test_disabled_store_is_a_silent_no_op(tmp_path):
    store = HistoryStore(path=str(tmp_path / "off.db"), enabled=False, max_per_domain=5)
    await store.init()
    await store.record(snapshot("job-1", 1.0, ["a.x.com"]))

    assert await store.previous("example.com", "basic", "job-2") is None
    assert await store.recent("example.com") == []
    assert await store.stats() == {"scans": 0, "domains": 0}
    await store.close()


async def test_unwritable_path_disables_instead_of_raising(tmp_path):
    """历史是增强功能:数据库打不开时服务必须还能跑。"""
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")
    store = HistoryStore(
        path=str(blocker / "h.db"), enabled=True, max_per_domain=5
    )
    await store.init()
    assert store.enabled is False
    await store.record(snapshot("job-1", 1.0, []))
    assert await store.stats() == {"scans": 0, "domains": 0}
