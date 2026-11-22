"""job 存储:原子占坑、去重索引释放、TTL 清理、容量淘汰。"""

import time

from app.core.jobs import Job, JobStore


def make_job(job_id: str, domain: str = "example.com", plan: str = "basic") -> Job:
    return Job(job_id=job_id, domain_key=domain, plan=plan, status="queued", created_at=time.time())


async def test_reserve_is_exclusive():
    store = JobStore(maxsize=8, ttl=60)
    assert await store.reserve_active("example.com", "basic", "job-a") is None
    # 第二次占坑必须拿到已有的 job_id,而不是再开一个
    assert await store.reserve_active("example.com", "basic", "job-b") == "job-a"
    assert await store.find_active("example.com", "basic") == "job-a"
    # 不同计划互不影响
    assert await store.reserve_active("example.com", "pro", "job-c") is None


async def test_release_only_own_slot():
    store = JobStore(maxsize=8, ttl=60)
    await store.reserve_active("example.com", "basic", "job-a")
    # 别的任务不能把 job-a 的坑位删掉
    await store.release_active("example.com", "basic", "job-x")
    assert await store.find_active("example.com", "basic") == "job-a"
    await store.release_active("example.com", "basic", "job-a")
    assert await store.find_active("example.com", "basic") is None


async def test_get_drops_expired_finished_job():
    store = JobStore(maxsize=8, ttl=10)
    job = make_job("job-a")
    job.status = "completed"
    job.finished_at = time.time() - 11
    await store.add(job)
    assert await store.get("job-a") is None
    # 过期即清,连去重索引一起释放
    assert await store.find_active("example.com", "basic") is None


async def test_running_job_is_not_ttl_evicted():
    store = JobStore(maxsize=8, ttl=10)
    job = make_job("job-a")  # 未完成,finished_at 为 None
    job.created_at = time.time() - 1000
    await store.add(job)
    assert await store.get("job-a") is job


async def test_add_respects_maxsize_and_releases_index():
    store = JobStore(maxsize=2, ttl=60)
    await store.reserve_active("a.com", "basic", "job-a")
    job_a = make_job("job-a", "a.com")
    job_a.created_at = 1.0
    job_a.status = "completed"
    job_a.finished_at = 1.5
    await store.add(job_a)

    await store.reserve_active("b.com", "basic", "job-b")
    job_b = make_job("job-b", "b.com")
    job_b.created_at = 2.0
    await store.add(job_b)

    await store.reserve_active("c.com", "basic", "job-c")
    job_c = make_job("job-c", "c.com")
    job_c.created_at = 3.0
    await store.add(job_c)  # 超限,淘汰最老的**终结**任务 job-a

    assert await store.get("job-a") is None
    assert await store.get("job-b") is job_b
    # 被淘汰的 job 其占坑索引必须一并释放,否则该域名永远无法再发起扫描
    assert await store.find_active("a.com", "basic") is None


async def test_inflight_jobs_are_never_evicted():
    """容量打满且全在跑时,宁可暂时超限,也不能让正在轮询的任务突然 404。"""
    store = JobStore(maxsize=1, ttl=60)
    running = make_job("job-run", "a.com")
    running.status = "running"
    await store.add(running)

    queued = make_job("job-queued", "b.com")
    await store.add(queued)  # 超限,但没有终结任务可淘汰

    assert await store.get("job-run") is running
    assert await store.get("job-queued") is queued
    # 一旦有任务终结,下一次写入就会把它淘汰掉,内存最终能回收
    running.status = "completed"
    running.finished_at = time.time()
    await store.add(make_job("job-third", "c.com"))
    assert await store.get("job-run") is None


async def test_stats_counts_states():
    store = JobStore(maxsize=8, ttl=60)
    await store.add(make_job("job-a", "a.com"))
    done = make_job("job-b", "b.com")
    done.status = "completed"
    done.finished_at = time.time()
    await store.add(done)

    stats = await store.stats()
    assert stats["queued"] == 1
    assert stats["completed"] == 1
    assert stats["total"] == 2
    assert stats["inflight"] == 1
