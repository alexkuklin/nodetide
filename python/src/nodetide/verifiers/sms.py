"""The SMS queue between the verification service and an SMS gateway.

The service never talks to a modem. It queues messages; a gateway (a script next to a modem, possibly behind NAT)
fetches them over HTTPS with a bearer token, sends them, and reports the outcome. Queue entries are leased: an
entry that is fetched but not reported comes back after `lease_seconds`, at most `max_attempts` times.
Everything is in memory: a restart drops pending codes, which then simply expire for the person too.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Callable

QUEUED, LEASED, SENT, FAILED = "queued", "leased", "sent", "failed"
MAX_QUEUE = 200


@dataclass
class SmsJob:
    id: str
    to: str
    text: str
    expires_at: float
    state: str = QUEUED
    attempts: int = 0
    lease_until: float = 0.0
    error: str = ""


class OutboxFull(Exception):
    pass


class SmsOutbox:
    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        lease_seconds: int = 120,
        max_attempts: int = 2,
        max_queue: int = MAX_QUEUE,
    ):
        self._clock, self.lease_seconds, self.max_attempts, self.max_queue = clock, lease_seconds, max_attempts, max_queue
        self._jobs: dict[str, SmsJob] = {}
        self._wake = asyncio.Event()

    def enqueue(self, to: str, text: str, ttl: int) -> SmsJob:
        self.cleanup()
        if sum(1 for j in self._jobs.values() if j.state in (QUEUED, LEASED)) >= self.max_queue:
            raise OutboxFull()
        job = SmsJob(id=secrets.token_urlsafe(16), to=to, text=text, expires_at=self._clock() + ttl)
        self._jobs[job.id] = job
        self._wake.set()
        return job

    def lease(self, limit: int = 5) -> list[SmsJob]:
        """Hand out queued jobs (and those whose lease ran out) to the gateway."""
        now = self._clock()
        out: list[SmsJob] = []
        for job in self._jobs.values():
            if len(out) >= limit:
                break
            if job.expires_at <= now:
                continue
            expired_lease = job.state == LEASED and job.lease_until <= now
            if job.state == QUEUED or expired_lease:
                if job.attempts >= self.max_attempts:
                    job.state, job.error = FAILED, job.error or "gateway_no_answer"
                    continue
                job.state, job.attempts, job.lease_until = LEASED, job.attempts + 1, now + self.lease_seconds
                out.append(job)
        return out

    async def wait_for_work(self, timeout: float) -> None:
        """Sleep until something is enqueued, or `timeout` seconds pass."""
        self._wake.clear()
        try:
            await asyncio.wait_for(self._wake.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    def report(self, job_id: str, status: str, error: str = "") -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.state not in (LEASED, QUEUED):
            return False
        job.state = SENT if status == "sent" else FAILED
        job.error = "" if job.state == SENT else (error or status)[:64]
        return True

    def get(self, job_id: str) -> SmsJob | None:
        return self._jobs.get(job_id)

    def cleanup(self) -> None:
        now = self._clock()
        for job_id in [i for i, j in self._jobs.items() if j.expires_at + 3600 < now]:
            del self._jobs[job_id]
