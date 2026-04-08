"""Redis 8 storage backend — for distributed, high-throughput deployments.

Leverages Redis 8 native data structures for maximum performance:

- **JSON**: Structured storage for IP reputation and banned email records
  with field-level atomic updates and secondary indexing.
- **Time Series**: Registration activity timeline with native downsampling
  and efficient compression (replaces manual SQL/code-based bucketing).
- **Bloom Filter**: O(1) probabilistic pre-filter for banned email lookups —
  eliminates unnecessary roundtrips for clean emails.
- **Count-Min Sketch**: Approximate IP registration frequency tracking
  without per-IP counters.
- **Top-K**: Real-time identification of most active IPs for the dashboard.
- **Query Engine**: Secondary indexes on JSON documents for efficient
  aggregate statistics (status counts, registration totals).
- **Sliding-window rate limiting**: Distributed, atomic, multi-instance
  rate limiting via Lua scripts and sorted sets.
- **AI score cache**: JSON documents with TTL for sharing OpenRouter
  response cache across instances.

Requires::

    pip install guardpost[redis]

Usage::

    from guardpost.storage.redis import RedisStorage

    storage = RedisStorage("redis://localhost:6379")
    await storage.initialize()
"""

from __future__ import annotations

import logging
import time
import uuid

from guardpost.email.banned import BannedEmailRecord
from guardpost.fraud.patterns import Registration
from guardpost.ip.reputation import IPReputationRecord

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key layout
# ---------------------------------------------------------------------------
_IP_KEY = "gp:ip:"  # JSON documents (keyed by IP)
_BAN_KEY = "gp:ban:"  # JSON documents (keyed by email hash)
_REG_KEY = "gp:reg:"  # JSON documents (keyed by sequential ID)
_REG_IDX = "gp:reg:idx"  # Sorted set (score=timestamp, member=reg key)
_REG_SEQ = "gp:reg:seq"  # Counter for registration IDs
_TS_REGS = "gp:ts:regs"  # TimeSeries — raw registration events
_TS_REGS_1M = "gp:ts:regs:1m"  # TimeSeries — 1-minute compacted
_BF_BANS = "gp:bf:banned"  # Bloom filter for banned email hashes
_CMS_IP = "gp:cms:ip_freq"  # Count-Min Sketch for IP frequency
_TOPK_IP = "gp:topk:ips"  # Top-K most active registration IPs
_RL_KEY = "gp:rl:"  # Rate limiter sorted sets
_AI_CACHE = "gp:ai:"  # AI score cache (JSON with TTL)
_IP_IDX = "gp:idx:ip"  # Search index on IP reputation docs
_STATS_BANNED = "gp:stats:banned_count"  # Atomic counter

# ---------------------------------------------------------------------------
# Lua script for atomic sliding-window rate limiting
# ---------------------------------------------------------------------------
_RATE_LIMIT_LUA = """\
local key   = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local uid    = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, uid)
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return 1
end
redis.call('EXPIRE', key, math.ceil(window) + 1)
return 0
"""


class RedisStorage:
    """Async Redis 8 storage backend using ``redis-py`` ≥ 5.2.

    Implements the full :class:`~guardpost.storage.base.StorageBackend`
    protocol plus distributed rate limiting, AI score caching, and
    probabilistic analytics powered by Redis 8 modules.

    Args:
        url: Redis connection URL (e.g. ``redis://localhost:6379``).
        bloom_capacity: Expected number of banned emails for Bloom filter
            sizing (default: 100 000).
        bloom_error_rate: Bloom filter false-positive rate (default: 0.01).
        topk_size: Number of top IPs to track (default: 100).
        cms_width: Count-Min Sketch width (default: 2000).
        cms_depth: Count-Min Sketch depth (default: 5).
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379",
        *,
        bloom_capacity: int = 100_000,
        bloom_error_rate: float = 0.01,
        topk_size: int = 100,
        cms_width: int = 2000,
        cms_depth: int = 5,
    ) -> None:
        try:
            import redis.asyncio as aioredis  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "redis is required for Redis storage. "
                "Install it with: pip install guardpost[redis]"
            ) from exc

        self._url = url
        self._redis = aioredis.from_url(
            url, decode_responses=True, protocol=3,
        )
        self._bloom_capacity = bloom_capacity
        self._bloom_error_rate = bloom_error_rate
        self._topk_size = topk_size
        self._cms_width = cms_width
        self._cms_depth = cms_depth
        self._rl_script_sha: str | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Create indexes, probabilistic structures, and TimeSeries keys."""
        # Pre-load the rate-limit Lua script
        self._rl_script_sha = await self._redis.script_load(_RATE_LIMIT_LUA)

        # --- Bloom filter for banned emails ---
        try:
            await self._redis.bf().reserve(
                _BF_BANS, self._bloom_error_rate, self._bloom_capacity,
            )
        except Exception:
            pass  # already exists

        # --- Count-Min Sketch for IP frequency ---
        try:
            await self._redis.cms().initbydim(
                _CMS_IP, self._cms_width, self._cms_depth,
            )
        except Exception:
            pass

        # --- Top-K for most active IPs ---
        try:
            await self._redis.topk().reserve(
                _TOPK_IP, self._topk_size, 2000, 7, 0.9,
            )
        except Exception:
            pass

        # --- TimeSeries for registration counts ---
        try:
            await self._redis.ts().create(
                _TS_REGS,
                retention_msecs=7 * 24 * 3600 * 1000,  # 7-day retention
                duplicate_policy="sum",
                labels={"type": "registrations"},
            )
        except Exception:
            pass
        try:
            await self._redis.ts().create(
                _TS_REGS_1M,
                retention_msecs=30 * 24 * 3600 * 1000,  # 30-day compaction
                duplicate_policy="sum",
                labels={"type": "registrations", "agg": "1m"},
            )
            await self._redis.ts().createrule(
                _TS_REGS, _TS_REGS_1M, "sum", bucket_size_msec=60_000,
            )
        except Exception:
            pass

        # --- Query Engine index on IP reputation JSON docs ---
        try:
            from redis.commands.search.field import NumericField, TagField
            from redis.commands.search.indexDefinition import (
                IndexDefinition,
                IndexType,
            )

            await self._redis.ft(_IP_IDX).create_index(
                [
                    TagField("$.status", as_name="status"),
                    TagField(
                        "$.manually_whitelisted",
                        as_name="manually_whitelisted",
                    ),
                    NumericField(
                        "$.total_registrations",
                        as_name="total_registrations",
                    ),
                    NumericField(
                        "$.suspicious_registrations",
                        as_name="suspicious_registrations",
                    ),
                ],
                definition=IndexDefinition(
                    prefix=[_IP_KEY], index_type=IndexType.JSON,
                ),
            )
        except Exception:
            pass  # index already exists

        logger.info("Redis 8 storage initialized (%s)", self._url)

    async def close(self) -> None:
        await self._redis.aclose()

    # ------------------------------------------------------------------
    # IP Reputation  (JSON documents + Query Engine index)
    # ------------------------------------------------------------------

    async def get_ip_reputation(self, ip_address: str) -> IPReputationRecord | None:
        data = await self._redis.json().get(f"{_IP_KEY}{ip_address}")
        if data is None:
            return None
        return IPReputationRecord.from_dict(data)

    async def save_ip_reputation(self, record: IPReputationRecord) -> None:
        await self._redis.json().set(
            f"{_IP_KEY}{record.ip_address}", "$", record.to_dict(),
        )

    # ------------------------------------------------------------------
    # Banned Emails  (JSON + Bloom Filter pre-check)
    # ------------------------------------------------------------------

    async def is_email_banned(self, email_hash: str) -> bool:
        # Bloom filter fast path: definite-negative in O(1)
        if not await self._redis.bf().exists(_BF_BANS, email_hash):
            return False
        # Bloom says "maybe" — confirm with authoritative JSON doc
        return await self._redis.exists(f"{_BAN_KEY}{email_hash}") > 0

    async def get_banned_email(self, email_hash: str) -> BannedEmailRecord | None:
        data = await self._redis.json().get(f"{_BAN_KEY}{email_hash}")
        if data is None:
            return None
        return BannedEmailRecord.from_dict(data)

    async def save_banned_email(self, record: BannedEmailRecord) -> None:
        key = f"{_BAN_KEY}{record.normalized_email_hash}"
        is_new = not await self._redis.exists(key)
        await self._redis.json().set(key, "$", record.to_dict())
        await self._redis.bf().add(_BF_BANS, record.normalized_email_hash)
        if is_new:
            await self._redis.incr(_STATS_BANNED)

    async def delete_banned_email(self, email_hash: str) -> bool:
        # Bloom filter entry remains (false-positive on future checks just
        # triggers a JSON lookup that returns None — acceptable trade-off)
        result = await self._redis.delete(f"{_BAN_KEY}{email_hash}")
        if result > 0:
            await self._redis.decr(_STATS_BANNED)
            return True
        return False

    # ------------------------------------------------------------------
    # Registrations  (JSON + Sorted Set index + TimeSeries + CMS + TopK)
    # ------------------------------------------------------------------

    async def save_registration(self, registration: Registration) -> None:
        reg_id = await self._redis.incr(_REG_SEQ)
        key = f"{_REG_KEY}{reg_id}"
        data = registration.to_dict()

        # Core persistence (pipeline for single roundtrip)
        pipe = self._redis.pipeline(transaction=False)
        pipe.json().set(key, "$", data)
        pipe.zadd(_REG_IDX, {key: registration.timestamp})
        await pipe.execute()

        # Best-effort TimeSeries update
        try:
            ts_ms = int(registration.timestamp * 1000)
            await self._redis.ts().add(
                _TS_REGS, ts_ms, 1, duplicate_policy="sum",
            )
        except Exception:
            logger.debug("TimeSeries update failed", exc_info=True)

        # Best-effort probabilistic updates
        if registration.ip_address:
            try:
                await self._redis.cms().incrby(
                    _CMS_IP, [registration.ip_address], [1],
                )
            except Exception:
                logger.debug("CMS update failed", exc_info=True)
            try:
                await self._redis.topk().add(
                    _TOPK_IP, registration.ip_address,
                )
            except Exception:
                logger.debug("TopK update failed", exc_info=True)

    async def get_recent_registrations(self, since: float) -> list[Registration]:
        keys = await self._redis.zrangebyscore(_REG_IDX, since, "+inf")
        if not keys:
            return []
        pipe = self._redis.pipeline()
        for key in keys:
            pipe.json().get(key)
        results = await pipe.execute()
        registrations = []
        for data in results:
            if data is not None:
                registrations.append(Registration.from_dict(data))
        registrations.sort(key=lambda r: r.timestamp)
        return registrations

    async def purge_old_registrations(self, before: float) -> int:
        keys = await self._redis.zrangebyscore(_REG_IDX, "-inf", before)
        if not keys:
            return 0
        pipe = self._redis.pipeline()
        for key in keys:
            pipe.delete(key)
        pipe.zremrangebyscore(_REG_IDX, "-inf", before)
        await pipe.execute()
        return len(keys)

    async def get_registration_timeline(
        self, since: float, bucket_seconds: int = 3600,
    ) -> list[dict]:
        """Leverage Redis TimeSeries for native aggregated timeline."""
        since_ms = int(since * 1000)
        bucket_ms = bucket_seconds * 1000
        try:
            result = await self._redis.ts().range(
                _TS_REGS,
                from_time=since_ms,
                to_time="+",
                aggregation_type="sum",
                bucket_size_msec=bucket_ms,
            )
            return [
                {"t": ts / 1000, "count": int(val)}
                for ts, val in result
            ]
        except Exception:
            return await self._timeline_fallback(since, bucket_seconds)

    async def _timeline_fallback(
        self, since: float, bucket_seconds: int,
    ) -> list[dict]:
        from collections import Counter

        members = await self._redis.zrangebyscore(
            _REG_IDX, since, "+inf", withscores=True,
        )
        buckets: Counter[float] = Counter()
        for _, ts in members:
            bucket = int(ts / bucket_seconds) * bucket_seconds
            buckets[bucket] += 1
        return [{"t": t, "count": c} for t, c in sorted(buckets.items())]

    # ------------------------------------------------------------------
    # Stats  (Query Engine aggregations with SCAN fallback)
    # ------------------------------------------------------------------

    async def get_stats(self) -> dict:
        try:
            return await self._stats_via_search()
        except Exception:
            logger.debug(
                "Query Engine stats failed, using SCAN fallback",
                exc_info=True,
            )
            return await self._stats_via_scan()

    async def _stats_via_search(self) -> dict:
        from redis.commands.search import reducers
        from redis.commands.search.aggregation import AggregateRequest
        from redis.commands.search.query import Query

        ft = self._redis.ft(_IP_IDX)

        total_ips = (await ft.search(Query("*").paging(0, 0))).total
        graylisted = (
            await ft.search(Query("@status:{graylisted}").paging(0, 0))
        ).total
        blacklisted = (
            await ft.search(Query("@status:{blacklisted}").paging(0, 0))
        ).total
        whitelisted = (
            await ft.search(
                Query("@manually_whitelisted:{true}").paging(0, 0),
            )
        ).total

        # Aggregated registration totals
        agg_req = AggregateRequest("*").group_by(
            [],
            [
                reducers.sum("@total_registrations").alias("total_regs"),
                reducers.sum("@suspicious_registrations").alias(
                    "total_suspicious",
                ),
            ],
        )
        agg_result = await ft.aggregate(agg_req)
        total_regs = 0
        total_suspicious = 0
        if agg_result.rows:
            row = agg_result.rows[0]
            if isinstance(row, (list, tuple)):
                d = dict(zip(row[::2], row[1::2]))
            else:
                d = row
            total_regs = int(float(d.get("total_regs", 0)))
            total_suspicious = int(float(d.get("total_suspicious", 0)))

        total_banned = int(await self._redis.get(_STATS_BANNED) or 0)

        return {
            "total_ips": total_ips,
            "graylisted_ips": graylisted,
            "blacklisted_ips": blacklisted,
            "whitelisted_ips": whitelisted,
            "total_banned_emails": total_banned,
            "total_registrations": total_regs,
            "total_suspicious_registrations": total_suspicious,
        }

    async def _stats_via_scan(self) -> dict:
        total_ips = 0
        graylisted = 0
        blacklisted = 0
        whitelisted = 0
        total_regs = 0
        total_suspicious = 0

        cursor: int | str = 0
        while True:
            cursor, keys = await self._redis.scan(
                cursor, match=f"{_IP_KEY}*", count=200,
            )
            if keys:
                pipe = self._redis.pipeline()
                for key in keys:
                    pipe.json().get(key)
                results = await pipe.execute()
                for data in results:
                    if data:
                        total_ips += 1
                        status = data.get("status")
                        if status == "graylisted":
                            graylisted += 1
                        elif status == "blacklisted":
                            blacklisted += 1
                        if data.get("manually_whitelisted"):
                            whitelisted += 1
                        total_regs += data.get("total_registrations", 0)
                        total_suspicious += data.get(
                            "suspicious_registrations", 0,
                        )
            if cursor == 0:
                break

        total_banned = int(await self._redis.get(_STATS_BANNED) or 0)

        return {
            "total_ips": total_ips,
            "graylisted_ips": graylisted,
            "blacklisted_ips": blacklisted,
            "whitelisted_ips": whitelisted,
            "total_banned_emails": total_banned,
            "total_registrations": total_regs,
            "total_suspicious_registrations": total_suspicious,
        }

    # ==================================================================
    # Extended capabilities (beyond StorageBackend protocol)
    # ==================================================================

    # ------------------------------------------------------------------
    # Distributed rate limiter  (atomic Lua + sliding-window sorted sets)
    # ------------------------------------------------------------------

    async def rate_limit_check(
        self,
        key: str,
        limit: int,
        window_seconds: float = 60.0,
    ) -> bool:
        """Atomic sliding-window rate-limit check shared across instances.

        Returns ``True`` if the request is allowed, ``False`` if limited.
        """
        now = time.time()
        uid = f"{now}:{uuid.uuid4().hex[:8]}"
        result = await self._redis.evalsha(
            self._rl_script_sha,
            1,
            f"{_RL_KEY}{key}",
            str(now),
            str(window_seconds),
            str(limit),
            uid,
        )
        return result == 1

    # ------------------------------------------------------------------
    # AI score cache  (JSON documents with TTL)
    # ------------------------------------------------------------------

    async def get_ai_cache(self, cache_key: str) -> dict | None:
        """Retrieve a cached AI score result (shared across instances)."""
        return await self._redis.json().get(f"{_AI_CACHE}{cache_key}")

    async def set_ai_cache(
        self,
        cache_key: str,
        result: dict,
        ttl_seconds: int = 3600,
    ) -> None:
        """Cache an AI score result with automatic TTL expiry."""
        key = f"{_AI_CACHE}{cache_key}"
        await self._redis.json().set(key, "$", result)
        await self._redis.expire(key, ttl_seconds)

    # ------------------------------------------------------------------
    # Probabilistic queries  (Top-K + Count-Min Sketch)
    # ------------------------------------------------------------------

    async def get_top_ips(self) -> list[str]:
        """Return the top-K most active registration IPs."""
        try:
            result = await self._redis.topk().list(_TOPK_IP)
            return [ip for ip in result if ip is not None]
        except Exception:
            return []

    async def get_ip_frequency(self, ip_address: str) -> int:
        """Approximate registration count for an IP (Count-Min Sketch)."""
        try:
            result = await self._redis.cms().query(_CMS_IP, ip_address)
            return result[0] if result else 0
        except Exception:
            return 0
