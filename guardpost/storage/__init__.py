# Pluggable storage backends
#
# Available backends:
#   SQLiteStorage  — zero-config default (guardpost.storage.sqlite)
#   MongoStorage   — high-throughput MongoDB (pip install guardpost[mongo])
#   PostgresStorage— enterprise PostgreSQL (pip install guardpost[postgres])
#   RedisStorage   — distributed Redis 8 with JSON, TimeSeries, Bloom filters,
#                    Count-Min Sketch, Top-K, Query Engine, distributed rate
#                    limiting, and shared AI cache (pip install guardpost[redis])
