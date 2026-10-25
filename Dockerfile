FROM python:3.12.10-slim AS builder

# .git is not in the build context, so hatch-vcs can't read the version here:
# CI passes it in (release tag, or the dev version on main).
ARG GUARDPOST_VERSION=0.0.0.dev0
ENV SETUPTOOLS_SCM_PRETEND_VERSION=${GUARDPOST_VERSION}

WORKDIR /app
COPY pyproject.toml README.md ./
COPY guardpost/ guardpost/
RUN pip install --no-cache-dir .[api,redis]

FROM python:3.12.10-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN groupadd -r guardpost && useradd -r -g guardpost -s /sbin/nologin guardpost

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/guardpost /usr/local/bin/guardpost
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn
COPY --from=builder /app/guardpost /app/guardpost

RUN mkdir -p /data && chown guardpost:guardpost /data

ENV GUARDPOST_DB_PATH=/data/guardpost.db

VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/readyz || exit 1

USER guardpost

ENTRYPOINT ["guardpost", "serve"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
