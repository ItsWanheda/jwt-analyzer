.PHONY: install docker-build docker-audit docker-shell clean

install:
    pip install -e .

docker-build:
    docker build -t jwt-analyzer:latest .

# Most common use case - audit a token file
docker-audit:
    @mkdir -p reports
    docker compose --profile audit run --rm jwt-analyzer \
        audit --token-file /app/tokens/$(TOKEN) \
              --wordlist /app/wordlists/common_secrets.txt \
              --output /app/reports/audit-$(shell date +%Y%m%d-%H%M%S) \
              --format both

# Interactive debugging
docker-shell:
    docker compose --profile audit run --rm -it jwt-analyzer /bin/bash

# CI/CD use case
docker-test:
    docker build -t jwt-analyzer:test .
    docker run --rm jwt-analyzer:test python -m pytest tests/

clean:
    docker compose down -v
    docker rmi jwt-analyzer:latest 2>/dev/null || true
    rm -rf reports/* .pytest_cache