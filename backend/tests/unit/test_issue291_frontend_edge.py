from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTAINERFILE = ROOT / "frontend/Containerfile"
NGINX_CONFIG = ROOT / "frontend/nginx.conf"
LEGACY_DOCKERFILE = ROOT / "Dockerfile"


def test_frontend_image_is_static_only_and_has_no_backend_or_secret_copy() -> None:
    containerfile = CONTAINERFILE.read_text(encoding="utf-8")

    assert "FROM node:22-slim AS frontend-build" in containerfile
    assert "FROM nginx:1.27-alpine AS frontend-edge" in containerfile
    assert (
        "COPY --from=frontend-build /src/frontend/dist /usr/share/nginx/html"
        in containerfile
    )
    assert "COPY backend" not in containerfile
    assert "COPY .env" not in containerfile
    assert "COPY ." not in containerfile
    assert "signing" not in containerfile.lower()
    assert "rpc" not in containerfile.lower()
    assert "postgres" not in containerfile.lower()
    assert "USER nginx" in containerfile
    assert 'ENTRYPOINT ["nginx", "-c", "/etc/nginx/nginx.conf"' in containerfile


def test_edge_contract_has_private_control_api_and_no_spa_error_fallback() -> None:
    config = NGINX_CONFIG.read_text(encoding="utf-8")

    assert "listen 8080 default_server;" in config
    assert "server control-api:8081;" in config
    assert "location = /api" in config
    assert "location ^~ /api/" in config
    assert "location = /ws" in config
    assert "location ^~ /ws/" in config
    assert "proxy_http_version 1.1;" in config
    assert "proxy_set_header Upgrade $http_upgrade;" in config
    assert "proxy_set_header Connection $connection_upgrade;" in config
    assert "proxy_set_header X-Correlation-ID $http_x_correlation_id;" in config
    assert config.count("proxy_intercept_errors off;") >= 4
    assert "try_files $uri $uri/ /index.html;" in config
    assert "error_page" not in config
    assert "proxy_pass http://control_api;" in config
    assert 'Cache-Control "public, max-age=31536000, immutable"' in config
    assert 'Cache-Control "no-store"' in config
    assert 'X-Content-Type-Options "nosniff" always' in config
    assert "Content-Security-Policy" in config


def test_legacy_backend_image_no_longer_packages_frontend_dist() -> None:
    dockerfile = LEGACY_DOCKERFILE.read_text(encoding="utf-8")

    assert "frontend-build" not in dockerfile
    assert "frontend/dist" not in dockerfile
    assert "COPY frontend" not in dockerfile
