FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY shared ./shared
COPY test_rpc_readonly.py test_rpc_trade_flow.py ./
COPY scripts/commodity_c_fast_t1_one_shot.py ./scripts/commodity_c_fast_t1_one_shot.py
COPY scripts/commodity_c_fast_simnow_research_bundle.py ./scripts/commodity_c_fast_simnow_research_bundle.py
COPY scripts/commodity_c_fast_simnow_research_acceptance.py ./scripts/commodity_c_fast_simnow_research_acceptance.py
COPY scripts/commodity_c_fast_fee_statement_verify.py ./scripts/commodity_c_fast_fee_statement_verify.py
COPY docs/schemas/commodity-c-fast-simnow-research-bundle-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-bundle-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-bundle-trusted-keys-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-bundle-trusted-keys-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-bundle-install-receipt-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-bundle-install-receipt-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-acceptance-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-acceptance-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-acceptance-trusted-keys-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-acceptance-trusted-keys-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-acceptance-consume-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-acceptance-consume-v1.schema.json
COPY docs/schemas/commodity-c-fast-simnow-research-acceptance-receipt-v1.schema.json ./docs/schemas/commodity-c-fast-simnow-research-acceptance-receipt-v1.schema.json
COPY docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json ./docs/schemas/commodity-c-fast-t1-query-terminal-v6.schema.json
COPY docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json ./docs/schemas/commodity-c-fast-questdb-readonly-proof-v1.schema.json
COPY docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json ./docs/schemas/commodity-c-fast-l1-l5-audit-v1.schema.json
COPY docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json ./docs/schemas/commodity-c-fast-l1-l5-audit-v2.schema.json
COPY docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json ./docs/schemas/commodity-c-fast-l1-l5-audit-manifest-v2.schema.json
ENV PYTHONPATH=/app/backend:/app/scripts

RUN python -m py_compile test_rpc_readonly.py test_rpc_trade_flow.py \
    backend/app/services/deployment_drain_bootstrap.py \
    scripts/commodity_c_fast_fee_statement_verify.py \
    && python -m app.services.commodity_c_fast_permit_runtime_smoke \
    && python -m app.services.deployment_drain_bootstrap \
        --state-root /tmp/issue267-bootstrap-smoke \
        --operator image-build \
        --reason image-packaging-smoke \
        --confirm-offline-trading-disabled \
    && python -c "import json; from pathlib import Path; payload=json.loads(Path('/tmp/issue267-bootstrap-smoke/state.json').read_text()); assert payload['state'] == 'RESTARTED_FROZEN'" \
    && rm -r /tmp/issue267-bootstrap-smoke

ENV APP_ENV=production

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--app-dir", "backend"]
