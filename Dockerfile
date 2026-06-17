FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY test_rpc_readonly.py test_rpc_trade_flow.py ./

RUN python -m py_compile test_rpc_readonly.py test_rpc_trade_flow.py

CMD ["python", "test_rpc_readonly.py"]
