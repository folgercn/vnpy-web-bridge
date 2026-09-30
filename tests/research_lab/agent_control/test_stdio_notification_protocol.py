"""Real FastMCP and raw JSON-RPC negative peers; zero real Provider calls."""
import json
from pathlib import Path
import sys
import time

import pytest

from research_lab.agent_control.errors import ProviderError, ProviderErrorCode
from research_lab.agent_control.transports.local_mcp import ALL_MCP_OPERATIONS, LocalMCPTransport
from scripts.issue502_trusted_runtime import wait_owned_job


def fast_transport():
    pytest.importorskip("mcp.server.fastmcp")
    return LocalMCPTransport(command=[sys.executable, str(Path(__file__).parent / "fixtures/notification_mcp.py")])


def test_actual_fastmcp_notification_precedes_matching_watch_response(tmp_path):
    transport = fast_transport()
    assert transport.discover_tools().has_operation("watch")
    checkpoint = tmp_path / "watch.json"
    wait_owned_job(transport, "owned-job", state_path=checkpoint, max_updates=2)
    assert json.loads(checkpoint.read_text()) == {"job_id": "owned-job", "cursor": 7}


def test_actual_fastmcp_eof_after_notification_keeps_cursor(tmp_path):
    transport = fast_transport()
    checkpoint = tmp_path / "watch.json"
    with pytest.raises(ProviderError) as error:
        wait_owned_job(transport, "disconnect", state_path=checkpoint)
    assert error.value.code == ProviderErrorCode.EXECUTION_UNCERTAIN
    assert json.loads(checkpoint.read_text())["cursor"] == 7
    # Resume uses the saved cursor; no submit or replacement job.
    class Peer:
        def call_tool(self, op, args, **kw):
            assert op == "watch" and args == {"job_id": "disconnect", "cursor": 7, "timeout_seconds": 60}
            return {"status": "completed", "resume": {"cursor": 7}}
    wait_owned_job(Peer(), "disconnect", state_path=checkpoint)


@pytest.mark.parametrize("job_id,code", [("timeout", ProviderErrorCode.EXECUTION_UNCERTAIN),
                                       ("tool-error", ProviderErrorCode.EXECUTION_FAILED)])
def test_actual_fastmcp_timeout_and_tool_error(job_id, code):
    transport = fast_transport()
    transport.discover_tools()
    notifications = []
    start = time.monotonic()
    with pytest.raises(ProviderError) as error:
        transport.call_tool("watch", {"job_id": job_id}, timeout_seconds=3, on_notification=notifications.append)
    assert error.value.code == code
    assert notifications
    assert time.monotonic() - start < 6


def raw_peer(payload):
    code = '''import json,sys,time
request=json.loads(sys.stdin.readline())
print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{}}),flush=True)
sys.stdin.readline()
request=json.loads(sys.stdin.readline())
''' + payload
    return LocalMCPTransport(command=[sys.executable, "-u", "-c", code], tool_catalog=list(ALL_MCP_OPERATIONS))


def test_unrelated_ids_notifications_and_coalesced_response_frames():
    transport = raw_peer('''print(json.dumps({'jsonrpc':'2.0','method':'notifications/message','params':{}}))
print(json.dumps({'jsonrpc':'2.0','id':999,'error':{'message':'unrelated'}}))
print(json.dumps({'jsonrpc':'2.0','id':'2','result':{'bad':True}}))
print(json.dumps({'jsonrpc':'2.0','id':True,'result':{'bad':True}}))
print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'answer':7}}),flush=True)
''')
    assert transport.call_tool("status") == {"answer": 7}


@pytest.mark.parametrize("payload,code", [
    ("print('not-json',flush=True)", ProviderErrorCode.EXECUTION_UNCERTAIN),
    ("print('{}',flush=True)", ProviderErrorCode.EXECUTION_UNCERTAIN),
    ("print('partial',end='',flush=True);time.sleep(3)", ProviderErrorCode.EXECUTION_UNCERTAIN),
    ("pass", ProviderErrorCode.EXECUTION_UNCERTAIN),
    ("print(json.dumps({'jsonrpc':'2.0','id':request['id'],'error':{'message':'failed'}}),flush=True)", ProviderErrorCode.EXECUTION_FAILED),
])
def test_bad_frames_partial_line_eof_and_matching_error(payload, code):
    with pytest.raises(ProviderError) as error:
        raw_peer(payload).call_tool("status", timeout_seconds=0.5)
    assert error.value.code == code
