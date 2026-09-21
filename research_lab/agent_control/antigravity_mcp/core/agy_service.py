#!/usr/bin/env python3
"""Reloadable business implementation. One fresh process per MCP call."""
import asyncio
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import agy_account as account
import agy_desktop as desktop

ROOT=desktop.STATE/'mcp';JOBS=ROOT/'jobs'
PROGRESS_INTERVAL=60.0
TERMINAL={'completed','failed','cancelled','worker_lost'}

def init():
    os.umask(0o077)
    for p in (desktop.STATE,desktop.STATE/'tasks',desktop.STATE/'queue',desktop.STATE/'logs',ROOT,JOBS):p.mkdir(parents=True,exist_ok=True)

@contextlib.contextmanager
def guard():
    with (ROOT/'bridge.lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX);yield

def valid(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',value):raise ValueError('Invalid identifier')
    return value

def jobpath(job_id):return JOBS/valid(job_id)

def terminal_update(job,result):
    job.update(status='cancelled' if result.get('error') in ('CANCELED','TASK_CANCELED') else ('completed' if result.get('status') in ('TURN_COMPLETE','REVIEW_REQUIRED') else 'failed'),finished_at=time.time(),error=result.get('error'),outcome=result.get('outcome'),conversation_id=result.get('conversation_id'))
    return job

def jobread(job_id,locked=False):
    if not locked:
        with guard():return jobread(job_id,locked=True)
    directory=jobpath(job_id);d=desktop.read(directory/'job.json')
    if not d:raise ValueError('Unknown job_id')
    if d['status'] not in TERMINAL and d.get('pid'):
        # Never signal this PID; command identity only diagnoses lost workers.
        command=subprocess.run(['ps','-p',str(d['pid']),'-o','command='],capture_output=True,text=True,check=False).stdout
        if '_worker '+job_id not in command:
            result=desktop.read(directory/'result.json')
            if result:d=terminal_update(d,result)
            else:
                result={'status': 'ERROR','error': 'WORKER_LOST','outcome': 'uncertain','message': 'Worker disappeared; inspect the owned desktop conversation before continuation.'}
                desktop.save(directory/'result.json',result)
                d.update(status='worker_lost',error='WORKER_LOST',outcome='uncertain',finished_at=time.time())
            desktop.save(directory/'job.json',d)
    return d

def brief(d):
    return {k:v for k,v in d.items() if k in ('job_id','task_id','status','created_at','finished_at','error','outcome','conversation_id','project')}

def submit(task_id,prompt,cwd,request_id,mode='implement',timeout_seconds=600,ack_uncertain=False):
    valid(task_id);valid(request_id)
    if mode not in ('implement','research','logs'):raise ValueError('Invalid mode')
    if not prompt.strip() or len(prompt)>100000:raise ValueError('Prompt must be 1-100000 characters')
    if not math.isfinite(timeout_seconds) or timeout_seconds<=0 or timeout_seconds>86400:raise ValueError('Timeout must be 0-86400 seconds')
    if not Path(cwd).is_absolute() or not Path(cwd).is_dir():raise ValueError('cwd must be an existing absolute directory')
    request={'task_id': task_id,'prompt': prompt,'cwd': str(Path(cwd).resolve()),'mode': mode,'timeout_seconds': timeout_seconds,'ack_uncertain': ack_uncertain}
    digest=hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest()
    job_id=hashlib.sha256((task_id+'\0'+request_id).encode()).hexdigest()[:32];directory=jobpath(job_id)
    with guard():
        existing=desktop.read(directory/'job.json')
        if existing:
            if existing['request_hash']!=digest:raise ValueError('Idempotency conflict: request_id already used with different input')
            return dict(brief(jobread(job_id,locked=True)),reused_request=True,cursor=0)
        for p in JOBS.glob('*/job.json'):
            other=desktop.read(p)
            if other['task_id']==task_id and jobread(other['job_id'],locked=True)['status'] not in TERMINAL:
                desktop.diagnostic('continuation_rejected',task_id=task_id,job_id=other['job_id'],source='bridge_job',error_code='TASK_BUSY',accepted=False,queued=False)
                return {'status': 'TASK_BUSY','job_id': other['job_id'],'task_id': task_id,'source': 'bridge_job','accepted': False,'queued': False,'message': 'Use wait/status; do not submit duplicate work.'}
        directory.mkdir(mode=0o700)
        job={'job_id': job_id,'task_id': task_id,'status': 'starting','created_at': time.time(),'request_hash': digest}
        desktop.save(directory/'request.json',request);desktop.save(directory/'job.json',job)
        try:
            with (directory/'worker.log').open('a') as log:
                proc=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'_worker',job_id],stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
        except Exception as exc:  # noqa: BLE001
            job.update(status='failed',error='WORKER_START_FAILED',outcome='not_executed',finished_at=time.time())
            desktop.save(directory/'job.json',job)
            desktop.save(directory/'result.json',{'status': 'ERROR','error': 'WORKER_START_FAILED','outcome': 'not_executed','message': type(exc).__name__})
            return dict(brief(job),cursor=0)
        job.update(pid=proc.pid,status='submitted');desktop.save(directory/'job.json',job)
    return dict(brief(job),cursor=0)

def worker(job_id):
    directory=jobpath(job_id)
    desktop.ACTIVITY_PATH=directory/'activity.json';desktop.ACTIVITY={}
    with guard():
        job=desktop.read(directory/'job.json');job['status']='running';desktop.save(directory/'job.json',job)
    r=desktop.read(directory/'request.json')
    # File transport means prompts do not appear in process command lines.
    prompt=(f"工作目录：{r['cwd']}。本工作块由你负责交付，内部执行方式由你决定；条件合适时鼓励创建子智能体并行开展独立调研和代码工作。你负责分工、合并与核验，所有子智能体遵守相同授权边界，避免冲突修改。每条项目命令显式 cd 到工作目录；项目 Python 使用项目 venv。遵守用户授权范围，不能扩大权限。整改保留已通过内容；同一文件的相关证据尽量集中读取，避免无目的重复调查。最终给出结果、修改/证据路径、验证与未完成项。\n\n"+r['prompt'])
    args=SimpleNamespace(task=r['task_id'],prompt=prompt,cwd=r['cwd'],mode=r['mode'],timeout=r['timeout_seconds'],conversation=None,ack_uncertain=r['ack_uncertain'],no_fallback=False,cancel_requested=lambda:(directory/'cancel').exists())
    previous_result=desktop.read(desktop.STATE/'tasks'/(r['task_id']+'.json'),{}).get('last_result')
    try:
        with (directory/'events.jsonl').open('a',buffering=1) as events, contextlib.redirect_stderr(events):
            result=desktop.run_task(args)
    except BaseException as e:  # noqa: BLE001
        result={'status': 'ERROR','error': e.code if isinstance(e,desktop.Failure) else type(e).__name__,'message': desktop.clean(e.message if isinstance(e,desktop.Failure) else str(e))}
        rec=desktop.read(desktop.STATE/'tasks'/(r['task_id']+'.json'),{})
        previous=rec.get('last_result',{})
        if previous!=previous_result and previous.get('error')==result['error']:result.update(previous)
        elif result['error'] in ('CANCELED','QUEUE_TIMEOUT','TASK_BUSY','DESKTOP_STATE_UNKNOWN','CONTEXT_MISMATCH','OUTCOME_UNCERTAIN'):result['outcome']='not_executed'
    with (directory/'events.jsonl').open('a') as events:
        desktop.expose(r['task_id'],'bridge_result',result,events)
    desktop.save(directory/'result.json',desktop.clean(result))
    with guard():
        job=desktop.read(directory/'job.json');job.update(status='cancelled' if result.get('error') in ('CANCELED','TASK_CANCELED') else ('completed' if result.get('status') in ('TURN_COMPLETE','REVIEW_REQUIRED') else 'failed'),finished_at=time.time(),error=result.get('error'),outcome=result.get('outcome'),conversation_id=result.get('conversation_id'),project=result.get('project'))
        desktop.save(directory/'job.json',job)

def read_events(job_id,cursor=0,max_events=200,max_bytes=262144):
    if cursor<0:raise ValueError('cursor must be nonnegative')
    p=jobpath(job_id)/'events.jsonl';events=[];position=cursor;used=0
    if p.exists():
        with p.open('rb') as f:
            if cursor>f.seek(0,2):raise ValueError('cursor beyond event file')
            f.seek(cursor)
            while len(events)<max_events and used<max_bytes:
                line=f.readline()
                if not line or not line.endswith(b'\n'):break
                position=f.tell();used+=len(line)
                try:events.append(json.loads(line))
                except json.JSONDecodeError:events.append({'event':'unparsed','detail':line.decode(errors='replace')})
    return {'cursor': position,'events': events,'has_more': p.exists() and position<p.stat().st_size}

def poll(job_id,cursor=0,max_events=20):
    d=jobread(job_id);page=read_events(job_id,cursor,max_events,24000)
    events=page['events'];position=page['cursor'];p=jobpath(job_id)/'events.jsonl'
    rec=desktop.read(desktop.STATE/'tasks'/(d['task_id']+'.json'),{})
    records=desktop.active_records();active=next((x for x in records if x.get('task')==d['task_id'] and x.get('pid')==d.get('pid')),None)
    phase='terminal' if d['status'] in TERMINAL else ('executing' if active and active.get('task')==d['task_id'] and active.get('pid')==d.get('pid') else 'queued_or_preparing')
    evidence=desktop.read(jobpath(job_id)/'result.json',{}) if d['status'] in TERMINAL else (rec if active else {})
    out=dict(brief(d),phase=phase,cursor=position,events=events,efficiency=evidence.get('efficiency'),recovery=evidence.get('recovery'),has_more=p.exists() and position<p.stat().st_size)
    if d['status'] in TERMINAL:out['result_available']=(jobpath(job_id)/'result.json').exists()
    return out

def result(job_id,offset=0,max_chars=8000):
    if offset<0 or not 100<=max_chars<=16000:raise ValueError('Invalid output window')
    d=jobread(job_id);r=desktop.read(jobpath(job_id)/'result.json')
    if r is None:return dict(brief(d),message='No final result yet; use wait.')
    text=r.get('result',{}).get('response','');end=min(len(text),offset+max_chars)
    return dict(brief(d),project=r.get('project') or d.get('project') or 'unknown',result_status=r.get('status'),error=r.get('error'),message=r.get('message'),outcome=r.get('outcome'),cancel_confirmed=r.get('cancel_confirmed'),response=text[offset:end],next_offset=end if end<len(text) else None,issues=r.get('issues',[]),recovery=r.get('recovery'),efficiency=r.get('efficiency'),result_path=str(jobpath(job_id)/'result.json'))

def projects(cwd='',backend_factory=desktop.Desktop):
    backend=backend_factory()
    if not cwd:
        return {'projects': backend.projects()}
    path=Path(cwd)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError('cwd must be an existing absolute directory')
    return {'project': backend.resolve_project(str(path.resolve()))}

def activity_snapshot(job_id):
    directory=jobpath(job_id)
    activity=desktop.read(directory/'activity.json',{})
    # Older in-flight workers do not write activity.json. Only use metrics owned
    # by this worker, never a later turn in the same conversation.
    if not activity:
        job=desktop.read(directory/'job.json',{})
        owners=desktop.active_records()
        owned=any(x.get('task')==job.get('task_id') and x.get('pid')==job.get('pid') for x in owners)
        rec=desktop.read(desktop.STATE/'tasks'/(job.get('task_id','')+'.json'),{}) if owned else {}
        metrics=rec.get('efficiency') or {}
        activity={'source': 'legacy_worker_metrics','metrics': {k:metrics[k] for k in
            ('model_rounds','file_reads','observed_edit_steps','tool_issues','elapsed_seconds') if k in metrics}}
        if owned:
            # Bounded read of the existing scheduler log supports workers that
            # were already running before this update. Never scan full transcripts.
            from datetime import datetime
            logs=sorted((desktop.STATE/'logs').glob('scheduler-*.jsonl'))[-2:]
            for path in reversed(logs):
                try:
                    with path.open('rb') as f:
                        size=f.seek(0,2);start=max(0,size-512*1024);f.seek(start)
                        if start:f.readline()
                        lines=f.read().splitlines()
                    for line in reversed(lines):
                        try:item=json.loads(line)
                        except (ValueError,UnicodeError):continue
                        if item.get('task')!=job.get('task_id') or item.get('event')!='progress' or not item.get('changes'):continue
                        stamp=datetime.fromisoformat(item['time']).timestamp()
                        if stamp<job.get('created_at',float('inf')):continue
                        activity.update(source='legacy_scheduler',last_activity_at=stamp,
                            recent_actions=[{k:x[k] for k in ('index','type','status') if k in x} for x in item['changes'][-8:]])
                        break
                    if activity.get('last_activity_at'):break
                except (OSError,ValueError,KeyError,TypeError):continue
    activity=dict(activity)
    last=activity.get('last_activity_at')
    activity['seconds_since_activity']=round(max(0,time.time()-last),1) if last else None
    activity['activity_evidence']='observed_actions' if last else 'no_action_timestamp_available'
    activity['note']='Only observed backend actions; absence of recent actions is not proof of a hang or quota availability.'
    return activity

async def watch_job(job_id,cursor=0,timeout_seconds=1800,on_events=None,on_status=None):
    """One subscription at a time, returning model-visible activity at most every 60s.

    Disconnection cancels this subscription, never the detached worker.
    """
    from watchfiles import awatch
    if not 0<timeout_seconds<=3600 or not math.isfinite(timeout_seconds):raise ValueError('watch timeout must be 0-3600 seconds')
    directory=jobpath(job_id)
    if not (directory/'job.json').exists():raise ValueError('Unknown job_id')
    deadline=time.monotonic()+min(timeout_seconds,PROGRESS_INTERVAL)
    stop=asyncio.Event()
    changes=awatch(directory,watch_filter=None,debounce=250,step=50,recursive=False,
                   force_polling=False,rust_timeout=1000,yield_on_timeout=True,stop_event=stop)
    change_task=asyncio.create_task(anext(changes))
    next_health=0;refresh=True;d=None;last_status=None;delivery_enabled=bool(on_events)
    try:
        # The first yield (including an empty timeout batch) proves native
        # registration has finished. Read the snapshot AFTER this barrier.
        done,_=await asyncio.wait({change_task},timeout=max(0,deadline-time.monotonic()))
        if done:
            change_task.result()
            change_task=asyncio.create_task(anext(changes))
        while True:
            now=time.monotonic()
            if refresh or now>=next_health:
                d=await asyncio.to_thread(jobread,job_id);next_health=now+180;refresh=False
                if d['status']!=last_status:
                    last_status=d['status']
                    if on_status:await on_status(brief(d))
            # Read/push inside this held request. No model-driven pagination loop.
            if delivery_enabled:
                while True:
                    page=await asyncio.to_thread(read_events,job_id,cursor)
                    if not page['events']:break
                    if await on_events(page) is False:
                        delivery_enabled=False
                        break
                    cursor=page['cursor']
                    if not page['has_more'] or time.monotonic()>=deadline:break
            if d['status'] in TERMINAL:
                page=await asyncio.to_thread(read_events,job_id,cursor,0)
                if not delivery_enabled or not page['has_more']:
                    return dict(brief(d),cursor=cursor,has_more=page['has_more'],
                                activity=activity_snapshot(job_id),final_result=desktop.read(directory/'result.json'),resume={'job_id': job_id,'cursor': cursor},events_path=str(directory/'events.jsonl'))
            if time.monotonic()>=deadline:
                return dict(brief(d),cursor=cursor,resume={'job_id': job_id,'cursor': cursor},
                            watch_timeout=True,progress_update=True,worker_continues=True,
                            activity=activity_snapshot(job_id),next_check_seconds=0,
                            next_action='Read activity, then immediately call watch with the SAME job_id and resume.cursor. This is observation only: do not submit/message/cancel or change executor. No quota claim can be made from silence.',
                            events_path=str(directory/'events.jsonl'))
            done,_=await asyncio.wait({change_task},timeout=max(0,min(deadline-time.monotonic(),next_health-time.monotonic())))
            if done:
                changed=change_task.result()
                refresh=refresh or any(Path(path).name=='job.json' for _,path in changed)
                change_task=asyncio.create_task(anext(changes))
    finally:
        stop.set();change_task.cancel()
        with contextlib.suppress(asyncio.CancelledError,StopAsyncIteration):await change_task
        await changes.aclose()

def cancel(job_id):
    with guard():
        d=jobread(job_id,locked=True)
        if d['status'] in TERMINAL:return dict(brief(d),cancel_requested=False)
        (jobpath(job_id)/'cancel').touch(mode=0o600)
    return dict(brief(d),cancel_requested=True,message='Request recorded. Wait for cancellation confirmation; the shared app is not stopped.')

async def dispatch(name, arguments, on_events=None, on_status=None):
    """Internal API v1; public tool schemas live in the stable MCP frontend."""
    if name=='account_usage':return await asyncio.to_thread(account.account_usage)
    if name=='projects':return await asyncio.to_thread(projects,**arguments)
    if name=='watch':return await watch_job(**arguments,on_events=on_events,on_status=on_status)
    if name=='events':return await asyncio.to_thread(read_events,**arguments)
    if name=='submit':return await asyncio.to_thread(submit,**arguments)
    if name=='message':
        arguments=dict(arguments)
        task_id=arguments['task_id'];valid(task_id)
        rec=desktop.read(desktop.STATE/'tasks'/(task_id+'.json'))
        if not rec:raise ValueError('No saved task; use submit first')
        return await asyncio.to_thread(submit,**arguments,cwd=rec['cwd'],mode=rec['mode'])
    if name=='wait':
        job_id=arguments['job_id'];cursor=arguments.get('cursor',0)
        timeout=arguments.get('timeout_seconds',25)
        if not 0<=timeout<=50:raise ValueError('wait timeout must be 0-50 seconds')
        deadline=time.monotonic()+timeout
        while True:
            out=await asyncio.to_thread(poll,job_id,cursor)
            if out['events'] or out['status'] in TERMINAL or time.monotonic()>=deadline:return out
            await asyncio.sleep(.4)
    if name=='status':
        job_id=arguments.get('job_id')
        if job_id:
            out=await asyncio.to_thread(poll,job_id,0,0)
            def inspect():
                rec=desktop.read(desktop.STATE/'tasks'/(out['task_id']+'.json'),{})
                cid=rec.get('conversation_id')
                state={'readiness': 'unknown','scope': 'current_task_conversation','checked_at': time.time(),'conversation_id': cid}
                if cid:
                    try:state.update(desktop.conversation_state(desktop.Desktop().trajectory(cid)))
                    except Exception as exc:  # noqa: BLE001
                        state['error_code']=exc.code if isinstance(exc,desktop.Failure) else type(exc).__name__
                with guard():
                    pending=[d['job_id'] for p in JOBS.glob('*/job.json')
                             if (d:=desktop.read(p,{})).get('task_id')==out['task_id']
                             and d.get('status') not in TERMINAL]
                state['blocking_job_ids']=pending
                state['can_continue']=state['readiness']=='ready' and not pending and rec.get('state') not in ('uncertain','running')
                state['advisory']=True  # Submission rechecks; this observation is not a reservation.
                desktop.diagnostic('status_checked',task_id=out['task_id'],job_id=job_id,
                                   conversation_id=cid,**{k:v for k,v in state.items() if k in ('readiness','raw_status','unfinished_steps','error_code')})
                return state
            out['continuation']=await asyncio.to_thread(inspect)
            return out
        def snapshot():
            with desktop.guard():
                records=desktop.active_records();active=records[0] if records else None
                return {'active': active,'active_tasks': records,'queued': desktop.queue_view(records),'execution_limit': desktop.execution_limit(),'runtime': {'business_reload': 'per_call','business_pid': os.getpid()},'scope': 'local_scheduler_only','desktop_readiness': 'not_checked','next_action': 'Use status(job_id) to check current conversation readiness; an empty local queue does not mean Desktop is idle.'}
        return await asyncio.to_thread(snapshot)
    if name=='result':return await asyncio.to_thread(result,**arguments)
    if name=='cancel':return await asyncio.to_thread(cancel,**arguments)
    raise ValueError('Unknown business operation')


def send_frame(kind, data):
    payload=json.dumps({'kind': kind,'data': data},ensure_ascii=False)
    for offset in range(0,len(payload),16000):
        piece=payload[offset:offset+16000]
        print(json.dumps({'chunk': piece,'offset': offset,'final': offset+len(piece)==len(payload)},ensure_ascii=False),flush=True)


async def call_from_stdio():
    request=json.loads(sys.stdin.readline())
    if request.get('version')!=1:raise ValueError('Unsupported internal protocol version')
    async def events(page):
        send_frame('events',page)
        # Frontend acknowledges delivery or filtering before cursor advancement.
        line=await asyncio.to_thread(sys.stdin.readline)
        if not line:raise EOFError('MCP frontend disconnected')
        return json.loads(line).get('delivered') is True
    async def status(state):send_frame('status',state)
    result=await dispatch(request['operation'],request.get('arguments',{}),events,status)
    send_frame('result',result)


if __name__=='__main__':
    init()
    if len(sys.argv)==3 and sys.argv[1]=='_worker':worker(valid(sys.argv[2]))
    elif len(sys.argv)==2 and sys.argv[1]=='_call':
        try:asyncio.run(call_from_stdio())
        except Exception as exc:  # noqa: BLE001
            send_frame('error',{'type': type(exc).__name__,'message': desktop.clean(str(exc))})
    else:raise SystemExit('Use the stable agy_mcp.py entrypoint')
