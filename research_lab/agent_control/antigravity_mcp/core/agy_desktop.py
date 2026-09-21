#!/usr/bin/env python3
"""Schedule owned tasks against the existing Antigravity desktop backend.
No CLI workers; no desktop launch/kill; no automatic replay of uncertain turns.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

STATE = Path(os.environ.get('AGY_DESKTOP_STATE', Path(__file__).resolve().parents[1] / '.desktop'))
BINARY = '/Applications/Antigravity.app/Contents/Resources/bin/language_server'
SERVICE = '/exa.language_server_pb.LanguageServerService/'
MODELS = ['Gemini 3.8 Flash (High)', 'Gemini 3.8 Flash (Medium)', 'Gemini 3.7 Flash (High)']
IDLE = 'CASCADE_RUN_STATUS_IDLE'

class Failure(Exception):
    def __init__(self, code, message=''):
        self.code, self.message = code, message
        super().__init__(code)

def save(p, d):
    tmp = p.with_name(p.name+'.'+uuid.uuid4().hex+'.tmp')
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2)); tmp.replace(p)

def read(p, default=None):
    try:return json.loads(p.read_text())
    except FileNotFoundError:return default

def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False

def clean(v):
    if isinstance(v,dict):
        return {k:clean(x) for k,x in v.items() if k not in ('csrfToken','hostBridgeToken')}
    if isinstance(v,list): return [clean(x) for x in v]
    if isinstance(v,str):
        v=re.sub(r'(?i)(Bearer\s+)[\w.\-/+=]+',r'\1[REDACTED]',v)
        return re.sub(r'(?i)((?:password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*)[^\s,;}]+',r'\1[REDACTED]',v)
    return v

@contextlib.contextmanager
def guard():
    with (STATE/'control.lock').open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX); yield

ACTIVITY_PATH=None
ACTIVITY={}

def record_activity(task, phase, fields):
    # Per-worker, per-job metadata; never copy payloads, prompts or command text.
    if ACTIVITY_PATH is None:return
    try:
        now=time.time()
        ACTIVITY.update(task_id=task,phase=phase,observed_at=now)
        if phase=='progress' and fields.get('changes'):
            actions=[{k:x[k] for k in ('index','type','status') if k in x}
                     for x in fields['changes']]
            ACTIVITY.update(last_activity_at=now,recent_actions=actions[-8:],
                            observed_changes=ACTIVITY.get('observed_changes',0)+len(actions))
        if phase=='efficiency':
            ACTIVITY['metrics']={k:fields[k] for k in ('model_rounds','file_reads',
                'observed_edit_steps','tool_issues','elapsed_seconds') if k in fields}
        save(ACTIVITY_PATH,ACTIVITY)
    except (OSError,ValueError,TypeError):pass

def event(task, phase, **fields):
    item=clean(dict(time=time.strftime('%Y-%m-%dT%H:%M:%S%z'),task=task,event=phase,**fields))
    with (STATE/'logs'/('scheduler-'+time.strftime('%Y%m%d')+'.jsonl')).open('a') as f:
        fcntl.flock(f,fcntl.LOCK_EX); f.write(json.dumps(item,ensure_ascii=False)+'\n')
    record_activity(task,phase,fields)
    return item

def diagnostic(event_name, **fields):
    """Best-effort metadata only; never accept request/response bodies."""
    allowed={'task_id','job_id','conversation_id','source','raw_status','readiness',
             'unfinished_steps','error_code','accepted','queued','local_state'}
    item=dict(time=time.time(),event=event_name,pid=os.getpid(),
              **{k:v for k,v in fields.items() if k in allowed})
    try:
        directory=STATE/'diagnostics';directory.mkdir(mode=0o700,exist_ok=True)
        with (directory/'write.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            path=directory/('state-'+time.strftime('%Y%m%d')+'.jsonl')
            with path.open('a') as f:
                os.chmod(path,0o600);f.write(json.dumps(item)+'\n')
            files=sorted(directory.glob('state-*.jsonl'),key=lambda p:p.stat().st_mtime)
            total=sum(p.stat().st_size for p in files)
            for old in files:
                if time.time()-old.stat().st_mtime>7*86400 or total>100*1024*1024:
                    total-=old.stat().st_size;old.unlink()
    except (OSError,ValueError,TypeError):pass

def conversation_state(snapshot):
    """IDLE is necessary but insufficient while a step is still executing."""
    raw=snapshot.get('status')
    steps=snapshot.get('trajectory',{}).get('steps',[])
    unfinished=sum(x.get('status') in ('CORTEX_STEP_STATUS_GENERATING',
        'CORTEX_STEP_STATUS_RUNNING','CORTEX_STEP_STATUS_PENDING',
        'CORTEX_STEP_STATUS_WAITING') for x in steps)
    readiness=('busy' if unfinished or raw=='CASCADE_RUN_STATUS_RUNNING' else
               'ready' if raw==IDLE else 'unknown')
    return {'raw_status': raw,'readiness': readiness,'unfinished_steps': unfinished}

OUTPUT_LOCK=threading.RLock()
def emit(item,sink=None):
    with OUTPUT_LOCK:
        (sink or sys.stderr).write(json.dumps(item,ensure_ascii=False)+'\n')
        (sink or sys.stderr).flush()

def expose(task,source,payload,sink=None):
    # Fragment transport only: concatenating data then JSON-decoding restores
    # every business field. Auth redaction is the only content transformation.
    data=json.dumps(clean(payload),ensure_ascii=False,separators=(',',':'))
    identifier=uuid.uuid4().hex
    for offset in range(0,len(data),8000):
        end=min(offset+8000,len(data))
        emit({'event': 'upstream_payload','time': time.time(),'task': task,'source': source,'payload_id': identifier,
                  'offset': offset,'total_chars': len(data),'final': end==len(data),'data': data[offset:end]},sink)

class Desktop:
    def __init__(self,task=None):
        self.task=task
        listing=subprocess.check_output(['ps','-axo','pid=,command='],text=True)
        matches=[]
        for line in listing.splitlines():
            pieces=line.strip().split(None,1)
            if len(pieces)==2 and pieces[1].startswith(BINARY+' '):matches.append(pieces)
        if len(matches)!=1: raise Failure('DESKTOP_UNAVAILABLE','Expected one running desktop language_server.')
        self.pid=int(matches[0][0]); args=shlex.split(matches[0][1])
        def flag(name):
            for i,x in enumerate(args):
                if x==name:return args[i+1]
                if x.startswith(name+'='):return x.split('=',1)[1]
            raise Failure('PROTOCOL_CHANGED','Missing backend flag '+name)
        self.token=flag('--csrf_token')
        ls=subprocess.run(['lsof','-nP','-a','-p',str(self.pid),'-iTCP','-sTCP:LISTEN','-Fn'],capture_output=True,text=True,check=False).stdout
        ports=set(re.findall(r'^n(?:127\.0\.0\.1|\[::1\]|\*):(\d+)$',ls,re.MULTILINE))
        configured=flag('--https_server_port')
        if configured!='0':ports={configured}
        self.port=None
        # Trust the certificate presented by the locally owned backend port only.
        # Subsequent calls use certificate verification and never use proxy env vars.
        for port in sorted(ports):
            try:
                cert=ssl.get_server_certificate(('127.0.0.1',int(port)),timeout=2)
                ctx=ssl.create_default_context(cadata=cert);ctx.check_hostname=False
                self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
                self.port=int(port)
                self.rpc('GetCascadeModelConfigData',{},timeout=3)
                break
            except Exception:  # noqa: BLE001
                self.port=None
        if self.port is None:raise Failure('DESKTOP_UNAVAILABLE','No matching local HTTPS backend.')
    def request(self,method,body,stream=False,timeout=15):
        body=json.dumps(body).encode()
        if stream:body=b'\0'+struct.pack('>I',len(body))+body
        req=urllib.request.Request(f'https://127.0.0.1:{self.port}'+SERVICE+method,data=body,headers={'Content-Type':'application/connect+json' if stream else 'application/json','Connect-Protocol-Version':'1','x-codeium-csrf-token':self.token})
        try:return self.opener.open(req,timeout=timeout)
        except urllib.error.HTTPError as e:
            detail=clean(e.read().decode(errors='replace'))
            payload={'status': e.code,'body': detail}
            if not stream and getattr(self,'task',None):expose(self.task,method+':HTTPError',payload)
            failure=Failure('RPC_ERROR',str(e.code)+': '+detail);failure.upstream_payload=payload
            raise failure from None
    def rpc(self,method,body,timeout=15):
        with self.request(method,body,timeout=timeout) as r:
            data=r.read()
            try:result=json.loads(data)
            except (ValueError,UnicodeDecodeError):
                if getattr(self,'task',None):expose(self.task,method+':invalid_json',{'body': data.decode(errors='replace')})
                raise
        if getattr(self,'task',None):expose(self.task,method,result)
        return result
    def projects(self):
        # The initial stream frame contains the complete project ID snapshot.
        with self.request('ProjectUpdatesStream',{},stream=True,timeout=10) as stream:
            header=read_exact(stream,5)
            if len(header)!=5 or header[0]!=0:raise Failure('PROJECT_DISCOVERY_FAILED')
            size=struct.unpack('>I',header[1:])[0]
            payload=read_exact(stream,size)
            if len(payload)!=size:raise Failure('PROJECT_DISCOVERY_FAILED')
            snapshot=json.loads(payload)
        ids=snapshot.get('projectList',{}).get('projectIds')
        if ids is None:raise Failure('PROJECT_DISCOVERY_FAILED','Missing project list snapshot.')
        if not ids:return []
        records=self.rpc('ReadProjects',{'ids':ids}).get('projects',[])
        from urllib.parse import unquote, urlparse
        projects=[]
        for record in records:
            folders=[]
            for resource in record.get('projectResources',{}).get('resources',[]):
                for value in resource.values():
                    uri=value.get('folderUri') if isinstance(value,dict) else None
                    if uri and urlparse(uri).scheme=='file' and urlparse(uri).netloc in ('','localhost'):
                        folders.append(str(Path(unquote(urlparse(uri).path)).resolve()))
            projects.append({'project_id': record['id'],'name': record.get('name'),'folders': folders})
        return projects
    def resolve_project(self,cwd):
        path=Path(cwd).resolve()
        matches=[p for p in self.projects() if any(path.is_relative_to(Path(f)) for f in p['folders'])]
        if len(matches)!=1:
            raise Failure('PROJECT_AMBIGUOUS' if matches else 'PROJECT_NOT_FOUND',
                          'Working directory must match exactly one desktop project; no default project is used.')
        return dict(matches[0],cwd=str(path))

    def trajectory(self,cid):
        result=self.rpc('GetCascadeTrajectory',{'cascadeId':cid})
        steps=result.get('trajectory',{}).get('steps',[])
        total=result.get('numTotalSteps',len(steps))
        while len(steps)<total:
            page=self.rpc('GetCascadeTrajectorySteps',{'cascadeId':cid,'stepOffset':len(steps)})
            new=page.get('steps',[])
            if not new:raise Failure('INCOMPLETE_TRAJECTORY')
            steps.extend(new)
        return result
    def cancel(self,cid):
        self.rpc('CancelCascadeInvocation',{'cascadeId':cid,'killBackgroundTasks':True})
        for _ in range(10):
            if self.trajectory(cid).get('status')==IDLE:return True
            time.sleep(.5)
        return False

def read_exact(stream,size):
    chunks=[];remaining=size
    while remaining:
        chunk=stream.read(remaining)
        if not chunk:break
        chunks.append(chunk);remaining-=len(chunk)
    return b''.join(chunks)

class Updates:
    def __init__(self,backend,cid,task):
        self.backend,self.cid,self.task=backend,cid,task
        self.changed=threading.Event();self.stop=threading.Event();self.response=None
        self.frames=0;self.error=None;self.reconnects=0;self.sink=sys.stderr
        self.cache_lock=threading.Lock();self.steps={};self.status=None;self.trajectory_id=None;self.total=0
    def start(self):
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            self.read_once()
            self.stop.wait(.5)
    def read_once(self):
        try:
            with self.backend.request('StreamAgentStateUpdates',{'conversationId':self.cid},stream=True,timeout=60) as r:
                self.response=r
                while not self.stop.is_set():
                    h=read_exact(r,5)
                    if len(h)!=5:break
                    size=struct.unpack('>I',h[1:])[0]
                    payload=read_exact(r,size)
                    if len(payload)!=size:raise Failure('INCOMPLETE_FRAME')
                    msg=json.loads(payload)
                    with OUTPUT_LOCK:
                        expose(self.task,'StreamAgentStateUpdates',{'flags': h[0],'message': msg},self.sink)
                    if h[0]&2:
                        if msg.get('error'):self.error=clean(msg['error'])
                        break
                    if h[0]!=0:raise Failure('UNSUPPORTED_STREAM_COMPRESSION')
                    self.frames+=1
                    update=msg.get('update',{})
                    self.apply(update)
                    self.changed.set()
        except Exception as e:  # noqa: BLE001
            with OUTPUT_LOCK:
                if hasattr(e,'upstream_payload'):
                    expose(self.task,'StreamAgentStateUpdates:HTTPError',e.upstream_payload,self.sink)
            if not self.stop.is_set():
                self.reconnects+=1
                self.error=None if isinstance(e,(TimeoutError,socket.timeout)) else type(e).__name__
                event(self.task,'stream_reconnect',reason=type(e).__name__,count=self.reconnects)
                self.changed.set()
    def apply(self, update):
        if update.get('conversationId') not in (None,self.cid):return
        with self.cache_lock:
            tid=update.get('trajectoryId')
            if tid and self.trajectory_id and tid!=self.trajectory_id:self.steps={};self.total=0
            if tid:self.trajectory_id=tid
            if 'status' in update:self.status=update['status']
            delta=update.get('mainTrajectoryUpdate',{}).get('stepsUpdate',{})
            if 'totalLength' in delta:
                self.total=delta['totalLength']
                self.steps={i:s for i,s in self.steps.items() if i<self.total}
            for i,step in zip(delta.get('indices',[]),delta.get('steps',[])):
                self.steps[i]=step
    def snapshot(self):
        with self.cache_lock:
            if any(i not in self.steps for i in range(self.total)):return None
            return {'status':self.status,'trajectory':{'steps':[self.steps[i] for i in range(self.total)]}}
    def close(self):
        self.stop.set()
        # Unblock urllib's pending read, then let any fully received message
        # finish parsing/writing before the caller closes the event sink.
        response=self.response
        sock=getattr(getattr(getattr(response,'fp',None),'raw',None),'_sock',None)
        if sock is not None:
            try:sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        thread=getattr(self,'thread',None)
        if thread is not None:
            thread.join(timeout=60)
            if thread.is_alive():raise Failure('STREAM_DRAIN_TIMEOUT','Reader did not finish writing received output.')


def step_issue(st):
    status=st.get('status','')
    failed='ERROR' in st.get('type','') or status.endswith(('ERROR','FAILED','CANCELED','CANCELLED'))
    command=st.get('runCommand',{})
    if not failed and command.get('exitCode') in (None,0):return None
    detail=st.get('error',{}) or st.get('errorMessage',{})
    if not detail and command:detail=command.get('combinedOutput',{})
    if isinstance(detail,dict):detail=detail.get('shortError') or detail.get('fullError') or detail.get('message') or detail.get('full') or str(detail)
    return clean({'type': st.get('type'),'status': status,'message': str(detail)[:2000],'exit_code': command.get('exitCode')})

def recovery_state(steps, offset=0):
    """Conservative evidence: identical command, cwd and shell, later DONE/0.

    A retry success only resolves that invocation, never its side effects or
    task acceptance. Unknown tools and changed commands require human review.
    """
    history=[]; pending={}; generation_pending=[]
    for index, step in enumerate(steps, offset):
        command=step.get('runCommand') or {}
        line=command.get('commandLine')
        cwd=command.get('cwd')
        key=(line,cwd,command.get('shellName')) if isinstance(line,str) and line and isinstance(cwd,str) and cwd else None
        issue=step_issue(step)
        if issue:
            entry=dict(issue,step_index=index,recovery='unverified')
            if key:
                entry.update(command=line,cwd=cwd,shell=command.get('shellName'))
                pending.setdefault(key,[]).append(entry)
            history.append(entry)
            if step.get('type')=='CORTEX_STEP_TYPE_ERROR_MESSAGE':generation_pending.append(entry)
        elif key and step.get('status')=='CORTEX_STEP_STATUS_DONE' and command.get('exitCode')==0:
            # No retry-parent id is available: only the nearest failed
            # invocation can be conservatively paired with this success.
            for entry in pending.pop(key,[])[-1:]:
                entry.update(recovery='exact_retry_succeeded',recovery_evidence={
                    'step_index': index,'command': line,'cwd': cwd,'shell': command.get('shellName'),'exit_code': 0,
                    'sandbox_override': command.get('sandboxOverride')})
        response=step.get('plannerResponse',{})
        if step.get('type')=='CORTEX_STEP_TYPE_PLANNER_RESPONSE' and step.get('status')=='CORTEX_STEP_STATUS_DONE' and (response.get('modifiedResponse') or response.get('response')) and not issue:
            for entry in generation_pending:
                entry.update(recovery='generation_resumed',recovery_evidence={'step_index': index,'type': step['type'],'status': step['status'],'scope': 'generation returned a completed response; does not resolve tool failures'})
            generation_pending=[]
    unresolved=[x['step_index'] for x in history if x['recovery']=='unverified']
    return clean({'error_history': history,'unresolved_issue_indices': unresolved,
        'recovered_issue_count': len(history)-len(unresolved),
        'assessment': 'unresolved_history' if unresolved else ('observed_recoveries' if history else 'no_observed_errors'),
        'note': 'Historical issues are not current blocking proof. Exact retry success does not certify side effects or task acceptance.'})

class Progress:
    def __init__(self):self.seen={}
    def changes(self,steps,offset=0):
        changes=[]
        for i,st in enumerate(steps,offset):
            item={'index': i,'type': st.get('type'),'status': st.get('status')}
            issue=step_issue(st)
            if issue:item['error']=issue
            if self.seen.get(i)!=item:
                changes.append(item);self.seen[i]=item
        return changes

def classify(steps):
    responses=[];issues=[];tools=[];terminal_errors=[]
    for st in steps:
        typ=st.get('type','')
        if typ=='CORTEX_STEP_TYPE_PLANNER_RESPONSE':
            p=st.get('plannerResponse',{});response=p.get('modifiedResponse') or p.get('response') or '';responses.append(response)
            if response and st.get('status')=='CORTEX_STEP_STATUS_DONE':terminal_errors=[]
        elif typ not in ('CORTEX_STEP_TYPE_USER_INPUT','CORTEX_STEP_TYPE_ERROR_MESSAGE'):
            tools.append(typ)
        issue=step_issue(st)
        if issue:issues.append(issue)
        if typ=='CORTEX_STEP_TYPE_ERROR_MESSAGE' and issue:terminal_errors.append(issue)
    # Historical tool failures remain review evidence; they do not make a known
    # finished invocation uncertain. Only explicit generator error steps classify
    # backend 500/503, never file contents or a tool's quoted output.
    blob=json.dumps(terminal_errors)
    code='SERVICE_UNAVAILABLE' if re.search(r'\b503\b|No capacity available',blob,re.IGNORECASE) else ('SERVICE_INTERNAL_ERROR' if re.search(r'\b500\b|Internal error',blob,re.IGNORECASE) else ('AGENT_ERROR' if terminal_errors else None))
    return next((x for x in reversed(responses) if x),''),issues,tools,code


def efficiency(steps, elapsed, remaining):
    files={};models=0;edits=0;failed=0
    for step in steps:
        typ=step.get('type','');models+=typ=='CORTEX_STEP_TYPE_PLANNER_RESPONSE'
        failed+=step_issue(step) is not None
        if typ in ('CORTEX_STEP_TYPE_CODE_ACTION','CORTEX_STEP_TYPE_WRITE_TO_FILE') and step.get('status')=='CORTEX_STEP_STATUS_DONE':edits+=1
        view=step.get('viewFile')
        if view:
            path=view.get('absolutePathUri','unknown');entry=files.setdefault(path,{'reads': 0,'overlapping_reads': 0,'ranges': []})
            entry['reads']+=1
            if 'endLine' in view:
                lo=view.get('startLine',0);hi=view['endLine']
                if any(lo<=b and hi>=a for a,b in entry['ranges']):entry['overlapping_reads']+=1
                entry['ranges'].append((lo,hi))
    repeated=[{'path': p,'reads': v['reads'],'overlapping_reads': v['overlapping_reads']} for p,v in files.items() if v['reads']>1]
    repeated.sort(key=lambda x:x['reads'],reverse=True)
    return {'model_rounds': models,'file_reads': sum(v['reads'] for v in files.values()),'unique_files': len(files),'repeated_files': repeated[:5],'observed_edit_steps': edits,'tool_issues': failed,'elapsed_seconds': round(elapsed),'remaining_seconds': max(0,round(remaining)),'note': 'Edit steps are observable tool events, not a git diff or delivery verdict.'}

def execution_limit():
    value=read(STATE/'config.json',{}).get('max_concurrency',2)
    if type(value) is not int or not 1<=value<=4:raise Failure('INVALID_CONCURRENCY','max_concurrency must be an integer from 1 to 4.')
    return value

def slot_path(slot,kind):
    return STATE/(kind+('' if slot==0 else '-'+str(slot))+('.lock' if kind=='execution' else '.json'))

def active_records():
    return [dict(d,slot=slot) for slot in range(4) if (d:=read(slot_path(slot,'active')))]

def queue_view(active):
    records=([active] if isinstance(active,dict) else active) or []
    owners={(x.get('task'),x.get('pid')) for x in records}
    items=[read(q) for q in sorted((STATE/'queue').glob('*.json'))]
    return [x for x in items if alive(x['pid']) and 'slot' not in x and (x['task'],x['pid']) not in owners]

NUDGE = '当前进展如何？若受阻请说明具体原因；若仍有未完成工作，请在原授权范围内继续。不要重复已完成操作，不要扩大任务范围。'

class StallWatch:
    def __init__(self, now, threshold=300):
        self.threshold=threshold;self.last_progress=now;self.fingerprint=None
        self.nudged=False;self.last_check=now
    def observe(self, steps, now):
        # Ignore transport/status heartbeats and metadata timestamps. Include
        # generated content lengths and tool output so real work resets the clock.
        meaningful=[]
        for step in steps:
            payload={k:v for k,v in step.items() if k!='metadata'}
            meaningful.append(payload)
        fingerprint=hashlib.sha256(json.dumps(meaningful,sort_keys=True).encode()).digest()
        if fingerprint!=self.fingerprint:
            self.fingerprint=fingerprint;self.last_progress=now
        return now-self.last_progress>=self.threshold and now-self.last_check>=self.threshold
    def decision(self, current, steps, now):
        self.last_check=now
        if self.nudged:return 'still_stalled'
        if current.get('status')!=IDLE:return 'active_or_unknown'
        if any(x.get('status') in ('CORTEX_STEP_STATUS_GENERATING','CORTEX_STEP_STATUS_RUNNING','CORTEX_STEP_STATUS_PENDING') for x in steps):
            return 'active_or_unknown'
        if turn_has_result(steps):return 'completed'
        return 'nudge'

def turn_has_result(steps):
    last_user=max((i for i,s in enumerate(steps) if s.get('type')=='CORTEX_STEP_TYPE_USER_INPUT'),default=-1)
    if last_user<0:return False
    return any(s.get('type') in ('CORTEX_STEP_TYPE_PLANNER_RESPONSE','CORTEX_STEP_TYPE_ERROR_MESSAGE') for s in steps[last_user+1:])

def run_task(args):
    task=args.task; path=STATE/'tasks'/(task+'.json'); deadline=time.monotonic()+args.timeout
    ticket=STATE/'queue'/(f'{time.time_ns():020d}-'+uuid.uuid4().hex+'.json')
    with guard():
        for q in (STATE/'queue').glob('*.json'):
            d=read(q)
            if not alive(d['pid']):q.unlink();continue
            if d['task']==task:raise Failure('TASK_BUSY','Task is already queued or running.')
        rec=read(path)
        if rec:
            if rec['cwd']!=args.cwd or rec['mode']!=args.mode:raise Failure('CONTEXT_MISMATCH')
            if args.conversation and args.conversation!=rec['conversation_id']:raise Failure('CONVERSATION_MISMATCH')
            if rec['state']=='uncertain' and not args.ack_uncertain:raise Failure('OUTCOME_UNCERTAIN','Inspect result and desktop before acknowledged continuation.')
        elif args.conversation:raise Failure('IMPORT_UNSUPPORTED','Use a new managed task; existing desktop sessions are not imported automatically.')
        save(ticket,{'task': task,'pid': os.getpid()});event(task,'queued')
    lock=None;active=False;backend=None;cid=None;sent=False;active_path=None
    try:
        while True:
            if getattr(args,'cancel_requested',lambda:False)():raise Failure('CANCELED','Canceled before execution.')
            if time.monotonic()>=deadline:raise Failure('QUEUE_TIMEOUT','No task executed.')
            with guard():
                queued=[]
                owners={(x['task'],x['pid']) for x in active_records()}
                for q in sorted((STATE/'queue').glob('*.json')):
                    if not alive(read(q)['pid']):q.unlink()
                    elif 'slot' not in read(q) and (read(q)['task'],read(q)['pid']) not in owners:queued.append(q)
                if queued and queued[0]==ticket:
                    # Slot zero retains the legacy lock so existing callers remain safe.
                    for slot in sorted(range(execution_limit()),key=lambda n:bool(read(slot_path(n,'active')))):
                        candidate=slot_path(slot,'execution').open('a')
                        try:fcntl.flock(candidate,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:candidate.close();continue
                        lock=candidate;active=True;active_path=slot_path(slot,'active')
                        save(ticket,{'task': task,'pid': os.getpid(),'slot': slot})
                        break
            if active:break
            time.sleep(.2)
        if getattr(args,'cancel_requested',lambda:False)():raise Failure('CANCELED','Canceled before execution.')
        backend=Desktop(task=task)
        # A caller can die while the desktop keeps executing. Reconcile the prior
        # owned session before allowing another run; never replay its prompt.
        previous=read(active_path)
        if previous:
            oldcid=previous['conversation_id']
            if backend.trajectory(oldcid).get('status')!=IDLE:
                raise Failure('PREVIOUS_TASK_RUNNING','Inspect '+previous['task']+' in desktop; no new task started.')
            oldpath=STATE/'tasks'/(previous['task']+'.json');old=read(oldpath)
            if old and old['state']=='running':old['state']='uncertain';save(oldpath,old)
            (active_path).unlink(missing_ok=True)
        rec=read(path)
        if rec and rec['state']=='running':
            rec['state']='uncertain';save(path,rec)
        if rec and rec['state']=='uncertain' and not args.ack_uncertain:raise Failure('OUTCOME_UNCERTAIN')
        project=backend.resolve_project(args.cwd)
        if rec and rec.get('project',{}).get('project_id')!=project['project_id']:
            raise Failure('PROJECT_CONTEXT_MISMATCH','Use a new task for an unbound or different project; old conversations are not reassigned.')
        emit(event(task,'project_bound',project=project))
        models=backend.rpc('GetCascadeModelConfigData',{}).get('clientModelConfigs',[])
        model_map={m['label']:m['modelOrAlias'] for m in models}
        index=(rec or {}).get('model_index',0)
        if MODELS[index] not in model_map:raise Failure('MODEL_UNAVAILABLE',MODELS[index])
        cid=(rec or {}).get('conversation_id') or str(uuid.uuid4())
        if rec is None:
            rec={'task': task,'cwd': args.cwd,'mode': args.mode,'project': project,'conversation_id': cid,'state': 'creating','model_index': index,'turn': 0}
            save(path,rec)
            backend.rpc('StartCascade',{'cascadeId':cid,'projectEnvConfig':{'projectId':project['project_id'],'defaultProjectEnvironment':{}},'trajectoryType':'CORTEX_TRAJECTORY_TYPE_CASCADE','source':'CORTEX_TRAJECTORY_SOURCE_CASCADE_CLIENT'})
        baseline=backend.trajectory(cid)
        expose(task,'GetCascadeTrajectory:baseline',baseline)
        readiness=conversation_state(baseline)
        diagnostic('continuation_check',task_id=task,conversation_id=cid,
                   source='desktop_conversation',**readiness)
        if readiness['readiness']!='ready':
            code='TASK_BUSY' if readiness['readiness']=='busy' else 'DESKTOP_STATE_UNKNOWN'
            diagnostic('continuation_rejected',task_id=task,conversation_id=cid,
                       source='desktop_conversation',error_code=code,accepted=False,queued=False,**readiness)
            raise Failure(code,json.dumps(dict(source='desktop_conversation',accepted=False,
                                              queued=False,**readiness)))
        rec.update(state='running',turn=rec.get('turn',0)+1,updated_at=time.time(),recovery=recovery_state([]),efficiency=None)
        save(path,rec);save(active_path,{'task': task,'conversation_id': cid,'pid': os.getpid()})
        event(task,'started',conversation_id=cid,backend_pid=backend.pid,slot=slot,execution_limit=execution_limit(),queue_seconds=round(args.timeout-(deadline-time.monotonic()),3))
        attempts=[];watch=StallWatch(time.monotonic());work_started=time.monotonic();next_efficiency=work_started+60;turn_start=len(baseline.get('trajectory',{}).get('steps',[]))
        while True:
            before=len(baseline.get('trajectory',{}).get('steps',[]));stream=Updates(backend,cid,task);stream.start()
            try:
                if time.monotonic()>=deadline:raise Failure('TIMEOUT')
                backend_log=Path.home()/'Library/Logs/Antigravity/language_server.log'
                log_offset=backend_log.stat().st_size if backend_log.exists() else 0
                diagnostics=[]
                sent=True
                backend.rpc('SendUserCascadeMessage',{'cascadeId':cid,'items':[{'text':args.prompt}],'cascadeConfig':{'plannerConfig':{'requestedModel':model_map[MODELS[index]]}},'propagateError':True},timeout=max(.1,min(15,deadline-time.monotonic())))
                progress=Progress();next_recovery=0;recovery_snapshot=baseline
                while time.monotonic()<deadline:
                    if getattr(args,'cancel_requested',lambda:False)():raise Failure('CANCELED','Cancellation requested by caller.')
                    if backend_log.exists():
                        with backend_log.open('rb') as native:
                            if native.seek(0,2)<log_offset:log_offset=0
                            native.seek(log_offset);data=native.read();log_offset=native.tell()
                        for line in data.decode(errors='replace').splitlines():
                            if re.search(r'code 50[03]|No capacity available|Internal error',line,re.IGNORECASE):
                                detail=clean(line[:2000]);diagnostics.append(detail)
                                event(task,'backend_window_error',attribution='shared_desktop_time_window',detail=detail)
                    current=stream.snapshot()
                    if time.monotonic()>=next_recovery:
                        recovery_snapshot=backend.trajectory(cid);expose(task,'GetCascadeTrajectory:recovery',recovery_snapshot);next_recovery=time.monotonic()+30
                    if current is None or not current.get('status'):current=recovery_snapshot
                    steps=current.get('trajectory',{}).get('steps',[])[before:]
                    changes=progress.changes(steps,before)
                    recovery=recovery_state(current.get('trajectory',{}).get('steps',[])[turn_start:],turn_start)
                    if changes or recovery!=rec.get('recovery'):
                        rec['recovery']=recovery;save(path,rec)
                        item=event(task,'progress',conversation_id=cid,changes=changes,recovery=rec['recovery'])
                        emit(item)
                    if time.monotonic()>=next_efficiency:
                        metrics=efficiency(current.get('trajectory',{}).get('steps',[])[turn_start:],time.monotonic()-work_started,deadline-time.monotonic())
                        rec['efficiency']=metrics;save(path,rec)
                        item=event(task,'efficiency',**metrics)
                        emit(item)
                        next_efficiency=time.monotonic()+60
                    if watch.observe(steps,time.monotonic()):
                        fresh=backend.trajectory(cid)
                        expose(task,'GetCascadeTrajectory:stall',fresh)
                        fresh_steps=fresh.get('trajectory',{}).get('steps',[])[before:]
                        if watch.observe(fresh_steps,time.monotonic()):
                            action=watch.decision(fresh,fresh_steps,time.monotonic())
                            item=event(task,'stall_check',action=action,inactive_seconds=round(time.monotonic()-watch.last_progress),conversation_id=cid)
                            emit(item)
                            if action=='nudge' and deadline-time.monotonic()>1:
                                # Reserve before the mutation: an ambiguous response
                                # must never cause a duplicate follow-up.
                                watch.nudged=True
                                rec['nudge_attempted_at']=time.time();save(path,rec)
                                event(task,'nudge_attempted',conversation_id=cid,delivery='WHEN_IDLE')
                                backend.rpc('SendUserCascadeMessage',{'cascadeId':cid,'items':[{'text':NUDGE}],'deliveryStrategy':'MESSAGE_DELIVERY_STRATEGY_WHEN_IDLE','cascadeConfig':{'plannerConfig':{'requestedModel':model_map[MODELS[index]]}}},timeout=max(.1,min(15,deadline-time.monotonic())))
                                watch.last_progress=time.monotonic()
                                continue
                    # IDLE alone is not enough: require this turn's user step and
                    # an actual response or error, avoiding pre-send cached state.
                    if conversation_state(current)['readiness']=='ready' and turn_has_result(steps):
                        current=backend.trajectory(cid)
                        expose(task,'GetCascadeTrajectory:final',current)
                        steps=current.get('trajectory',{}).get('steps',[])[before:]
                        if conversation_state(current)['readiness']=='ready' and turn_has_result(steps):break
                    stream.changed.wait(1);stream.changed.clear()
                else:raise Failure('TIMEOUT')
                response,errors,tools,code=classify(steps)
                executors=current.get('trajectory',{}).get('executorMetadatas',[])
                if executors and 'CANCELED' in executors[-1].get('terminationReason',''):
                    code='TASK_CANCELED'
                attempt={'model': MODELS[index],'error': code,'tools': tools,'stream_frames': stream.frames,'stream_error': stream.error,'stream_reconnects': stream.reconnects,'backend_window_errors': diagnostics}
                attempts.append(attempt)
                log=STATE/'logs'/(task+'--turn-'+str(rec['turn'])+'--attempt-'+str(len(attempts))+'.json')
                save(log,clean({'conversation_id': cid,'steps': steps,'attempt': attempt}))
                event(task,'attempt_finished',**attempt)
                if code in ('SERVICE_UNAVAILABLE','SERVICE_INTERNAL_ERROR') and not tools and not args.no_fallback and index<2 and time.monotonic()<deadline:
                    if MODELS[index+1] not in model_map:break
                    index+=1
                    rec['model_index']=index;save(path,rec);baseline=current
                    event(task,'fallback',model=MODELS[index]);continue
                break
            finally:stream.close()
        metrics=efficiency(current.get('trajectory',{}).get('steps',[])[turn_start:],time.monotonic()-work_started,deadline-time.monotonic())
        rec['efficiency']=metrics
        emit(event(task,'efficiency',**metrics))
        outcome='uncertain' if code=='TASK_CANCELED' else ('turn_failed' if code or not response else 'turn_returned')
        result={'status': 'ERROR' if code or not response else ('REVIEW_REQUIRED' if errors else 'TURN_COMPLETE'),'error': code,'conversation_id': cid,'project': project,'backend': 'desktop','backend_pid': backend.pid,'model': MODELS[index],'result': {'status': 'ERROR' if code or not response else 'SUCCESS','response': response},'issues': errors,'recovery': recovery_state(current.get('trajectory',{}).get('steps',[])[turn_start:],turn_start),'outcome': outcome,'attempts': attempts,'nudge_attempted': watch.nudged,'efficiency': metrics,'log_file': str(log),'task': task}
        rec.update(state='uncertain' if outcome=='uncertain' else 'idle',last_result=result,model_index=index)
        save(path,rec);save(STATE/'logs'/(task+'--turn-'+str(rec['turn'])+'.summary.json'),clean(result))
        (active_path).unlink(missing_ok=True)
        event(task,'finished',status=result['status'],conversation_id=cid)
        # Retention is best effort and must never turn a completed task into failure.
        with guard():
            files=[]
            for f in ([] if active_records() else (STATE/'logs').glob('*')):
                if f.suffix not in ('.json','.jsonl'):continue
                try:files.append((f,f.stat()))
                except FileNotFoundError:continue
            size=0
            for f,info in sorted(files,key=lambda x:x[1].st_mtime,reverse=True):
                size+=info.st_size
                if time.time()-info.st_mtime>7*86400 or size>100*1024*1024:
                    try:f.unlink(missing_ok=True)
                    except OSError:pass
        return result
    except BaseException as exc:
        code=exc.code if isinstance(exc,Failure) else type(exc).__name__
        canceled=None
        if sent and backend and cid:
            try:canceled=backend.cancel(cid)
            except Exception:canceled=False  # noqa: BLE001
        if cid:
            if backend:
                try:
                    evidence=backend.trajectory(cid)
                    expose(task,'GetCascadeTrajectory:failure',evidence)
                    if 'turn_start' in locals():
                        rec['efficiency']=efficiency(evidence.get('trajectory',{}).get('steps',[])[turn_start:],time.monotonic()-work_started,deadline-time.monotonic())
                        save(path,rec)
                        emit(event(task,'efficiency',**rec['efficiency']))
                    save(STATE/'logs'/(task+'--failure-'+str(time.time_ns())+'.json'),clean(evidence))
                except Exception:pass  # noqa: BLE001, S110
            rec=read(path,{})
            result={'status': 'ERROR','error': code,'outcome': 'uncertain' if sent else 'not_executed','conversation_id': cid,'cancel_confirmed': canceled,'task': task,'efficiency': rec.get('efficiency')}
            # A rejected continuation must not overwrite the previous delivered turn.
            if sent or code not in ('TASK_BUSY','DESKTOP_STATE_UNKNOWN'):
                rec.update(state='uncertain' if sent else 'failed',last_result=result);save(path,rec)
            if canceled or not sent:(active_path).unlink(missing_ok=True)
        event(task,'failed',error=code,cancel_confirmed=canceled)
        raise
    finally:
        with guard():ticket.unlink(missing_ok=True)
        if lock:lock.close()


def main():
    os.umask(0o077)
    for d in [STATE,STATE/'tasks',STATE/'queue',STATE/'logs']:d.mkdir(parents=True,exist_ok=True)
    p=argparse.ArgumentParser();p.add_argument('action',choices=['run','ping','status','result','retire'])
    p.add_argument('--task');p.add_argument('--mode',default='research',choices=['research','logs','implement']);p.add_argument('--cwd',default=os.getcwd());p.add_argument('--timeout',type=float,default=600);p.add_argument('--json',action='store_true');p.add_argument('--all',action='store_true');p.add_argument('--conversation');p.add_argument('--ack-uncertain',action='store_true');p.add_argument('--no-fallback',action='store_true');p.add_argument('prompt',nargs='?')
    a=p.parse_intermixed_args();a.cwd=str(Path(a.cwd).resolve())
    try:
        if a.task is not None and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}',a.task):raise Failure('INVALID_TASK_ID')
        if a.action=='run':
            if not a.task or not a.prompt or not math.isfinite(a.timeout) or a.timeout<=0:raise Failure('INVALID_REQUEST')
            result=run_task(a)
        elif a.action=='ping':
            b=Desktop();result={'status': 'OK','backend': 'desktop','backend_pid': b.pid,'execution_limit': execution_limit(),'cli_workers': 0}
        elif a.action=='status':
            with guard():
                records=active_records();active=records[0] if records else None
                result={'status': 'OK','backend': 'desktop','execution_limit': execution_limit(),'active': active,'active_tasks': records,'queued': queue_view(records),'efficiency': (read(STATE/'tasks'/(active['task']+'.json'),{}).get('efficiency') if active else None),'task_record': read(STATE/'tasks'/(a.task+'.json')) if a.task else None}
        elif a.action=='result':
            result=(read(STATE/'tasks'/(a.task+'.json'),{}) if a.task else {}).get('last_result') or {'status': 'ERROR','error': 'NO_RESULT'}
        else:
            # Retirement releases the managed task, not the shared desktop process
            # or its history. Exact conversation can still resume with the same ID.
            with guard():
                targets=list((STATE/'tasks').glob('*.json')) if a.all else ([STATE/'tasks'/(a.task+'.json')] if a.task else [])
                queued={read(q)['task'] for q in (STATE/'queue').glob('*.json') if alive(read(q)['pid'])}
                if any(x.stem in queued or read(x,{}).get('state')=='running' for x in targets):raise Failure('TASK_BUSY')
                for x in targets:
                    rec=read(x)
                    if rec and rec.get('state')!='uncertain':rec['state']='retired';save(x,rec)
                result={'status': 'OK','retired': [x.stem for x in targets]}
    except Exception as exc:  # noqa: BLE001
        result={'status': 'ERROR','error': exc.code if isinstance(exc,Failure) else type(exc).__name__,'message': clean(exc.message if isinstance(exc,Failure) else str(exc))}
    print(json.dumps(clean(result),ensure_ascii=False,indent=2) if a.json else (result.get('result',{}).get('response') or json.dumps(clean(result),ensure_ascii=False)))
    return 0 if result.get('status') in ('OK','TURN_COMPLETE') else 1

if __name__=='__main__':
    sys.exit(main())
