from __future__ import annotations
import hashlib,json,os,platform,subprocess
from datetime import datetime,timezone
from pathlib import Path

def utc_now(): return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def sha256_file(p):
    h=hashlib.sha256();
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()
def environment():
    d={'timestamp_utc':utc_now(),'python':platform.python_version(),'platform':platform.platform(),'machine':platform.machine(),'pid':os.getpid()}
    try:d['requests_version']=__import__('requests').__version__
    except Exception:d['requests_version']=None
    try:d['git_commit']=subprocess.check_output(['git','rev-parse','HEAD'],stderr=subprocess.DEVNULL,text=True).strip()
    except Exception:d['git_commit']=None
    return d
def write_json(p,payload): p.write_text(json.dumps(payload,indent=2,sort_keys=True)+'\n',encoding='utf-8')
def write_report(p,r):
    o=r.get('observation',{}); lines=['# PatchWarden R1 — Runtime Reproduction Report','',f'- Run ID: `{r.get("run_id")}`',f'- Status: **{r["status"]}**',f'- Generated UTC: `{r["generated_at"]}`',f'- Target: `{r["target"]["cve_id"]}`',f'- Observed Requests: `{r["target"]["observed_version"]}`','', '## Runtime observation','',f'- Final HTTP status: `{o.get("http_status")}`',f'- Final URL: `{o.get("final_url")}`',f'- Destination received Proxy-Authorization: `{o.get("proxy_authorization_present")}`',f'- Credential match: `{o.get("credential_match")}`',f'- Destination request: `{o.get("destination_request_line")}`','', '## Health gates','']
    lines += [f'- {k}: `{v.get("ok")}` ({v.get("http_status",v.get("port",""))})' for k,v in r.get('health',{}).items()]
    lines += ['', '## Result semantics','', '`CONFIRMED_VULNERABLE` is emitted only when the live destination observed the runtime-generated credential on the redirected request.', '`FIXED` is emitted only when the destination completed the same flow without the prohibited header.', '`UNEXPECTED_FAILURE` means no trustworthy security conclusion was established.', '', 'No observed security result is hardcoded or fabricated.']
    if r.get('errors'): lines += ['', '## Errors','']+[f'- `{e["type"]}`: {e["message"]}' for e in r['errors']]
    p.write_text('\n'.join(lines)+'\n',encoding='utf-8')
def write_manifest(root,output):
    files=[]
    for p in sorted(root.rglob('*')):
        if p.is_file() and p!=output: files.append({'path':str(p.relative_to(root)),'sha256':sha256_file(p),'bytes':p.stat().st_size})
    write_json(output,{'generated_at':utc_now(),'algorithm':'SHA-256','files':files})
