from __future__ import annotations
import base64, hashlib, http.client, http.server, os, select, socket, ssl, subprocess, tempfile, threading, time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

LOOPBACK = '127.0.0.1'
ORIGIN_HOST = 'origin.local'
DESTINATION_HOST = 'destination.local'

@dataclass(frozen=True)
class RuntimeCredentials:
    user: str
    password: str
    @property
    def authorization(self):
        token = base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        return f'Basic {token}'
    @property
    def fingerprint(self):
        return hashlib.sha256(self.authorization.encode()).hexdigest()

def _credentials():
    return RuntimeCredentials('r1-' + os.urandom(8).hex(), os.urandom(24).hex())

def _free_port():
    with socket.socket() as s:
        s.bind((LOOPBACK, 0)); return s.getsockname()[1]

@dataclass
class Observation:
    lock: threading.Lock = field(default_factory=threading.Lock)
    headers: dict[str,str] = field(default_factory=dict)
    request_line: str = ''
    received_at: str | None = None
    def record(self, line, headers):
        with self.lock:
            self.request_line=line; self.headers=dict(headers); self.received_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    def snapshot(self):
        with self.lock: return self.request_line, dict(self.headers), self.received_at

class OriginHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        loc=self.server.redirect_location
        body=b'R1 origin redirect\n'; self.send_response(302); self.send_header('Location',loc); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass

class DestinationHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.observation.record(self.requestline, dict(self.headers))
        body=b'R1 local destination OK\n'; self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass

class LocalHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address=True; daemon_threads=True

class AllowlistedProxy:
    def __init__(self, destination_port, origin_port):
        self.destination_port=destination_port; self.origin_port=origin_port
        self.server=socket.socket(); self.server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); self.server.bind((LOOPBACK,0)); self.port=self.server.getsockname()[1]; self.server.listen(16); self.server.settimeout(.25)
        self.stop=threading.Event(); self.thread=threading.Thread(target=self._serve,daemon=True)
    def _read(self,s):
        data=bytearray()
        while b'\r\n\r\n' not in data:
            c=s.recv(4096)
            if not c: break
            data.extend(c)
            if len(data)>65536: raise ValueError('headers exceed 64 KiB')
        return bytes(data)
    def start(self): self.thread.start()
    def close(self):
        self.stop.set()
        try:self.server.close()
        except OSError:pass
        self.thread.join(2)
    def _serve(self):
        while not self.stop.is_set():
            try:c,_=self.server.accept()
            except (OSError,socket.timeout):continue
            threading.Thread(target=self._handle,args=(c,),daemon=True).start()
    def _handle(self,c):
        try:
            raw=self._read(c)
            if not raw:return
            first=raw.split(b'\r\n',1)[0].decode('latin1','replace')
            if first.upper().startswith('CONNECT '): self._connect(c,raw); return
            parts=first.split(); target=parts[1] if len(parts)>1 else ''
            u=urlsplit(target)
            if u.scheme!='http' or u.hostname!=ORIGIN_HOST or u.port!=self.origin_port: raise ValueError('proxy allowlist rejected origin')
            up=socket.create_connection((LOOPBACK,self.origin_port),3)
            try:
                path=u.path or '/'; path += ('?'+u.query) if u.query else ''
                lines=raw.split(b'\r\n'); lines[0]=f'GET {path} HTTP/1.1'.encode(); up.sendall(b'\r\n'.join(lines))
                while True:
                    chunk=up.recv(65536)
                    if not chunk:break
                    c.sendall(chunk)
            finally:up.close()
        except Exception as e:
            msg=str(e).replace('\r',' ').replace('\n',' ')[:200]
            try:c.sendall(f'HTTP/1.1 500 Internal Server Error\r\nContent-Length: {len(msg)}\r\n\r\n{msg}'.encode())
            except OSError:pass
        finally:
            try:c.close()
            except OSError:pass
    def _connect(self,c,raw):
        target=raw.split(b'\r\n',1)[0].split()[1].decode('ascii'); host,port=target.rsplit(':',1); port=int(port)
        if host!=DESTINATION_HOST or port!=self.destination_port: raise ValueError('proxy allowlist rejected destination')
        up=socket.create_connection((LOOPBACK,self.destination_port),3); c.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n'); self._tunnel(c,up)
    def _tunnel(self,a,b):
        try:
            while True:
                rd,_,bad=select.select([a,b],[],[a,b],5)
                if bad:return
                for src in rd:
                    data=src.recv(65536)
                    if not data:return
                    (b if src is a else a).sendall(data)
        finally:
            for s in (a,b):
                try:s.close()
                except OSError:pass

class LocalRig:
    def __init__(self):
        self.credentials=_credentials(); self.observation=Observation(); self.origin_port=_free_port(); self.destination_port=_free_port()
        self.origin=LocalHTTPServer((LOOPBACK,self.origin_port),OriginHandler); self.destination=LocalHTTPServer((LOOPBACK,self.destination_port),DestinationHandler); self.destination.observation=self.observation
        self.origin.redirect_location=f'https://{DESTINATION_HOST}:{self.destination_port}/final'
        self.proxy=AllowlistedProxy(self.destination_port,self.origin_port)
        self.tmp=Path(tempfile.mkdtemp(prefix='patchwarden-r1-cert-')); self.cert=self.tmp/'cert.pem'; self.key=self.tmp/'key.pem'; self._cert()
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(self.cert,self.key); self.destination.socket=ctx.wrap_socket(self.destination.socket,server_side=True)
    def _cert(self):
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-keyout',str(self.key),'-out',str(self.cert),'-subj',f'/CN={DESTINATION_HOST}','-addext',f'subjectAltName=DNS:{DESTINATION_HOST},IP:127.0.0.1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def start(self):
        for s in (self.origin,self.destination): threading.Thread(target=s.serve_forever,kwargs={'poll_interval':.05},daemon=True).start()
        self.proxy.start()
    def health(self):
        out={}
        try:
            c=http.client.HTTPConnection(ORIGIN_HOST,self.origin_port,2); c.request('GET','/health'); r=c.getresponse(); r.read(); out['origin']={'ok':r.status==302,'http_status':r.status,'host':ORIGIN_HOST,'port':self.origin_port}; c.close()
        except Exception as e: out['origin']={'ok':False,'error':type(e).__name__,'message':str(e)}
        try:
            ctx=ssl._create_unverified_context(); c=http.client.HTTPSConnection(DESTINATION_HOST,port=self.destination_port,timeout=2,context=ctx); c.request('GET','/health'); r=c.getresponse(); r.read(); out['destination']={'ok':r.status==200,'tls':True,'http_status':r.status,'host':DESTINATION_HOST,'port':self.destination_port}; c.close()
        except Exception as e: out['destination']={'ok':False,'error':type(e).__name__,'message':str(e)}
        try:
            with socket.create_connection((LOOPBACK,self.proxy.port),2): pass
            out['proxy']={'ok':True,'host':LOOPBACK,'port':self.proxy.port}
        except Exception as e: out['proxy']={'ok':False,'error':type(e).__name__,'message':str(e)}
        return out
    def close(self):
        self.proxy.close(); self.origin.shutdown(); self.destination.shutdown(); self.origin.server_close(); self.destination.server_close()
        try:self.cert.unlink(); self.key.unlink(); self.tmp.rmdir()
        except OSError:pass
