"""Loopback-only integration service for the uploaded PatchWarden pipeline."""
from __future__ import annotations
import argparse
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / 'backend'
STATE = ROOT / 'state'
sys.path.insert(0, str(BACKEND))
from pipeline.report import load_report
from pipeline.backends import BobSessionBackend, BobVerdictMissing
from pipeline.schema import VerdictSchemaError

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    os.replace(temp, path)

def configure_environment():
    # Use the installed Git OpenSSL only for the local TLS reproduction harness.
    for directory in ('C:/Program Files/Git/usr/bin', 'C:/Program Files/Git/mingw64/bin'):
        if (Path(directory) / 'openssl.exe').exists():
            os.environ['PATH'] = directory + os.pathsep + os.environ.get('PATH', '')
            break

def fixture_catalog():
    items = []
    for path in sorted((BACKEND / 'fixtures').glob('*.md')):
        report = load_report(path)
        try:
            verdict = BobSessionBackend(BACKEND / 'bob_sessions').triage(report).to_dict()
            bob = {'available': True, 'verdict': verdict, 'source': 'Imported Bob session export; not a new live Bob run.'}
        except (BobVerdictMissing, VerdictSchemaError, ValueError) as exc:
            bob = {'available': False, 'detail': str(exc)}
        items.append({'id': path.stem, 'title': report.title or path.stem,
                      'body': report.body, 'metadata': report.metadata,
                      'references': report.references, 'bob': bob})
    return items

def verify_sample(label):
    if label not in ('vulnerable', 'fixed'):
        raise ValueError('Unknown evidence set')
    directory = BACKEND / 'r1ultra' / 'sample-evidence' / label
    manifest = json.loads((directory / 'evidence-manifest.sha256.json').read_text())
    checks = []
    for entry in manifest['files']:
        relative = entry['path']
        if relative not in ('r1-result.json', 'r1-report.md'):
            raise ValueError('Unexpected evidence file')
        raw = (directory / relative).read_bytes()
        actual = hashlib.sha256(raw).hexdigest()
        checks.append({'file': relative, 'expected': entry['sha256'], 'actual': actual,
                       'verified': secrets.compare_digest(actual, entry['sha256'])})
    return {'label': label, 'source': 'Imported archived evidence from ZIP',
            'verified': len(checks) == 2 and all(c['verified'] for c in checks),
            'checks': checks, 'result': json.loads((directory / 'r1-result.json').read_text()),
            'report': (directory / 'r1-report.md').read_text(encoding='utf-8'), 'manifest': manifest}

class Application:
    def __init__(self, state=STATE):
        self.state = Path(state)
        self.state.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.active = None
        # Interrupted runs remain visible after a process restart.
        for path in self.state.glob('*/job.json'):
            try:
                job = json.loads(path.read_text(encoding='utf-8'))
                if job['status'] in ('queued', 'running'):
                    job.update(status='interrupted', detail='Service stopped before this run completed.', finished_at=now())
                    atomic_json(path, job)
            except (ValueError, KeyError, OSError):
                continue

    def jobs(self):
        with self.lock:
            jobs = []
            for path in self.state.glob('*/job.json'):
                try:
                    jobs.append(json.loads(path.read_text(encoding='utf-8')))
                except (OSError, ValueError):
                    continue
            return sorted(jobs, key=lambda j: j['created_at'], reverse=True)

    def get(self, job_id):
        if len(job_id) != 24 or any(c not in '0123456789abcdef' for c in job_id):
            raise ValueError('Invalid run identifier')
        path = self.state / job_id / 'job.json'
        if not path.exists():
            raise FileNotFoundError('Run not found')
        with self.lock:
            return json.loads(path.read_text(encoding='utf-8'))

    def create(self, payload):
        if not isinstance(payload, dict):
            raise ValueError('Expected a JSON object')
        if set(payload) - {'report_id', 'text', 'backend', 'reproduce'}:
            raise ValueError('Unsupported request field')
        backend = payload.get('backend', 'engine')
        reproduce = payload.get('reproduce', True)
        if backend not in ('engine', 'bob') or not isinstance(reproduce, bool):
            raise ValueError('Invalid backend or reproduction option')
        report_id = payload.get('report_id')
        text = payload.get('text')
        fixtures = {p.stem: p for p in (BACKEND / 'fixtures').glob('*.md')}
        if report_id is not None:
            if not isinstance(report_id, str) or report_id not in fixtures or text is not None:
                raise ValueError('Choose one known fixture or supply report text')
        elif not isinstance(text, str) or not text.strip() or len(text.encode('utf-8')) > 64000:
            raise ValueError('Report text must contain 1–64,000 UTF-8 bytes')
        if backend == 'bob' and report_id is None:
            raise ValueError('Bob session exports are available only for bundled reports')
        with self.lock:
            if self.active:
                raise RuntimeError('A run is already active. Wait for it to finish.')
            job_id = secrets.token_hex(12)
            folder = self.state / job_id
            folder.mkdir()
            report_path = fixtures[report_id] if report_id else folder / 'submitted-report.md'
            if text is not None:
                report_path.write_text(text, encoding='utf-8')
            report = load_report(report_path)
            job = {'id': job_id, 'report_id': report_id, 'title': report.title or 'Submitted report',
                   'status': 'queued', 'backend': backend, 'reproduce': reproduce,
                   'created_at': now(), 'detail': 'Waiting for the local pipeline.', 'record': None}
            atomic_json(folder / 'job.json', job)
            self.active = job_id
            threading.Thread(target=self._run, args=(job, report_path), daemon=True).start()
            return job

    def _run(self, job, report_path):
        folder = self.state / job['id']
        try:
            with self.lock:
                job.update(status='running', detail='Running report triage and optional localhost reproduction.')
                atomic_json(folder / 'job.json', job)
            args = [sys.executable, str(ROOT / 'worker.py'), '--report', str(report_path),
                    '--backend', job['backend'], '--output', str(folder / 'record.json')]
            if job['reproduce']:
                args.append('--reproduce')
            process = subprocess.run(args, cwd=BACKEND, capture_output=True, text=True,
                                     encoding='utf-8', errors='replace', timeout=110)
            if process.returncode:
                raise RuntimeError((process.stderr or process.stdout or 'Pipeline failed').strip()[-2000:])
            record_path = folder / 'record.json'
            record = json.loads(record_path.read_text(encoding='utf-8'))
            digest = hashlib.sha256(record_path.read_bytes()).hexdigest()
            atomic_json(folder / 'manifest.json', {'algorithm': 'SHA-256', 'files': [
                {'path': 'record.json', 'sha256': digest}], 'created_at': now()})
            job.update(status='completed', detail='Pipeline completed. Review verdict and reproduction separately.',
                       record=record, sha256=digest, finished_at=now())
        except subprocess.TimeoutExpired:
            job.update(status='failed', detail='Pipeline exceeded the 110-second local execution limit.', finished_at=now())
        except Exception as exc:
            job.update(status='failed', detail=str(exc), finished_at=now())
        finally:
            with self.lock:
                atomic_json(folder / 'job.json', job)
                self.active = None

def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'PatchWarden/1.0'
        def log_message(self, fmt, *args):
            pass
        def trusted(self):
            port = self.server.server_address[1]
            allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
            host = self.headers.get('Host', '')
            origin = self.headers.get('Origin')
            return host in allowed and (not origin or origin in {'http://' + h for h in allowed})
        def send_data(self, code, raw, content_type='application/json; charset=utf-8', download=None):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'same-origin')
            if download:
                self.send_header('Content-Disposition', f'attachment; filename="{download}"')
            self.end_headers()
            self.wfile.write(raw)
        def json(self, code, value, download=None):
            self.send_data(code, json.dumps(value, ensure_ascii=False).encode('utf-8'), download=download)
        def do_GET(self):
            if not self.trusted():
                return self.json(403, {'error': 'Only same-origin loopback requests are accepted.'})
            path = unquote(urlsplit(self.path).path)
            try:
                if path == '/api/health':
                    import requests
                    return self.json(200, {'status': 'connected', 'requests_version': requests.__version__,
                        'backend': 'Uploaded PatchWarden pipeline', 'engine': 'Deterministic offline verifier',
                        'openssl_available': bool(shutil.which('openssl')), 'active_job': app.active,
                        'target': 'requests / CVE-2023-32681', 'report_count': len(fixture_catalog())})
                if path == '/api/reports':
                    return self.json(200, {'reports': fixture_catalog()})
                if path == '/api/runs':
                    return self.json(200, {'runs': app.jobs()})
                if path.startswith('/api/runs/'):
                    parts = path.split('/')
                    job = app.get(parts[3])
                    if len(parts) == 4:
                        return self.json(200, job)
                    if len(parts) == 5 and parts[4] == 'download':
                        return self.json(200, job, download='patchwarden-' + job['id'] + '.json')
                    if len(parts) == 5 and parts[4] == 'verify':
                        record = app.state / job['id'] / 'record.json'
                        if job['status'] != 'completed' or not record.exists():
                            raise ValueError('No completed evidence record')
                        actual = hashlib.sha256(record.read_bytes()).hexdigest()
                        return self.json(200, {'verified': secrets.compare_digest(actual, job['sha256']),
                            'expected': job['sha256'], 'actual': actual})
                    raise FileNotFoundError('Unknown run endpoint')
                if path == '/api/evidence':
                    return self.json(200, {'evidence': [verify_sample('vulnerable'), verify_sample('fixed')]})
                if path == '/api/export':
                    return self.json(200, {'runs': app.jobs()}, download='patchwarden-triage-runs.json')
                if path in ('/legacy/present.html', '/legacy/console.html', '/legacy/demo.html'):
                    names = {'/legacy/present.html': 'present.html', '/legacy/console.html': 'index.html', '/legacy/demo.html': 'demo.html'}
                    return self.send_data(200, (BACKEND / 'ui' / names[path]).read_bytes(), 'text/html; charset=utf-8')
                if path == '/legacy/runs.json':
                    return self.json(200, {'runs': [j['record'] for j in app.jobs() if j.get('record')]})
                relative = path.lstrip('/') or 'index.html'
                public = (ROOT / 'dist').resolve()
                file = (public / relative).resolve()
                if not file.is_relative_to(public) or not file.is_file():
                    raise FileNotFoundError('File not found')
                return self.send_data(200, file.read_bytes(), mimetypes.guess_type(file.name)[0] or 'application/octet-stream')
            except FileNotFoundError as exc:
                self.json(404, {'error': str(exc)})
            except (ValueError, KeyError) as exc:
                self.json(400, {'error': str(exc)})
            except Exception:
                self.json(500, {'error': 'Local service could not complete this request.'})
        def do_POST(self):
            if not self.trusted() or self.headers.get('X-PatchWarden-Client') != 'dashboard':
                return self.json(403, {'error': 'Same-origin dashboard header required.'})
            if urlsplit(self.path).path != '/api/runs':
                return self.json(404, {'error': 'Endpoint not found'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self.json(415, {'error': 'Expected application/json'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 100000:
                    return self.json(413, {'error': 'Request must be under 100 KB'})
                payload = json.loads(self.rfile.read(length))
                self.json(202, app.create(payload))
            except (ValueError, UnicodeError) as exc:
                self.json(400, {'error': str(exc)})
            except RuntimeError as exc:
                self.json(409, {'error': str(exc)})
    return Handler

if __name__ == '__main__':
    configure_environment()
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=4173)
    args = parser.parse_args()
    server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(Application()))
    print(f'PatchWarden integrated dashboard: http://127.0.0.1:{args.port}/#scan', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
