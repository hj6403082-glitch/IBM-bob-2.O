"""Portable setup and launcher. Run with Python 3.11 or newer."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent

def main():
    if sys.version_info < (3, 11):
        print('Please install Python 3.11 or newer and run this launcher again.')
        return 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=4173)
    parser.add_argument('--setup-only', action='store_true')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Choose a port between 1024 and 65535.')
    python = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    os.chdir(ROOT)
    if not python.is_file():
        print('Creating the project Python environment...', flush=True)
        subprocess.run([sys.executable, '-m', 'venv', str(ROOT / '.venv')], check=True)
    check = subprocess.run([str(python), '-c', "import requests,pytest; assert requests.__version__ == '2.30.0'"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check.returncode:
        print('Installing dependencies. Internet access is needed for this first setup...', flush=True)
        subprocess.run([str(python), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')], check=True)
    for folder in ('C:/Program Files/Git/usr/bin', 'C:/Program Files/Git/mingw64/bin'):
        if (Path(folder) / 'openssl.exe').is_file():
            os.environ['PATH'] = folder + os.pathsep + os.environ.get('PATH', '')
            break
    if not shutil.which('openssl'):
        print('OpenSSL was not found. Triage works, but fresh TLS reproduction needs OpenSSL. See README.md.', flush=True)
    if args.setup_only:
        print('Setup complete. Run this launcher again to open PatchWarden.')
        return 0
    probe = socket.socket()
    try:
        probe.bind(('127.0.0.1', args.port))
    except OSError:
        print(f'Port {args.port} is unavailable. Close the previous server or run: python start.py --port {args.port + 1}')
        return 1
    finally:
        probe.close()
    address = f'http://127.0.0.1:{args.port}'
    process = subprocess.Popen([str(python), str(ROOT / 'service.py'), '--port', str(args.port)], cwd=ROOT)
    def open_when_ready():
        for _ in range(40):
            if process.poll() is not None:
                return
            try:
                with urllib.request.urlopen(address + '/api/health', timeout=1) as response:
                    if response.status == 200:
                        webbrowser.open(address + '/#scan')
                        return
            except OSError:
                time.sleep(.25)
    if not args.no_browser:
        threading.Thread(target=open_when_ready, daemon=True).start()
    print(f'Open {address}/#scan\nKeep this terminal open. Press Ctrl+C to stop.', flush=True)
    try:
        return process.wait()
    except KeyboardInterrupt:
        print('\nStopping PatchWarden...')
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError:
        print('Setup failed. Check your internet connection and Python installation, then retry. See README.md.')
        raise SystemExit(1)
