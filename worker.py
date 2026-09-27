"""One isolated pipeline invocation. Report content is never executed."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'backend'))
from pipeline.backends import TriageEngineBackend, BobSessionBackend
from pipeline.runner import PatchWardenPipeline

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--backend', choices=['engine', 'bob'], required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--reproduce', action='store_true')
    args = parser.parse_args()
    # This integration uses the ZIP's documented localhost lite fallback.
    # No machine-wide hosts entries or external CVE requests are required.
    import pipeline.runner as runner
    runner._run_r1_probe = lambda: None
    backend = TriageEngineBackend() if args.backend == 'engine' else BobSessionBackend(ROOT / 'backend' / 'bob_sessions')
    record = PatchWardenPipeline(backend, reproduce=args.reproduce).run(args.report).to_dict()
    record['report_path'] = Path(record['report_path']).name
    record['integration'] = {'source': 'Uploaded PatchWarden pipeline',
        'backend_kind': 'deterministic_offline_verifier' if args.backend == 'engine' else 'imported_bob_session',
        'scope': 'requests / CVE-2023-32681', 'reproduction_mode': 'localhost-lite',
        'note': 'Verdict/action text is output from the selected backend. It is not proof that a patch was applied or a PR was created by this integration.'}
    Path(args.output).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')

if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
