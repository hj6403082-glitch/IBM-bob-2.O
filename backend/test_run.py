from sandbox.triage_engine import analyze_report

with open("fixtures/report-001-real.md", "r") as f:
    real_text = f.read()

with open("fixtures/report-002-slop.md", "r") as f:
    slop_text = f.read()

print("--- TESTING REAL REPORT ---")
print(analyze_report(real_text))

print("\n--- TESTING SLOP REPORT ---")
print(analyze_report(slop_text))