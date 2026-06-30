import os
from cybersec_platform.sonar_analyzer import SonarAnalyzer

analyzer = SonarAnalyzer()
base = os.getcwd()
extensions = {'.py', '.js', '.ts', '.java', '.html', '.css'}
exclude_files = {'sonar_analyzer.py'}
results = []

for root, _, files in os.walk(base):
    if '.git' in root or '__pycache__' in root or root.startswith(os.path.join(base, '.github')):
        continue
    for name in files:
        if name in exclude_files:
            continue
        if os.path.splitext(name)[1].lower() in extensions:
            path = os.path.join(root, name)
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            report = analyzer.analyze_code(name, content)
            s = report['summary']
            if s['bugs'] or s['vulnerabilities'] or s['maintainability_issues']:
                results.append((path, report))

critical_files = [(os.path.relpath(p, base), [i for i in r['issues'] if i['severity'] == 'Critical'])
                  for p, r in results]
critical_files = [(f, c) for f, c in critical_files if c]

if critical_files:
    print("CRITICAL issues — workflow would FAIL:")
    for rel, crits in critical_files:
        print(f"  {rel}")
        for i in crits:
            print(f"    line {i['line']}: {i['description']}")
else:
    print(f"No Critical issues across {len(results)} flagged files — workflow would PASS.")
