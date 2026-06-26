import os
import re
from typing import Dict, List


class SonarAnalyzer:

    def analyze_code(self, filename: str, content: str) -> Dict[str, object]:
        extension = os.path.splitext(filename)[1].lower()
        lines = content.splitlines()
        issues = []

        rules = self._build_rules(extension)
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            for rule in rules:
                if rule["pattern"].search(line):
                    issues.append({
                        "category": rule["category"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "line": index,
                        "snippet": stripped
                    })

        issues.extend(self._maintainability_checks(filename, lines))
        return self._build_report(filename, issues)

    def _build_rules(self, extension: str) -> List[Dict[str, object]]:
        patterns = [
            {
                "category": "Bug",
                "severity": "Major",
                "description": "Bare except clause may hide unexpected exceptions.",
                "pattern": re.compile(r"^\s*except\s*:\s*$")
            },
            {
                "category": "Bug",
                "severity": "Critical",
                "description": "Use of eval() may lead to code execution vulnerabilities.",
                "pattern": re.compile(r"\beval\(")
            },
            {
                "category": "Vulnerability",
                "severity": "Critical",
                "description": "Shell execution with untrusted input can lead to command injection.",
                "pattern": re.compile(r"subprocess\.run\(|subprocess\.Popen\(|os\.system\(")
            },
            {
                "category": "Vulnerability",
                "severity": "High",
                "description": "Hardcoded credentials or secrets should be avoided.",
                "pattern": re.compile(r"(password|secret|api_key|token)\s*=\s*['\"]")
            },
            {
                "category": "Vulnerability",
                "severity": "High",
                "description": "Using HTTP without TLS may expose sensitive data in transit.",
                "pattern": re.compile(r"http://")
            },
            {
                "category": "Maintainability",
                "severity": "Minor",
                "description": "TODO/FIXME comments indicate unfinished work.",
                "pattern": re.compile(r"\b(TODO|FIXME)\b")
            },
            {
                "category": "Maintainability",
                "severity": "Minor",
                "description": "Long lines can reduce readability and maintainability.",
                "pattern": re.compile(r"^.{{120,}}$")
            }
        ]

        if extension == ".py":
            patterns.append({
                "category": "Bug",
                "severity": "Major",
                "description": "Mutable default arguments can retain state between function calls.",
                "pattern": re.compile(r"def .*\(.*=[\[{].*")
            })
            patterns.append({
                "category": "Maintainability",
                "severity": "Minor",
                "description": "Function or class may be too large and hard to maintain.",
                "pattern": re.compile(r"^(def |class )")
            })
        elif extension in {".js", ".ts"}:
            patterns.append({
                "category": "Vulnerability",
                "severity": "High",
                "description": "Use of eval() in JavaScript is risky and may introduce XSS issues.",
                "pattern": re.compile(r"\beval\(")
            })
            patterns.append({
                "category": "Bug",
                "severity": "Major",
                "description": "Strict equality (===) is preferred over == for type-safe comparisons.",
                "pattern": re.compile(r"[^=!]==[^=]")
            })
        elif extension == ".java":
            patterns.append({
                "category": "Vulnerability",
                "severity": "High",
                "description": "Use of insecure random number generation can weaken security.",
                "pattern": re.compile(r"new\s+Random\(")
            })

        return patterns

    def _maintainability_checks(self, filename: str, lines: List[str]) -> List[Dict[str, object]]:
        issues = []
        if len(lines) > 500:
            issues.append({
                "category": "Maintainability",
                "severity": "Major",
                "description": "File is very large and may be difficult to maintain.",
                "line": 1,
                "snippet": "File length exceeds 500 lines"
            })

        if filename.lower().endswith('.py') and any('TODO' in line or 'FIXME' in line for line in lines):
            issues.append({
                "category": "Maintainability",
                "severity": "Minor",
                "description": "Python files with TODO/FIXME comments may require cleanup before release.",
                "line": 1,
                "snippet": "File contains TODO or FIXME markers"
            })

        comment_only = sum(1 for line in lines if line.strip().startswith("#") or line.strip().startswith("//"))
        if comment_only / max(1, len(lines)) > 0.35:
            issues.append({
                "category": "Maintainability",
                "severity": "Minor",
                "description": "High comment density may indicate complex or poorly reusable code.",
                "line": 1,
                "snippet": "Comments make up more than 35% of the file"
            })

        return issues

    def _build_report(self, filename: str, issues: List[Dict[str, object]]) -> Dict[str, object]:
        categories = {"Bug": 0, "Vulnerability": 0, "Maintainability": 0}
        for item in issues:
            if item["category"] in categories:
                categories[item["category"]] += 1

        return {
            "filename": filename,
            "total_lines": len(issues),
            "issue_counts": categories,
            "issues": issues,
            "summary": {
                "bugs": categories["Bug"],
                "vulnerabilities": categories["Vulnerability"],
                "maintainability_issues": categories["Maintainability"]
            }
        }
