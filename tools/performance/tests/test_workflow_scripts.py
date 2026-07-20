"""Syntax checks for JavaScript embedded in GitHub workflows."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/pr-performance.yml"


def embedded_scripts(workflow: Path) -> list[str]:
    lines = workflow.read_text().splitlines()
    scripts = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.strip() != "script: |":
            index += 1
            continue
        key_indent = len(line) - len(line.lstrip())
        index += 1
        block = []
        while index < len(lines):
            candidate = lines[index]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and candidate_indent <= key_indent:
                break
            block.append(candidate)
            index += 1
        content_indents = [
            len(candidate) - len(candidate.lstrip())
            for candidate in block
            if candidate.strip()
        ]
        content_indent = min(content_indents)
        scripts.append("\n".join(candidate[content_indent:] for candidate in block))
    return scripts


class WorkflowScriptTests(unittest.TestCase):
    def test_embedded_github_scripts_parse_as_async_javascript(self) -> None:
        scripts = embedded_scripts(WORKFLOW)
        self.assertEqual(len(scripts), 2)
        for script in scripts:
            source = f"async function workflowScript() {{\n{script}\n}}\n"
            checked = subprocess.run(
                ["node", "--check", "-"],
                input=source,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)


if __name__ == "__main__":
    unittest.main()
