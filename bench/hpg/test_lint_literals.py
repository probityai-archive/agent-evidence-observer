"""Tests for lint_literals.py. Run: python3 bench/hpg/test_lint_literals.py"""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
LINT = HERE / "lint_literals.py"


def run(directory: Path, env=None):
    return subprocess.run(
        [sys.executable, str(LINT), str(directory)], capture_output=True, text=True, env=env
    )


class LintLiterals(unittest.TestCase):
    def check(self, filename: str, body: str, expect: int, env=None):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / filename).write_text(body)
            result = run(Path(d), env)
            self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
            return result.stdout

    def test_account_directive_refused(self):
        self.check("a.sbatch", "#!/bin/bash\n#SBATCH --account=acct1\n", 1)

    def test_qos_directive_refused(self):
        self.check("a.sbatch", "#SBATCH --qos=q1\n", 1)

    def test_short_account_flag_refused(self):
        self.check("a.sbatch", "#SBATCH -A acct1\n", 1)

    def test_blue_path_refused(self):
        self.check("a.sh", "H=/blue/group/user/work\n", 1)

    def test_home_path_refused(self):
        self.check("a.sh", "cd /home/someone/x\n", 1)

    def test_variable_paths_allowed(self):
        self.check("a.sh", 'H="$HPG_BLUE_DIR/runs"\nexport TMPDIR=${TMPDIR:-/tmp}/x\n', 0)

    def test_resource_directives_allowed(self):
        self.check("a.sbatch", "#SBATCH --partition=p\n#SBATCH --gres=gpu:b200:1\n#SBATCH --mem=32gb\n", 0)

    def test_extra_literal_from_environment(self):
        import os

        env = dict(os.environ, HPG_LITERALS="secretname")
        self.check("a.md", "uses secretname here\n", 1, env)
        self.check("a.md", "clean text\n", 0, env)

    def test_lock_file_skipped(self):
        self.check("uv.lock", "url = '/blue/x'\n", 0)

    def test_real_templates_clean(self):
        result = run(HERE)
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
