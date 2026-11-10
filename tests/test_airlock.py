#!/usr/bin/env python3
"""Offline regression tests for Airlock. Standard library only, no network, no real secrets.

Run from the repo root:  python -m unittest discover -s tests -v
Each test builds a throw-away git repo in the temp folder. The fake key is assembled at
runtime so this file never contains a key-shaped string.
"""
import json, os, shutil, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AIRLOCK = os.path.join(ROOT, "airlock.py")
FAKE_KEY = "sk-" + "ant-" + "api03-" + "Qw7Lm9Zr2Tb5Vc8Nd4Hf6Jg3Ks0Py" * 2
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@airlock.example", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@airlock.example", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
ENV.pop("AIRLOCK_SAAF_GUARD", None)

UNFENCED = ("from pypdf import PdfReader\n"
            "def review(client, path):\n"
            "    text = PdfReader(path).pages[0].extract_text()\n"
            "    return client.messages.create(model='m', messages=[{'role': 'user', 'content': 'Review: ' + text}])\n")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


class Repo(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="airlock-test-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.git("init", "-q")

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.d, env=ENV, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def airlock(self, *a, cwd=None):
        return subprocess.run([sys.executable, AIRLOCK, *a], cwd=cwd or self.d, env=ENV, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def write(self, name, text):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)


class Staged(Repo):
    def test_clean_commit_passes(self):
        self.write("agent.py", "def add(a, b):\n    return a + b\n"); self.git("add", ".")
        r = self.airlock("staged")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_risky_file_blocked(self):
        self.write("agent.py", "def run(x):\n    return eval(x)\n"); self.git("add", ".")
        self.assertEqual(self.airlock("staged").returncode, 1)

    def test_filename_with_space_blocked(self):
        self.write("agent file.py", "def run(x):\n    return eval(x)\n")
        self.write("my rating.py", "def rate(f):\n    try:\n        return max(f)\n    except Exception:\n        return \"Green\"\n")
        self.git("add", ".")
        r = self.airlock("staged")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("agent file.py", r.stdout)
        self.assertIn("my rating.py", r.stdout)

    def test_secret_blocked_and_masked(self):
        self.write("config.py", f'API_KEY = "{FAKE_KEY}"\n'); self.git("add", ".")
        r = self.airlock("staged")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn(FAKE_KEY, r.stdout + r.stderr)

    def test_partial_staging_checks_the_index_not_the_working_tree(self):
        # staged version is bad, working tree already fixed -> still blocked
        self.write("agent.py", "def run(x):\n    return eval(x)\n"); self.git("add", ".")
        self.write("agent.py", "def run(x):\n    return x\n")
        self.assertEqual(self.airlock("staged").returncode, 1)
        # staged version is clean, working tree has an unstaged problem -> passes
        self.git("add", "."); self.write("agent.py", "def run(x):\n    return eval(x)\n")
        self.assertEqual(self.airlock("staged").returncode, 0)

    def test_fence_marker_in_a_comment_does_not_count(self):
        self.write("agent.py", "# this input is untrusted\n" + UNFENCED); self.git("add", ".")
        r = self.airlock("staged")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("fence", r.stdout)

    def test_outside_a_git_repo_fails_closed(self):
        d = tempfile.mkdtemp(prefix="airlock-nogit-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        r = self.airlock("staged", cwd=d)
        self.assertEqual(r.returncode, 2)
        self.assertIn("CHECK FAILED", r.stdout)


class Scan(Repo):
    def test_non_git_directory_is_not_scored(self):
        d = tempfile.mkdtemp(prefix="airlock-nogit-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        r = self.airlock("scan", d)
        self.assertEqual(r.returncode, 2)
        self.assertIn("SCAN FAILED", r.stdout)
        self.assertNotIn("grade", r.stdout)

    def test_secret_is_masked_in_evidence_of_other_rules(self):
        self.write("client.py", f'import requests\nr = requests.get(URL, verify=False, headers={{"x-api-key": "{FAKE_KEY}"}})\n')
        self.git("add", "."); self.git("commit", "-qm", "c", "--no-verify")
        out = os.path.join(self.d, "out.json")
        r = self.airlock("scan", ".", "--json", out)
        raw = read(out)
        self.assertNotIn(FAKE_KEY, raw)
        self.assertNotIn(FAKE_KEY, r.stdout + r.stderr)
        self.assertIn("tls-verify-off", {f["rule"] for f in json.loads(raw)[0]["findings"]})

    def test_history_only_secret_is_found(self):
        self.write("config.py", f'API_KEY = "{FAKE_KEY}"\n'); self.git("add", "."); self.git("commit", "-qm", "add", "--no-verify")
        self.write("config.py", "import os\nAPI_KEY = os.environ['API_KEY']\n"); self.git("add", "."); self.git("commit", "-qm", "fix", "--no-verify")
        out = os.path.join(self.d, "out.json")
        r = self.airlock("scan", ".", "--json", out, "--fail-on", "high")
        self.assertEqual(r.returncode, 1, r.stdout)
        rep = json.loads(read(out))[0]
        self.assertTrue(any(f["rule"].endswith("-history") for f in rep["findings"]))
        self.assertEqual(rep["decision"], "block")
        self.assertIn("BLOCK", r.stdout)

    def test_clean_repo_passes(self):
        self.write(".gitignore", ".env\n"); self.write("agent.py", "def add(a, b):\n    return a + b\n")
        self.write("tests/test_agent.py", "def test_add():\n    assert True\n"); self.write("AUDIT-CRITERIA.md", "# criteria\n")
        self.git("add", "."); self.git("commit", "-qm", "c", "--no-verify")
        r = self.airlock("scan", ".", "--fail-on", "medium")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("PASS", r.stdout)


class Install(Repo):
    def hook(self):
        return os.path.join(self.d, ".git", "hooks", "pre-commit")

    def test_existing_hook_is_not_overwritten(self):
        os.makedirs(os.path.dirname(self.hook()), exist_ok=True)
        with open(self.hook(), "w", newline="\n") as fh:
            fh.write("#!/bin/sh\necho team-hook\n")
        r = self.airlock("install", ".")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(read(self.hook()), "#!/bin/sh\necho team-hook\n")

    def test_chain_keeps_existing_hook_and_adds_airlock(self):
        os.makedirs(os.path.dirname(self.hook()), exist_ok=True)
        with open(self.hook(), "w", newline="\n") as fh:
            fh.write("#!/bin/sh\necho team-hook-ran\n")
        self.assertEqual(self.airlock("install", ".", "--chain").returncode, 0)
        self.write("agent.py", "def run(x):\n    return eval(x)\n"); self.git("add", ".")
        r = self.git("commit", "-m", "bad")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("team-hook-ran", r.stdout + r.stderr)
        self.assertIn("COMMIT BLOCKED", r.stdout + r.stderr)
        self.assertEqual(self.airlock("install", ".", "--chain").returncode, 0)  # re-install is safe
        self.assertIn("team-hook-ran", read(os.path.join(os.path.dirname(self.hook()), "pre-commit.pre-airlock")))

    def test_hook_refuses_the_commit_when_python_is_missing(self):
        self.assertEqual(self.airlock("install", ".").returncode, 0)
        text = read(self.hook())
        self.assertTrue(text.rstrip().endswith("exit 1"))
        self.assertNotIn("exit 0", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
