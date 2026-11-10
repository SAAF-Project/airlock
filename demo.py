#!/usr/bin/env python3
"""Airlock live demo: building a SAAF vendor-review agent and making the mistakes from
today's findings. Each risky commit is refused, fixed, and then goes through.
No real secrets: the fake key is generated at runtime and never leaves the demo folder."""
import os, random, shutil, string, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
AL = os.path.join(HERE, "airlock.py")
DEMO = os.path.join(os.path.expanduser("~"), "airlock-demo")
B, DIM, CY, R = "\033[1m", "\033[2m", "\033[36m", "\033[0m"
AUTO = "--auto" in sys.argv

def step(t):
    print(f"\n{CY}{B}▶ {t}{R}", flush=True)
    if not AUTO:
        input(f"{DIM}  [Enter]{R}")

def sh(*cmd, show=True):
    if show: print(f"{DIM}$ {' '.join(cmd)}{R}", flush=True)
    return subprocess.run(cmd, cwd=DEMO).returncode

def write(name, text):
    p = os.path.join(DEMO, name); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh: fh.write(text)

FAKE_KEY = "sk-ant-api03-" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(48))

ENV_EXAMPLE_BAD = f"ANTHROPIC_API_KEY={FAKE_KEY}\nMODEL=claude-sonnet-4-6\n"
ENV_EXAMPLE_GOOD = "ANTHROPIC_API_KEY=xxxx\nMODEL=claude-sonnet-4-6\n"

AGENT_BAD = '''import os
import anthropic
from pypdf import PdfReader

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

def review(path):
    report = "".join(p.extract_text() for p in PdfReader(path).pages)
    msg = client.messages.create(model=os.environ["MODEL"], max_tokens=2000,
        messages=[{"role": "user", "content": f"Review this vendor report:\\n{report}"}])
    return msg.content[0].text
'''
AGENT_GOOD = AGENT_BAD.replace("from pypdf import PdfReader", "from pypdf import PdfReader\nfrom saaf_guard import fence, FENCE_RULE").replace(
    'messages=[{"role": "user", "content": f"Review this vendor report:\\n{report}"}])',
    'system=FENCE_RULE,\n        messages=[{"role": "user", "content": "Review this vendor report:\\n" + fence(report, source="vendor report")}])')

RATING_BAD = '''def overall_rating(findings):
    try:
        worst = max(f["risk"] for f in findings)
    except Exception:
        return "Green"
    return worst
'''
RATING_GOOD = RATING_BAD.replace('return "Green"', 'return "Inconclusive"')

SERVER_BAD = '''from flask import Flask
from agent import review

app = Flask(__name__)

@app.post("/review")
def run_review():
    return review("upload.pdf")

app.run(host="0.0.0.0", debug=True)
'''
SERVER_GOOD = SERVER_BAD.replace('app.run(host="0.0.0.0", debug=True)', 'app.run(host="127.0.0.1")')

def main():
    if os.path.exists(DEMO):
        # git marks object files read-only; Windows refuses to delete them unless made writable
        shutil.rmtree(DEMO, onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))
    os.makedirs(DEMO)
    for c in (["git", "init", "-q"], ["git", "config", "user.email", "demo@airlock.example"], ["git", "config", "user.name", "Airlock Demo"]):
        sh(*c, show=False)
    write("README.md", "# Vendor review agent\n")
    sh("git", "add", "README.md", show=False); sh("git", "commit", "-qm", "init", "--no-verify", show=False)

    step("New SAAF agent repo. One command adds Airlock.")
    sh(sys.executable, AL, "install", ".")

    step("Set up config: a real .env, and a .env.example copied from it (a real mistake from today)")
    write(".env", f"ANTHROPIC_API_KEY={FAKE_KEY}\n"); write(".env.example", ENV_EXAMPLE_BAD)
    sh("git", "add", "."); sh("git", "commit", "-m", "project setup")

    step("Fix: .env stays local (.gitignore), .env.example gets placeholders")
    write(".gitignore", ".env\n"); write(".env.example", ENV_EXAMPLE_GOOD)
    sh("git", "rm", "-q", "--cached", ".env"); sh("git", "add", ".gitignore", ".env.example")
    sh("git", "commit", "-m", "project setup")

    step("Write the agent: send the vendor's PDF to Claude")
    write("agent.py", AGENT_BAD); sh("git", "add", "agent.py"); sh("git", "commit", "-m", "vendor review agent")

    step("Fix: fence the document so hidden instructions in the PDF are treated as data")
    write("agent.py", AGENT_GOOD); sh("git", "add", "agent.py"); sh("git", "commit", "-m", "vendor review agent")

    step("Add the overall rating")
    write("rating.py", RATING_BAD); sh("git", "add", "rating.py"); sh("git", "commit", "-m", "overall rating")

    step("Fix: when in doubt, never green")
    write("rating.py", RATING_GOOD); sh("git", "add", "rating.py"); sh("git", "commit", "-m", "overall rating")

    step("Put it behind a small web server for the team")
    write("server.py", SERVER_BAD); sh("git", "add", "server.py"); sh("git", "commit", "-m", "web server")

    step("Fix: local only, no debug")
    write("server.py", SERVER_GOOD); sh("git", "add", "server.py"); sh("git", "commit", "-m", "web server")

    step("Four mistakes from today's findings, none of them reached git history")
    sh("git", "log", "--oneline")
    print(f"\n{B}Done.{R} Demo repo: {DEMO}")

if __name__ == "__main__":
    try: sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception: pass
    if os.name == "nt": os.system("")
    main()
