#!/usr/bin/env python3
"""Airlock: the commit-time layer for SAAF agent repos. Scans a git repo for secrets (files + full history), committed .env files,
unsafe rendering of LLM output, personal data in samples and risky code patterns.

Usage:
  python airlock.py scan <repo> [--json out.json] [--csv out.csv] [--redact] [--fail-on high]
  python airlock.py staged            # pre-commit: scan staged changes, block on findings
Stdlib only. Runs offline. Secret values are always masked in output.
"""
import argparse, csv, hashlib, json, math, os, re, subprocess, sys

SEV_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]
SEV_PENALTY = {"Critical": 30, "High": 15, "Medium": 6, "Low": 2, "Informational": 0}
SKIP_DIRS = ("node_modules/", ".venv/", "venv/", "dist/", "build/", ".next/")
SKIP_FILES = re.compile(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|\.min\.js|\.map|\.svg|\.png|\.jpe?g|\.gif|\.pdf|\.ico|\.woff2?|\.ttf|\.zip|\.docx|\.xlsx|\.pptx|\.mp4|\.mp3)$", re.I)

# ---------- secret rules ----------
SECRET_RULES = [
    ("anthropic-key", "Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", "OpenAI API key", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("aws-key", "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", "GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})")),
    ("google-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack-token", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("hf-token", "Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("private-key", "Private key block", re.compile(r"^\s*[\"']?-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("db-url", "Database URL with password", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/'\"]+:[^@\s'\"]{4,}@[^\s'\"]+")),
    ("generic-secret", "Hard-coded secret", re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd)\b\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]")),
]
PLACEHOLDER = re.compile(r"(?i)(your|xxx|example|dummy|placeholder|changeme|insert|replace|fake|sample|redacted|\*\*\*|<|\$\{|\{\{|os\.environ|getenv|process\.env|\.\.\.|test_?key|1234)")

def entropy(s):
    if not s: return 0.0
    from collections import Counter
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def mask(v):
    v = v.strip()
    return (v[:6] + "…" if len(v) > 10 else v[:2] + "…") + f"({len(v)} chars)"

def scrub(text):
    """Mask every secret value inside free text, whichever rule produced the text."""
    text = text or ""
    for _, _, val in find_secrets(text):
        text = text.replace(val, mask(val))
    return text

def find_secrets(line):
    out = []
    for rid, name, rx in SECRET_RULES:
        for m in rx.finditer(line):
            val = m.group(1) if m.groups() else m.group(0)
            if PLACEHOLDER.search(val):
                continue
            if rid in ("generic-secret",) and entropy(val) < 3.3:
                continue
            if rid == "db-url" and re.search(r"(?i)(localhost|127\.0\.0\.1|user:pass|username:password)", m.group(0)):
                continue
            if any(v == val or val in v or v in val for _, _, v in out):
                continue
            out.append((rid, name, val))
    return out

# ---------- code-pattern rules (per line) ----------
CODE_RULES = [
    ("unsafe-html-streamlit", "Model/user text rendered as raw HTML (Streamlit)", "Medium", re.compile(r"unsafe_allow_html\s*=\s*True"), (".py",),
     "Escape model and document text with html.escape() before passing it to st.markdown(..., unsafe_allow_html=True), or drop unsafe_allow_html."),
    ("unsafe-html-react", "Raw HTML injected in React", "Medium", re.compile(r"dangerouslySetInnerHTML"), (".js", ".jsx", ".ts", ".tsx"),
     "Sanitise with DOMPurify before dangerouslySetInnerHTML, or render as text."),
    ("unsafe-innerhtml", "Dynamic value assigned to innerHTML", "Medium", re.compile(r"\.innerHTML\s*[+]?=.*(\$\{|['\"]\s*\+\s*\w)"), (".js", ".jsx", ".ts", ".tsx", ".html"),
     "Use textContent, or escape the value before assigning to innerHTML."),
    ("jinja-autoescape-off", "Template autoescaping disabled", "Medium", re.compile(r"autoescape\s*=\s*False|\|\s*safe\b|Markup\("), (".py", ".html", ".j2", ".jinja"),
     "Keep autoescape on and avoid |safe / Markup() on model or document text."),
    ("tls-verify-off", "TLS certificate verification disabled", "Medium", re.compile(r"verify\s*=\s*False"), (".py",),
     "Remove verify=False; use a proper CA bundle."),
    ("shell-true", "subprocess with shell=True", "Medium", re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), (".py",),
     "Pass an argument list without shell=True so input cannot inject shell commands."),
    ("eval-exec", "eval()/exec() on dynamic input", "High", re.compile(r"(?<![\w.])(?:eval|exec)\(\s*(?![\"'])"), (".py",),
     "Never eval/exec model output or file content; parse it (json.loads, ast.literal_eval) instead."),
    ("yaml-unsafe", "yaml.load without SafeLoader", "Medium", re.compile(r"yaml\.load\((?![^)]*SafeLoader)"), (".py",),
     "Use yaml.safe_load()."),
    ("pickle-load", "pickle deserialisation", "Low", re.compile(r"pickle\.loads?\("), (".py",),
     "Only unpickle trusted files; prefer JSON."),
    ("open-server-bind", "Server listens on all interfaces (0.0.0.0)", "High", re.compile(r"[\"']0\.0\.0\.0[\"']|--host\s+0\.0\.0\.0"), (".py", ".js", ".ts", ".sh", ".toml", ".yml", ".yaml", ".json"),
     "Bind to 127.0.0.1 and require a token on every endpoint that runs the agent (SAAF Guard rule 6)."),
    ("cors-wildcard", "CORS allows any origin", "High", re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']|Access-Control-Allow-Origin[\"']?\s*[:,]\s*[\"']\*"), (".py", ".js", ".ts", ".json"),
     "Restrict CORS to known origins."),
    ("flask-debug", "Debug mode enabled in server", "High", re.compile(r"\.run\([^)]*debug\s*=\s*True|\bdebug\s*=\s*True\b"), (".py",),
     "Turn debug off outside local development (debugger allows code execution)."),
]

def code_hits(path, line):
    ext = os.path.splitext(path)[1].lower()
    for rid, title, sev, rx, exts, rec in CODE_RULES:
        if ext in exts and rx.search(line):
            if rid == "eval-exec" and re.search(r"\.(eval|exec)\(|model\.eval\(|literal_eval", line):
                continue
            yield rid, title, sev, rec

# ---------- PII in samples ----------
SAMPLE_DIR = re.compile(r"(?i)(^|/)(samples?|sample_inputs|examples?|data|fixtures|test_?data|inputs?)/")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SAFE_EMAIL = re.compile(r"(?i)@(\S*synth\S*|\S*\.(example|test|invalid|local)\b|example\.(com|org|net)|test\.|localhost|users\.noreply\.github\.com|company\.com|acme|contoso|fabrikam|domain\.)|noreply|no-reply|^info@|^support@")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b")
BSN_CTX = re.compile(r"(?i)\b(bsn|burgerservicenummer|ssn|social security)\b\D{0,20}(\d{8,9})")

def iban_ok(s):
    s = s.replace(" ", "")
    if not (15 <= len(s) <= 34): return False
    r = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in r)) % 97 == 1
    except ValueError:
        return False

def pii_hits(path, line):
    if not SAMPLE_DIR.search(path):
        return
    for m in EMAIL.finditer(line):
        if not SAFE_EMAIL.search(m.group(0)):
            yield "email", m.group(0)
    for m in IBAN.finditer(line):
        if iban_ok(m.group(0)) and not m.group(0).replace(" ", "").startswith(("NL91ABNA0417164300", "DE89370400440532013000", "GB82WEST12345698765432")):
            yield "IBAN", m.group(0)
    for m in BSN_CTX.finditer(line):
        yield "national ID", m.group(2)


# ---------- file-level checks: prompt-injection fence, fail-open verdicts ----------
LLM_CALL = re.compile(r"messages\.create\(|chat\.completions\.create\(|ChatCompletion\.create\(|responses\.create\(|generate_content\(|\.invoke\(|litellm\.completion\(|ollama\.chat\(")
DOC_READ = re.compile(r"PdfReader|pypdf|fitz\.open|pdfplumber|docx\.Document|\bDocument\(|extract_text|file_uploader|UploadFile|load_workbook|read_csv|requests\.get\(")
FENCE = re.compile(r"(?i)fence\(|<\s*/?\s*(document|untrusted|data|input|source|context|vendor_\w+|org_\w+|\w+_(report|document|text|content|excerpt))\s*>|BEGIN (UNTRUSTED|DOCUMENT|DATA)|as data,? not (as )?instructions|ignore (any )?instructions (in|inside|within)|untrusted")
PASS_VAL = re.compile(r"""(?i)return\s+(["'](pass(ed)?|green|approved?|compliant|ok|matched|valid|safe|low|no issues?|accept(ed)?)["']|\{\s*["'](status|verdict|result|rating)["']\s*:\s*["'](pass(ed)?|green|approved?|compliant|ok|valid|safe|low)["'])""")
TRUE_RET = re.compile(r"return\s+True\b")
CHECK_FN = re.compile(r"(?i)def\s+(\w*(valid|verif|check|is_|has_|safe|complian|approv|pass|allow|authori|grounded)\w*)\s*\(")
GUARD_LINE = re.compile(r"^\s*(except\b.*:|if\s+not\s+\w[\w.\[\]'\"]*\s*:|if\s+len\(.+\)\s*==\s*0\s*:|if\s+\w[\w.]*\s+is\s+None\s*:)")

def file_checks(path, lines, repo_defended=False):
    """Yield (rule, title, severity, line, recommendation) for whole-file patterns."""
    if not path.endswith(".py"):
        return
    text = "\n".join(lines)
    code_text = "\n".join(l for l in lines if not l.lstrip().startswith("#"))  # a marker in a comment is not a fence
    if LLM_CALL.search(text) and DOC_READ.search(text) and not FENCE.search(code_text):
        ln = next((i for i, l in enumerate(lines, 1) if LLM_CALL.search(l)), None)
        yield ("prompt-injection-unfenced",
               "Document text sent to the LLM without a data fence" + (" (prompt-only defence)" if repo_defended else ""),
               "Medium" if repo_defended else "High", ln,
               "Wrap every document/auditee text in clear delimiters (e.g. <document>…</document>) and tell the model to treat it as data, not instructions (OWASP LLM01).")
    fn = ""
    for i, l in enumerate(lines):
        m = re.match(r"\s*def\s+(\w+)", l)
        if m: fn = m.group(0)
        if GUARD_LINE.match(l):
            ind = len(l) - len(l.lstrip())
            for j in range(i + 1, min(i + 5, len(lines))):
                nl = lines[j]
                if nl.strip() and (len(nl) - len(nl.lstrip())) <= ind:
                    break
                if PASS_VAL.search(nl):
                    kind = "an error" if l.strip().startswith("except") else "empty or missing input"
                    yield ("fail-open-verdict", f"Fail-open: {kind} produces a passing verdict", "High", j + 1,
                           "On errors or empty input return a failing / 'needs review' verdict and surface it in the report and exit code, never a pass.")
                    break

# ---------- git helpers ----------
class ScanError(Exception):
    """The scan could not run. Never report a score or a clean result after this."""

def git(repo, *args, check=False):
    """Run git in repo. With check=True a git failure raises ScanError instead of looking like 'nothing found'."""
    try:
        r = subprocess.run(["git", "-c", "core.quotePath=false", "-C", repo, *args],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    except OSError as e:
        raise ScanError(f"could not run git: {e}")
    if check and r.returncode != 0:
        raise ScanError((r.stderr.strip().splitlines() or [f"git {args[0]} failed"])[-1])
    return r.stdout

def repo_name(repo):
    url = git(repo, "remote", "get-url", "origin").strip()
    base = url.rstrip("/").split("/")[-1] if url else os.path.basename(os.path.abspath(repo))
    return base[:-4] if base.endswith(".git") else base

def skip(path):
    return path.startswith(SKIP_DIRS) or any(f"/{d}" in path for d in SKIP_DIRS) or SKIP_FILES.search(path)

ENV_FILE = re.compile(r"(^|/)\.env(\.(?!example|sample|template|dist|defaults)[\w.-]+)?$")

# ---------- scan ----------
class Findings:
    def __init__(self, repo):
        self.repo = repo; self.items = []; self.seen = set()
    def add(self, key, **kw):
        if key in self.seen: return
        if kw.get("evidence"):
            kw["evidence"] = scrub(kw["evidence"])
        self.seen.add(key); self.items.append(kw)

def scan_repo(repo, log=print):
    repo = os.path.abspath(repo)
    if not os.path.isdir(repo):
        raise ScanError(f"not a directory: {repo}")
    git(repo, "rev-parse", "--git-dir", check=True)
    name = repo_name(repo)
    F = Findings(name)
    files = [f for f in git(repo, "ls-files", "-z", check=True).split("\0") if f]
    log(f"$ airlock scan {name}")
    log(f"  {len(files)} tracked files, {len(git(repo, 'rev-list', '--all').split())} commits")

    # 1. working tree
    log("[1/5] secrets, prompt-injection fences, fail-open verdicts …")
    repo_defended = False
    for f in files:
        if re.search(r"(?i)prompt", f) and f.endswith((".md", ".txt", ".yaml", ".yml", ".j2")):
            try:
                if FENCE.search(open(os.path.join(repo, f), encoding="utf-8", errors="ignore").read()):
                    repo_defended = True
            except OSError:
                pass
    head_secret_vals = set()
    for f in files:
        if skip(f): continue
        p = os.path.join(repo, f)
        try:
            if os.path.getsize(p) > 2_000_000: continue
            with open(p, encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
        except (OSError, IsADirectoryError):
            continue
        for rid, title, sev, ln, rec in file_checks(f, lines, repo_defended):
            F.add(("file", rid, f, ln if rid == "fail-open-verdict" else 0), category="AI safety", rule=rid, severity=sev, title=f"{title} in {f}", file=f, line=ln,
                  evidence=(scrub(lines[ln-1]).strip()[:120] if ln else ""), observation=f"{title} ({f}:{ln}).", recommendation=rec)
        for i, line in enumerate(lines, 1):
            line = line[:5000]
            for rid, rname, val in find_secrets(line):
                head_secret_vals.add(val)
                F.add(("sec", rid, val), category="Secrets", rule=rid, severity="Critical",
                      title=f"{rname} committed in {f}", file=f, line=i, evidence=mask(val),
                      observation=f"A {rname.lower()} is present in the current version of {f} (line {i}). Value masked: {mask(val)}.",
                      recommendation="Revoke and rotate the key now, move it to an environment variable or secret store, and purge it from git history.")
            for rid, title, sev, rec in code_hits(f, line):
                F.add(("code", rid, f), category="Unsafe code", rule=rid, severity=sev, title=f"{title} in {f}", file=f, line=i,
                      evidence=scrub(line).strip()[:120], observation=f"{title} at {f}:{i}.", recommendation=rec)
            for kind, val in pii_hits(f, line):
                F.add(("pii", kind, f), category="Personal data", rule=f"pii-{kind}", severity="Medium",
                      title=f"Possible real {kind} in sample data {f}", file=f, line=i, evidence=mask(val),
                      observation=f"Sample/data file {f} contains what looks like a real {kind} (line {i}, masked {mask(val)}).",
                      recommendation="Replace with synthetic data (example.com addresses, test IBANs) and check GDPR basis for any real data.")

    # 2. env files
    log("[2/5] committed .env files …")
    for f in files:
        if ENV_FILE.search(f):
            F.add(("env", f), category="Secrets", rule="env-committed", severity="High", title=f".env file committed: {f}", file=f, line=None,
                  evidence=f, observation=f"{f} is tracked in git. Environment files usually hold API keys.",
                  recommendation="git rm --cached the file, add .env to .gitignore, rotate any keys it held.")
    hist_env = set(x for x in git(repo, "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:").splitlines() if x and ENV_FILE.search(x))
    for f in hist_env - set(files):
        F.add(("envh", f), category="Secrets", rule="env-in-history", severity="High", title=f".env file deleted but still in git history: {f}", file=f, line=None,
              evidence=f, observation=f"{f} was committed in the past and removed, but it is still readable in git history.",
              recommendation="Rotate any keys it held; rewrite history (git filter-repo) only with maintainer approval.")
    gi = ""
    if os.path.exists(os.path.join(repo, ".gitignore")):
        gi = open(os.path.join(repo, ".gitignore"), encoding="utf-8", errors="ignore").read()
    if not re.search(r"(^|\n)\s*\*?\.env", gi):
        F.add(("gi",), category="Hygiene", rule="gitignore-env", severity="Low", title=".gitignore does not exclude .env", file=".gitignore", line=None,
              evidence="", observation="No .env rule in .gitignore, so a local .env with keys can be committed by accident.",
              recommendation="Add .env and .env.* (keep .env.example) to .gitignore.")

    # 3. history
    log("[3/5] secrets in full git history …")
    out = git(repo, "log", "--all", "-p", "--no-color", "--unified=0", "--pretty=format:@@@C %h %ad", "--date=short", check=True)
    commit = date = cur = None
    for line in out.splitlines():
        if line.startswith("@@@C "):
            _, commit, date = line.split(" ", 2); continue
        if line.startswith("+++ "):
            cur = line[6:].rstrip("\t") if line.startswith("+++ b/") else None; continue
        if not line.startswith("+") or line.startswith("+++") or not cur or skip(cur):
            continue
        for rid, rname, val in find_secrets(line[1:5000]):
            if val in head_secret_vals: continue
            F.add(("hist", rid, val), category="Secrets", rule=rid + "-history", severity="High",
                  title=f"{rname} removed but still in git history ({cur})", file=cur, line=None, commit=commit, evidence=mask(val),
                  observation=f"A {rname.lower()} was committed to {cur} in commit {commit} ({date}). It is gone from the current files but anyone who clones the repo can still read it. Masked: {mask(val)}.",
                  recommendation="Assume the key is compromised: revoke and rotate it. Add a pre-commit secret scan so it cannot happen again.")

    # 4. hygiene
    log("[4/5] repo hygiene …")
    if any("__pycache__/" in f or f.endswith(".pyc") for f in files):
        F.add(("pyc",), category="Hygiene", rule="pycache", severity="Low", title="Compiled Python files committed", file="__pycache__", line=None, evidence="",
              observation="__pycache__ / .pyc files are tracked.", recommendation="Remove them and add __pycache__/ to .gitignore.")
    if not any(re.search(r"(^|/)tests?/|test_.*\.py$|_test\.py$|\.test\.[jt]sx?$", f) for f in files):
        F.add(("tests",), category="Hygiene", rule="no-tests", severity="Informational", title="No automated tests", file="", line=None, evidence="",
              observation="No test files found.", recommendation="Add offline tests with a mocked LLM.")
    if "AUDIT-CRITERIA.md" not in files and name != "SAAF-Project":
        F.add(("ac",), category="Hygiene", rule="no-audit-criteria", severity="Informational", title="No AUDIT-CRITERIA.md", file="", line=None, evidence="",
              observation="SAAF requires AUDIT-CRITERIA.md next to the README.", recommendation="Run /harden-agent-repo to add it.")

    log("[5/5] scoring …")
    return report(name, F.items)

def report(name, items):
    score = max(0, 100 - sum(SEV_PENALTY[i["severity"]] for i in items))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    cats = {}
    for c in ["Secrets", "AI safety", "Unsafe code", "Personal data", "Hygiene"]:
        sub = [i for i in items if i["category"] == c]
        worst = max((SEV_ORDER.index(i["severity"]) for i in sub), default=-1)
        cats[c] = {"count": len(sub), "status": "red" if worst >= 3 else "amber" if worst >= 1 else "green"}
    items.sort(key=lambda i: -SEV_ORDER.index(i["severity"]))
    blocking = sum(1 for i in items if i["severity"] in ("High", "Critical"))
    return {"repo": name, "decision": "block" if blocking else "pass", "blocking": blocking, "score": score, "grade": grade, "categories": cats, "findings": items}

def redact(rep):
    r = json.loads(json.dumps(rep))
    for i in r["findings"]:
        h = hashlib.sha1((i.get("file") or "").encode()).hexdigest()[:6]
        for k in ("title", "observation"):
            if i.get("file"):
                i[k] = i[k].replace(i["file"], f"[file-{h}]")
            i[k] = re.sub(r"(\[file-[0-9a-f]{6}\]):\d+", r"\1", i[k])
            i[k] = re.sub(r"\b[0-9a-f]{7}\b", "[commit]", i[k])
            i[k] = re.sub(r"Masked: .*?\.|masked .*?\)", "masked", i[k])
        i["file"] = f"[file-{h}]" if i.get("file") else ""
        i["line"] = None; i["evidence"] = "[redacted]"; i.pop("commit", None)
    return r

def write_csv(reports, path, team):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["title", "repo", "risk_rating", "observation", "recommendation", "verified", "team"])
        for rep in reports:
            for i in rep["findings"]:
                if i["severity"] == "Informational": continue
                w.writerow([i["title"][:100], rep["repo"], i["severity"], i["observation"], i["recommendation"], "no", team])


ENV_EXAMPLE = re.compile(r"(^|/)\.env\.(example|sample|template|dist)$")
SECRET_KEY_NAME = re.compile(r"(?i)(key|token|secret|passw|pwd|credential|dsn|auth)")
PLACEHOLDER_VAL = re.compile(r"(?i)^(|x+|\*+|<.*>|your[\w-]*|changeme|change-me|todo|example|placeholder|dummy|none|null|\.\.\.|sk-ant-x+|sk-x+)$")

def env_example_hits(path, content):
    """Real-looking values in .env.example (SAAF Guard rule 7: xxxx only)."""
    for i, line in enumerate(content, 1):
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]?([^'\"#\s]*)", line)
        if m and SECRET_KEY_NAME.search(m.group(1)) and not PLACEHOLDER_VAL.match(m.group(2)):
            yield i, m.group(1), m.group(2)

def load_saaf_guard():
    """Import SAAF Guard's check module if available (pip-installed, AIRLOCK_SAAF_GUARD, or a sibling saaf-guard folder)."""
    cands = [os.environ.get("AIRLOCK_SAAF_GUARD", ""), os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "saaf-guard")]
    for c in [None] + [c for c in cands if c]:
        if c and c not in sys.path:
            sys.path.insert(0, c)
        try:
            from saaf_guard import check as sg
            sg.set_lang("en")
            return sg
        except Exception:
            continue
    return None

def saaf_guard_staged_hits(sg, files):
    """Write staged versions of files to a temp dir and run SAAF Guard's rules on them."""
    import tempfile, shutil
    tmp = tempfile.mkdtemp(prefix="airlock-")
    try:
        for f in files:
            data = subprocess.run(["git", "show", f":{f}"], capture_output=True).stdout
            dst = os.path.join(tmp, f); os.makedirs(os.path.dirname(dst), exist_ok=True)
            open(dst, "wb").write(data)
        out = []
        for h in sg.scan(tmp, include_tests=True):
            sev, title, fix = sg.rule_text(h.rule)
            out.append((h.path, h.line, sev.capitalize(), f"[SAAF Guard {h.rule}] {title}", fix))
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ---------- pre-commit ----------
RED, YEL, GRN, DIM, B, R = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[1m", "\033[0m"

def staged():
    try:
        return _staged()
    except ScanError as e:
        print(f"\n{RED}{B}airlock ✖ CHECK FAILED, commit refused{R}\n  {e}\n"
              f"  {DIM}Airlock could not inspect the staged changes, so nothing was checked. Fix the error, or bypass once with git commit --no-verify.{R}\n")
        return 2

def _staged():
    diff = git(".", "diff", "--cached", "-U0", "--no-color", check=True)
    names = [f for f in git(".", "diff", "--cached", "--name-only", "-z", "--diff-filter=A", check=True).split("\0") if f]
    hits, cur, ln = [], None, 0
    for f in names:
        if ENV_FILE.search(f):
            hits.append((f, None, "High", ".env file staged", "Unstage it (git restore --staged) and add .env to .gitignore."))
    for line in diff.splitlines():
        if line.startswith("+++ "):
            cur = line[6:].rstrip("\t") if line.startswith("+++ b/") else None; continue
        m = re.match(r"@@ -\S+ \+(\d+)", line)
        if m: ln = int(m.group(1)); continue
        if line.startswith("+") and cur and not skip(cur):
            for rid, rname, val in find_secrets(line[1:]):
                hits.append((cur, ln, "Critical", f"{rname} ({mask(val)})", "Move it to .env (gitignored) and read it with os.environ."))
            for rid, title, sev, rec in code_hits(cur, line[1:]):
                if sev in ("High", "Critical"):
                    hits.append((cur, ln, sev, title, rec))
            ln += 1
    staged_files = [f for f in git(".", "diff", "--cached", "--name-only", "-z", "--diff-filter=AM", check=True).split("\0") if f]
    for f in staged_files:
        if ENV_EXAMPLE.search(f):
            content = subprocess.run(["git", "show", f":{f}"], capture_output=True, text=True, errors="replace").stdout.splitlines()
            for ln_, k, v in env_example_hits(f, content):
                hits.append((f, ln_, "High", f"Real value for {k} in {f} ({mask(v)})", "Use a placeholder (xxxx) in .env.example; keep real values only in .env, which stays out of git."))
    for f in staged_files:
        if f.endswith(".py"):
            content = subprocess.run(["git", "show", f":{f}"], capture_output=True, text=True, errors="replace").stdout.splitlines()
            for rid, title, sev, ln, rec in file_checks(f, content):
                if sev in ("High", "Critical"):
                    hits.append((f, ln, sev, title, rec))
    sg = load_saaf_guard()
    if sg and staged_files:
        sg_hits = [h for h in saaf_guard_staged_hits(sg, staged_files) if h[2] in ("High", "Critical")]
        kinds = {"SG01": "sec", "SG02": "fence", "SG03": "fail", "SG05": "server", "SG06": "exec"}
        covered = {(h[0], kinds.get(h[3].split()[2].rstrip("]"), "")) for h in sg_hits}
        def kind(t):
            return "sec" if ("key" in t.lower() or "secret" in t.lower()) else "fence" if "fence" in t else "fail" if "Fail-open" in t else "server" if ("0.0.0.0" in t or "CORS" in t or "Debug" in t) else "exec" if "eval" in t else "x"
        hits = [h for h in hits if (h[0], kind(h[3])) not in covered] + sg_hits
    seen_h = set(); hits = [h for h in hits if not ((h[0], h[1], h[3]) in seen_h or seen_h.add((h[0], h[1], h[3])))]
    tag = f"{DIM}rules: Airlock" + (" + SAAF Guard" if sg else "") + f"{R}"
    if not hits:
        print(f"{GRN}{B}airlock ✔ commit clean{R}  {tag}"); return 0
    print(f"\n{RED}{B}┌─ airlock ✖ COMMIT BLOCKED ─────────────────────────────{R}")
    for f, l, sev, what, rec in hits:
        if not what.startswith("[SAAF Guard"):
            what = "[Airlock] " + what
        print(f"{RED}│{R} {B}{sev:<8}{R} {f}{':' + str(l) if l else ''}\n{RED}│{R}          {what}\n{RED}│{R}          {DIM}fix: {rec}{R}")
    print(f"{RED}{B}└────────────────────────────────────────────────────────────{R}")
    print(f"{DIM}False positive? Commit with --no-verify and tell the maintainers.{R}  {tag}\n")
    return 1


HOOK_MARK = "# Airlock pre-commit guard"
PREV_HOOK = "pre-commit.pre-airlock"

def install(repo, chain=False):
    repo = os.path.abspath(repo)
    hooks = subprocess.run(["git", "-C", repo, "rev-parse", "--git-path", "hooks"], capture_output=True, text=True).stdout.strip()
    if not hooks:
        print("Not a git repo:", repo); return 1
    hooks = hooks if os.path.isabs(hooks) else os.path.join(repo, hooks)
    os.makedirs(hooks, exist_ok=True)
    me = os.path.abspath(__file__).replace("\\", "/")
    hook = os.path.join(hooks, "pre-commit"); prev = os.path.join(hooks, PREV_HOOK)
    if os.path.exists(hook):
        try:
            ours = HOOK_MARK in open(hook, encoding="utf-8", errors="ignore").read()
        except OSError:
            ours = False
        if not ours and not chain:
            print(f"{RED}{B}Airlock not installed:{R} {repo} already has a pre-commit hook, and Airlock will not overwrite it.\n"
                  f"  Keep it and add Airlock:  python \"{me}\" install \"{repo}\" --chain\n"
                  f"  (your hook is kept as {PREV_HOOK} and runs first, then Airlock)\n"
                  f"  Or call Airlock from your own hook:  python \"{me}\" staged")
            return 1
        if not ours:
            if os.path.exists(prev):
                print(f"{RED}{B}Airlock not installed:{R} {PREV_HOOK} already exists in {hooks}. Remove or merge it first."); return 1
            os.replace(hook, prev)
    chained = os.path.exists(prev)
    with open(hook, "w", newline="\n") as fh:
        fh.write("#!/bin/sh\n" + HOOK_MARK + "\n"
                 + (f'd=$(dirname "$0")\nif [ -f "$d/{PREV_HOOK}" ]; then sh "$d/{PREV_HOOK}" "$@" || exit $?; fi\n' if chained else "")
                 + "for p in python python3 py; do\n"
                 f"  if command -v $p >/dev/null 2>&1 && $p -c 'import sys' >/dev/null 2>&1; then exec $p \"{me}\" staged; fi\n"
                 "done\n"
                 "echo 'airlock: Python was not found, so this commit was NOT checked and is refused.' >&2\n"
                 "echo 'Install Python 3.9+ or fix PATH. To bypass once: git commit --no-verify' >&2\n"
                 "exit 1\n")
    os.chmod(hook, 0o755)
    print(f"{GRN}{B}Airlock installed{R} in {repo} (pre-commit hook). Every commit is now checked."
          + (f" Your existing hook was kept as {PREV_HOOK} and runs first." if chained else ""))
    return 0

def main():
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace', line_buffering=True)
    except Exception:
        pass
    if os.name == 'nt':
        os.system('')
    ap = argparse.ArgumentParser(prog="airlock")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("repos", nargs="+"); s.add_argument("--json"); s.add_argument("--csv")
    s.add_argument("--redact", action="store_true"); s.add_argument("--team", default="airlock")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "never"], default="never")
    sub.add_parser("staged")
    i = sub.add_parser("install"); i.add_argument("repo", nargs="?", default=".")
    i.add_argument("--chain", action="store_true", help="keep an existing pre-commit hook and run it before Airlock")
    a = ap.parse_args()
    if a.cmd == "staged":
        sys.exit(staged())
    if a.cmd == "install":
        sys.exit(install(a.repo, a.chain))
    reports, failed = [], []
    for r in a.repos:
        try:
            rep = scan_repo(r)
        except ScanError as e:
            failed.append(r)
            print(f"  {RED}{B}{os.path.basename(os.path.abspath(r))}: SCAN FAILED · not assessed{R}\n    {e}\n")
            continue
        reports.append(rep)
        col = {"red": RED, "amber": YEL, "green": GRN}
        n = rep["blocking"]
        if n:
            print(f"  {RED}{B}{rep['repo']}: BLOCK · {n} blocking finding{'' if n == 1 else 's'} (High/Critical) · scan completed{R}")
        else:
            print(f"  {GRN}{B}{rep['repo']}: PASS · no blocking findings · scan completed{R}")
        print(f"  {DIM}score {rep['score']}/100, grade {rep['grade']}{R}")
        for c, v in rep["categories"].items():
            print(f"    {col[v['status']]}●{R} {c:<14} {v['count']}")
        print()
    if a.json:
        data = [redact(x) for x in reports] if a.redact else reports
        json.dump(data, open(a.json, "w", encoding="utf-8"), indent=2)
    if a.csv:
        write_csv(reports, a.csv, a.team)
    worst = max((SEV_ORDER.index(i["severity"]) for rep in reports for i in rep["findings"]), default=-1)
    th = {"critical": 4, "high": 3, "medium": 2, "never": 99}[a.fail_on]
    sys.exit(2 if failed else 1 if worst >= th else 0)  # 2 = a scan could not run

if __name__ == "__main__":
    main()
