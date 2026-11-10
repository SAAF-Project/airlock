# Airlock

**The commit-time layer for SAAF agent repos.** Airlock refuses a `git commit` that contains the mistakes found in SAAF agents on 10 November 2026, before they ever reach git history.

Built at the SAAF Security Challenge (Session #10, 10 Nov 2026).

## Why

On 10 Nov 2026 the challenge teams found 61 weaknesses in 29 SAAF repos. [SAAF Guard](https://github.com/SAAF-Project/saaf-guard) turned them into 17 rules that run in CI on every push.

CI runs *after* the push. By then a key is already in the remote history, and on a public repo it has leaked. SAAF Guard's README asks developers to run the check before committing, but nothing enforces it.

Airlock enforces it: it runs SAAF Guard's rules, plus its own, on the staged files at `git commit`, and refuses the commit on High or Critical findings.

## What it blocks at commit

| Mistake (from today's findings) | Example | Rule |
|---|---|---|
| Key or `.env` file committed | `git add .` picks up `.env` | Airlock + SAAF Guard SG01 |
| `.env.example` with real values instead of placeholders | key copied from `.env` | **Airlock only** |
| Auditee document sent to the LLM without a fence (prompt injection) | `f"Review this report: {pdf_text}"` | SAAF Guard SG02 (+ Airlock fallback) |
| Fail-open verdict inside an error branch | `except: return "Green"` | **Airlock only** (SG03 checks only a function's last line) |
| Agent server open to the network | `app.run(host="0.0.0.0", debug=True)` | SAAF Guard SG05 (+ Airlock fallback) |
| Command execution on input | `eval(model_output)`, `shell=True` | SAAF Guard SG06 (+ Airlock fallback) |

Every block shows file, line, which rule fired and the fix. Secret values are masked.

**For secrets, use a dedicated scanner too.** [gitleaks](https://github.com/gitleaks/gitleaks) and similar tools know hundreds of key formats; Airlock knows about ten. Airlock's value is the AI-agent rules that generic hooks cannot see.

## Install (any SAAF repo, one command)

Requires Python 3.9+ and git. Standard library only, works offline.

```bash
python airlock.py install path/to/your-agent-repo
```

If the repo already has a pre-commit hook, Airlock does not overwrite it. Add `--chain` to keep it: your hook runs first, then Airlock.

```bash
python airlock.py install path/to/your-agent-repo --chain
```

The hook fails closed: if Python is missing or git cannot be read, the commit is refused with a message, not silently let through.

SAAF Guard is used automatically when it is importable: `pip install -e` it, set `AIRLOCK_SAAF_GUARD=/path/to/saaf-guard`, or keep it next to Airlock (`../saaf-guard`). Without it, Airlock's own rules still run.

Alternatives:

- [pre-commit](https://pre-commit.com) framework: add this repo with hook id `airlock`. pre-commit installs Airlock from `pyproject.toml`, so nothing has to be copied into your repo.
- CI: copy `airlock.py` and `.github/workflows/airlock.yml` for a full repo + history scan on every push.

Full scan of an existing repo (auditors, maintainers):

```bash
python airlock.py scan repo1 repo2 --csv findings.csv   # challenge CSV format, verified=no
python airlock.py scan . --fail-on high                 # exit 1 for CI
```

The scan prints the decision first (`BLOCK · 2 blocking findings` or `PASS`); the score is secondary. A folder that is not a git repo, or a git error, gives `SCAN FAILED · not assessed` and exit code 2, never a score.

## Tests

```bash
python -m unittest discover -s tests -v
```

Offline, standard library only. Covers filenames with spaces, partial staging, history-only secrets, masking in every evidence field, existing hooks, non-git folders and a clean repo.

## Live demo

```bash
python demo.py          # Enter between steps
python demo.py --auto   # no pauses
```

Builds a throw-away "vendor review agent" repo in your home folder and makes four mistakes from today's findings: `.env` and a real key in `.env.example`, an unfenced vendor PDF, a fail-open rating and an open web server. Each commit is refused, fixed, and then goes through. The fake key is generated at runtime.

## Limitations

- Pattern-based static checks. They miss things (a prompt built in another file, unknown key formats) and can raise false alarms.
- The fence check is file-level: a fence marker anywhere in the code (comments do not count) counts as fenced. It shows a marker is missing; it does not prove the prompt is safe, and every untrusted input is not traced.
- Fencing reduces prompt-injection risk; it does not remove it. SAAF Guard's own red-team found 0 successful attacks on current models with or without a fence, so treat this as defence in depth.
- The fail-open check looks for pass-like return values ("Green", "Pass", "Compliant", …) within a few lines of `except`, `if not x` or `if len(x) == 0`. Other shapes are missed.
- About 30 of today's 61 findings are design flaws no static check can see (approvals from the request body, ungrounded quotes). SAAF Guard's build rules cover those during design.
- A local hook can be skipped with `git commit --no-verify`. Keep the CI check as the backstop.
- Python and JavaScript focused.

## Credits

Builds on SAAF Guard's rules and today's findings from the SAAF Security Challenge teams. Part of the [SAAF Project](https://saafproject.com).
