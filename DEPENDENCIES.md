# Dependencies and supported checks

Runtime and tests use the Python standard library. No model SDK, API key or network
connection is required. CI runs Python 3.11 and 3.12 on Ubuntu 24.04; passing those
checks does not establish support for other interpreters or operating systems.

GitHub Actions are pinned to commit revisions in `.github/workflows/`. Review
upstream changes and rerun the same synthetic tests before updating a pin. Hosted
runner images and Python patch releases are still supplied by GitHub; this is not
a fully hermetic environment or a transitive dependency lock.

Airlock also requires Git. `pyproject.toml` describes its optional setuptools
installation route; direct `python airlock.py` execution requires no package
installation. The optional `saaf_guard` import is not required by these tests:
if installed or selected through `AIRLOCK_SAAF_GUARD`, its reviewed revision must
be managed separately. Do not treat this CI result as evidence for that plugin.
