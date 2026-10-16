# Tiny Django sample app (HAND-WRITTEN test fixture)

Not a real project. It exists so the exposure graph has something to read, and it is arranged so the packages from
`tests/sample/requirements.txt` reach the code in different ways:

| package  | where it is imported                         | expected exposure |
|----------|----------------------------------------------|-------------------|
| pyyaml   | `accounts/views.py` (the /login/ route)      | web               |
| requests | `api/views.py` (the /api/reports/ route)     | web               |
| jinja2   | `utils/helpers.py`, used by the login view   | web               |
| pyspark  | `jobs/management/commands/sync_reports.py`   | command           |
| six      | `config/settings.py` and the tests           | startup           |
| flask    | `utils/legacy.py`, which nothing imports     | none (unreachable)|

`django` is declared in requirements.txt of this folder; it has no advisories in the frozen sample snapshot.
