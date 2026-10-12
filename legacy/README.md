# legacy/

What we deploy **into** the legacy system per customer: Perfex modules, never core edits (ADR-0024, ADR-0025). The legacy tree itself is the customer's and is not in any repository we own.

Today: `modules/erp_sso/` — the wave-0 SSO bridge that lets unmigrated Perfex screens accept erp-api's RS256 token (ADR-0030). Locally, `erp-infra/legacy-local/docker-compose.yml` bind-mounts it read-only into the legacy container and `activate-module.mjs` there writes its `tblmodules` row on the local database. Phase 5 wires the upload to the customer's host (upload the folder to `modules/`, then Setup → Modules → Activate; Deactivate rolls it back).
