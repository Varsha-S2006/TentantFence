# TenantFence 3-minute demo

## Before the demo

From the repository root, run `.\scripts\dev.ps1` and open <http://127.0.0.1:5173>. Keep the API and engine terminals visible. The app uses synthetic data only.

## Script

1. **20 seconds — establish the boundary.** “Alice is a member of Tenant A. Bob is a member of Tenant B. Invoice 102 belongs to Bob.”
2. **30 seconds — prove the leak.** Ensure the API is in vulnerable mode, then run:

   ```powershell
   curl.exe -i http://127.0.0.1:8001/invoices/102 -H "X-User-ID: alice"
   ```

   Point out `CANARY-B-102-x9f3` in the real response.

3. **40 seconds — scan live.** Run the dashboard scan. Show the progress counter, the policy-derived principal/resource matrix, and newly appearing findings. Explain that each result comes from a request to the local API.
4. **30 seconds — inspect proof.** Select a red matrix cell. Show the request and response, exact canary, severity, curl reproduction, and suggested tenant-check dependency.
5. **30 seconds — fix and retest.** Select **Switch to secure & retest**. Show the secure target mode, identical suite size, and the before/after leak delta.
6. **20 seconds — prevent regression.** Download the regression pack and point out `test_tenant_isolation.py` and `.github/workflows/tenantfence.yml`. The generated tests replay the observed cross-tenant cases against secure mode.
7. **10 seconds — close.** “Prove the leak. Fix it. Retest it.”

Counts are run-derived; they can vary when the policy, route set, or vulnerability toggles change.

## Fallback

- If the dashboard is unavailable, use both API Swagger pages at `http://127.0.0.1:8000/docs` and `http://127.0.0.1:8001/docs`, then run the standalone engine with `.\backend\venv\Scripts\python.exe -m engine.run`.
- If the scan engine cannot connect to the target, confirm the demo API is listening at `127.0.0.1:8001` and that `backend\policy.json` still points to that loopback address.
- If a run is incomplete or demo data was mutated, restart the demo API and call `POST http://127.0.0.1:8001/admin/reset`, then rerun the scan.
- For an offline artifact walkthrough, open [`docs/sample-report.md`](docs/sample-report.md) and the dashboard screenshot in `docs/`.
