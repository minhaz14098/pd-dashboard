# PD Dashboard

The dashboard keeps its existing design and browser saved data. Existing Sheets exports are read without modifying their rows.

## Services already in Cloudflare

The Worker uses the existing `pd-dashboard-api` service and its D1 binding `BD` (`pd-dashboard-auth`). It does not create a new database or run schema migrations. The existing CSV export variables and Resend key are preserved on deploy with Wrangler's `keep_vars` option.

## Deployment

The repository Actions workflows deploy the Worker first. GitHub Pages publishes only after that Worker deployment succeeds. In repository settings, set **Pages → Build and deployment → Source → GitHub Actions**.

Add these GitHub Actions **secrets** for the Worker workflow:

- `CLOUDFLARE_API_TOKEN`: the no-expiration Cloudflare Workers Scripts Edit token. Cloudflare only offered account-level scope for this token, so treat it as a broad account credential and limit GitHub repository collaborators who can edit workflows.
- `AUTH_SECRET`: a long random signing secret.
- `SETUP_KEY`: a separate one-time key used to create the first account.
- `MAIL_FROM`: the sender address configured for Resend. The current `onboarding@resend.dev` sender is a Resend test sender and may only deliver to the account owner; verify a domain in Resend and use its sender address for production OTP delivery.
- `SHEETS_WRITE_URL`: the deployed Apps Script web app URL.
- `SHEETS_WRITE_KEY`: a long random key that matches the Apps Script property.

The Cloudflare account ID and D1 binding ID are in `worker/wrangler.toml`. Keep the current `RESEND_API_KEY`, `TRACKER_CSV_URL`, and `COSTING_CSV_URL` as they are in Cloudflare. The deploy workflow deliberately does not replace or rotate the Resend key.

After a successful deploy, open the dashboard and choose **Create first account**. Enter your email, a password of at least 12 characters, and the one-time `SETUP_KEY`; then enter the email OTP. Setup is allowed only while the D1 `users` table has no rows. The OTP activates the first account. No existing D1 row is removed.

## Email OTP

The Worker uses the existing `RESEND_API_KEY` variable to send login, setup, and password-reset codes. `MAIL_FROM` must be an address Resend allows for this account; using a sender that is not verified can make code delivery fail. The existing key value is not changed by these files or workflows.

## Google Sheets write sync

Writes are append-only. The dashboard sends the selected Tracker or Costing rows to Apps Script; the script writes to the sheet tab matching its configured numeric `gid`. It never clears existing cells.

Deploy `worker/google-apps-script.js` as a Google Apps Script **Web app**, running as the sheet owner. Configure Script Properties:

- `SHEETS_WRITE_KEY`
- `TRACKER_SPREADSHEET_ID` and `TRACKER_SHEET_GID`
- `COSTING_SPREADSHEET_ID` and `COSTING_SHEET_GID`

Use the spreadsheet ID from its URL and each tab's numeric `gid`. Then add the web app URL and the same writer key to the GitHub Actions secrets above. Repeating an append can add duplicate rows, so use the dashboard sync button only when you intend to append.

## Checks

Run from `worker/` with Node.js:

```sh
node --test
node --check src/index.js
```
