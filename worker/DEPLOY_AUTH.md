# PD Dashboard authentication deployment

This branch adds a D1-backed authentication API and a login gate to the GitHub Pages UI. Do not merge/deploy until the D1 binding and provider secrets are configured.

## Cloudflare resources

1. Create a Cloudflare D1 database named \`pd-dashboard-auth\`.
2. Bind it to Worker \`pd-dashboard-api\` with variable name \`DB\`.
3. Apply \`worker/migrations/0001_auth.sql\` to that database (Cloudflare D1 SQL Console).
4. Keep the existing \`TRACKER_CSV_URL\` and \`COSTING_CSV_URL\` Worker variables.
5. Ensure Worker variable \`AUTH_REQUIRED\` is set to \`true\`.

## Worker secrets / variables

Required secrets:
- \`AUTH_PEPPER\`: a new random secret (32+ random bytes).
- \`ADMIN_SETUP_TOKEN\`: a one-time random setup code. Keep it private.
- \`RESEND_API_KEY\`: Resend API key for email OTP.

Required ordinary variable:
- \`RESEND_FROM_EMAIL\`: a sender address authorized by Resend.

Optional SMS secrets / variable:
- \`TWILIO_ACCOUNT_SID\`
- \`TWILIO_AUTH_TOKEN\`
- \`TWILIO_FROM_NUMBER\`

Start with Email OTP. SMS can be enabled later after Twilio verification.

## Build configuration

Cloudflare Workers Builds should use repository \`minhaz14098/pd-dashboard\`, branch \`auth-build\`, root directory \`worker\`, and deploy command \`npx wrangler deploy\`. The D1 binding must be present at deploy time.

## First administrator

After deployment, open the GitHub Pages dashboard. The first-run screen asks for the one-time \`ADMIN_SETUP_TOKEN\`, name, User ID, email, password (minimum 12 characters), and OTP channel. The first account is the administrator. Initial account creation is disabled after the first successful setup.

## Security notes

- Passwords use PBKDF2-SHA-256 with per-user random salts.
- OTP codes expire after 10 minutes and allow at most 5 guesses.
- OTP sends are limited to 5 per account per 15 minutes.
- Password login attempts are limited to 10 per IP/User ID per 15 minutes.
- Session tokens expire after 12 hours and are stored hashed in D1.
- The browser holds the session token in sessionStorage and sends it as a Bearer token. Avoid third-party scripts on the dashboard.
- CORS is restricted to \`https://minhaz14098.github.io\`.
