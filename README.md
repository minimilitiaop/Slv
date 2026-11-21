# Selov asx

3D storefront, GCash top-up, share orders, customer live chat, and a private admin dashboard. The server uses only Node.js 18+ and has no npm dependencies.

## Page layout

- `index.html` — public storefront and share-order interface.
- `login.html` — customer login.
- `register.html` — customer account registration.
- `chat.html` — customer-to-agent chat page.
- `adminsecretwow/login.html` — admin sign-in page.
- `adminsecretwow/adminsecretwow.html` — private admin dashboard source file. The server only returns this page to a valid admin session; requesting its file path directly is not allowed.
- `server.js` — API, authentication, chat transport, payment handling, and protected page routing.

The admin dashboard's **Chat** section is where the agent reads and replies to customer conversations. Customer chat messages are backed by the same authenticated server API and appear in the dashboard in real time. The page CSS and browser JavaScript are embedded in their corresponding HTML files; the storefront also includes the pinned Three.js r128 library. The favicon and GCash QR are separate image assets.

## Run it

```bash
cd selov-asx
ADMIN_PASSWORD='your-long-password' npm start
```

The admin password must be at least 10 characters. In Windows PowerShell:

```powershell
$env:ADMIN_PASSWORD='your-long-password'; npm start
```

The admin page is at `http://localhost:3000/adminsecretwow` by default. If `ADMIN_PASSWORD` is configured, it is authoritative on every start; changing the environment value and restarting rotates the password. It is never sent to the browser and is stored in the database only as a salted scrypt hash. If the variable is not set on first run, the server creates a random password and prints it once.

With `ADMIN_PASSWORD` unset, you can change the password in **Admin → Settings → Admin password**, or with the server stopped using `node set-admin-password.js "new long password"`. If the environment variable remains set, that value will be restored as the password at the next server start.

The optional `ADMIN_PATH` environment variable changes the admin route, for example `ADMIN_PATH=/my-secret-door`. Keep the folder's dashboard file private; do not configure a separate static host to publish the `adminsecretwow/` folder.

## Customer features

1. Register with a username and PIN to receive a unique ID such as `SLV-AB12CD`; balance starts at ₱0.00.
2. Submit a Facebook post link and share amount. A free claim is available once per device, within the configured limit.
3. Paid Pro/Premium orders are deducted from the customer's server-held balance.
4. Customers can submit GCash top-ups with a screenshot and optional reference number. Balance is credited only after admin approval.
5. Customers can use the live chat page; the agent responds from the admin dashboard.
6. Customers can submit feedback, reports, and ideas.

## Admin dashboard

- **Payments:** view submitted screenshots, approve or reject payments.
- **Users:** search by user ID, add/deduct balance, review ledger, ban users, and reset PINs.
- **Orders:** start, complete, or cancel orders; cancellation refunds the balance.
- **Chat:** respond to customer conversations in real time.
- **Feedback:** review, resolve, delete, or publish approved feedback.
- **Settings:** manage limits, tiers, GCash details and QR, and the admin password.
- Enable alerts for badges, sound, and browser notifications.

## Security notes

The dashboard page is served only after admin authentication, and all admin API routes independently verify the admin session. Passwords use salted scrypt hashes, login attempts are rate-limited, and admin sessions use HttpOnly cookies with SameSite=Strict. The server also checks CSRF headers and request origin, validates uploads, and never trusts client-supplied prices or balances.

## Going live

1. Host the Node app behind HTTPS (for example, Caddy, nginx, or Cloudflare).
2. Set `ADMIN_PASSWORD` in the host's secret/environment settings. For a trusted reverse proxy that supplies `X-Forwarded-For`, start with `COOKIE_SECURE=1 TRUST_PROXY=1 PORT=3000 npm start`.
3. Back up the `data/` directory; it contains the database and uploaded screenshots and is created automatically.
4. Keep the admin folder outside any static-public directory. The application server is responsible for checking the admin session before serving the dashboard.

## Notes

- “Free once per device” is best-effort, with device cookie, browser fingerprint, and per-IP limits.
- Orders are a queue to fulfill; the site does not post to Facebook itself.
- The GCash QR in `public/img/gcash-qr.jpg` can be replaced in **Admin → Settings**.
- Public testimonials come only from feedback you approve in the dashboard.
