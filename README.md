# Server-side login version (recommended for real protection)

The site in `protected/index.html` is sent to the browser ONLY after the server has checked the
username and password. The password is not in any file: the server keeps only a scrypt hash in
an environment variable, and signs session cookies with a secret (also an environment variable).

## What it does
- scrypt password hashing, constant-time comparison
- HttpOnly + SameSite cookie (Secure over HTTPS), 8-hour signed session
- 5 failed logins per 15 minutes per IP, then HTTP 429
- Origin check on login/logout, security headers, no-store caching of the protected page
- No npm packages needed (Node 18 or newer)

## 1. Make the two secret values (run on any computer with Node)
    node hash-password.js "the password"                -> value for AUTH_PASS_HASH
    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   -> value for SESSION_SECRET

## 2. Test on your computer
    AUTH_USER=AIRCoE AUTH_PASS_HASH='<hash>' SESSION_SECRET='<secret>' node server.js
    Open http://localhost:3000   (Windows PowerShell: set the three variables with $env:NAME='value' first)

## 3. Deploy on Render (free tier works)
1. Put this `server-version` folder in a GitHub repository (do NOT add a .env file).
2. render.com -> New -> Web Service -> pick the repository.
3. Runtime: Node. Build command: (leave empty). Start command: `node server.js`.
4. Environment -> add AUTH_USER, AUTH_PASS_HASH, SESSION_SECRET.
5. Deploy. Open the https://....onrender.com address and sign in.
GitHub Pages and Netlify static hosting cannot run this server; use Render, Railway, Fly.io or any Node host.

## Change the password later
Run hash-password.js with the new password, replace AUTH_PASS_HASH on the host, redeploy.
