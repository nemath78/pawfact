# 🐾 Pawfect Homes
A cute pet rehoming marketplace. Built with 💗 by **Nemath & Tanaaz**.

Real accounts, shared listings, photo uploads, owner messaging, favourites and a community board.
Zero dependencies – just Node 18+.

## Run locally
    node server.js
    # open http://localhost:3000

## Put it on GitHub
1. Create a new repo on github.com (e.g. `pawfect-homes`).
2. Upload everything in this folder (keep the `public/` folder as is).

## Deploy on Render
1. Render → **New → Web Service** → connect the repo (or **New → Blueprint** to use `render.yaml`).
2. Runtime **Node**, build command empty (or `echo ok`), start command `node server.js`.
3. Deploy. You get an `https://….onrender.com` link.

## ⚠️ Keeping data permanently
Render’s free plan wipes files on restart/redeploy, so users and pets would reset.
For a real launch: use a paid plan, add a **Disk** mounted at `/var/data`, and set env var `DATA_DIR=/var/data`.
(Later you can swap the JSON file for Postgres/Supabase if the site grows.)

## Security built in
scrypt-hashed passwords · random HttpOnly session cookies (Secure on https) · login/post rate limits ·
owner-only delete · JPEG-only validated uploads · CSP & security headers · no emails exposed except to a pet’s owner when someone messages them.
