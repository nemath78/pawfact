# 🐾 Pawfect Homes
A cute pet rehoming marketplace. Built with 💗 by **Nemath & Tanaaz**.
Data (accounts, pets, messages, posts) lives in **Supabase Postgres**; photos live in **Supabase Storage**.

## Setup
1. Supabase → SQL Editor → paste `supabase.sql` → Run (creates tables + the `pets` photo bucket).
2. Supabase → Settings → API Keys: copy the **Project URL** and the **secret / service_role** key.
3. On Render → your service → Environment, add:
   - `SUPABASE_URL` = your Project URL
   - `SUPABASE_SERVICE_KEY` = your secret key  (never put this in GitHub or share it!)
4. Deploy, then open `https://YOUR-SITE.onrender.com/health` – it should show `"db":true`.

## Run locally
    SUPABASE_URL=... SUPABASE_SERVICE_KEY=... node server.js
