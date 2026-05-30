# Put up a status page

A status page is a simple public web page that shows whether your services are up — the kind of "🟢 All systems operational" page you've seen from big companies. If anyone else relies on something you host (or you just want a clean dashboard of "is it up?"), this is a lovely, optional finishing touch.

It has two parts: **monitors** (the checks) and a **page** (where they're shown). You make a monitor first, then a page that displays it.

## Open Status Pages

Open the **Status Pages** screen — it's grouped under your cluster. You'll see tabs along the top: **Pages**, **Monitors**, and **Incidents**.

## Step 1 — create a monitor

1. Click the **Monitors** tab, then **+ New Monitor**.
2. Fill in:
   - **Monitor Name** — e.g. `Web Server`.
   - **Check Type** — how to test it. Common choices:
     - **HTTP(S)** — checks a web address responds. You'll enter a **URL** and an expected status (usually **200**).
     - **TCP Port** — checks a **host** + **port** is open.
     - **Ping** — checks a **host** simply responds.
   - **Check Interval (seconds)** — how often to test. **60** is fine.
   - **Timeout (seconds)** — how long to wait before calling it down. **10** is fine.
   - **Enabled** — leave it ticked.
3. Click **Save Monitor**. It starts checking immediately.

## Step 2 — create the public page

1. Click the **Pages** tab, then **+ New Page**.
2. Fill in:
   - **Page Title** — e.g. `My Status`.
   - **URL Slug** — the web address. It becomes **`/status/your-slug`**, so a slug of `home` gives you `/status/home`.
   - **Logo URL** and **Footer Text** — optional branding.
   - **Public Page Theme** — pick a look (Dark, Light, Midnight, and more).
   - **Monitors & Incidents** — tick the monitor you just made so it appears on the page.
   - **Enabled** — leave it ticked.
3. Click **Save Page**.

Your page is now live at **`https://your-server/status/your-slug`** — and importantly, it's **public and needs no login**, so you can share that link with anyone.

> **Keep public pages clean.** A status page is for "is it up?" — uptime and incidents. It's deliberately *not* a place for internal details, host data, or anything sensitive. WolfStack keeps it to safe basics by design; keep your monitor names friendly and generic too.

## ✓ What you just learned

- A status page = **monitors** (checks) shown on a **page** (public).
- **Monitors tab → + New Monitor**: name, **Check Type** (HTTP/TCP/Ping), interval, timeout, **Save Monitor**.
- **Pages tab → + New Page**: title, **URL Slug**, theme, tick your monitor, **Save Page**.
- The result is public at **`/status/your-slug`** — shareable, no login. Keep it free of internal detail.
