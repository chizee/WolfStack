# Install something from the App Store

This is the fun one. The App Store is the fastest way to get something real running, and it's the moment WolfStack starts feeling worth it. We'll install an app in a few clicks — no commands, no config files.

## Pick something low-stakes

For your first install, pick something small and harmless so you can relax and watch how it works. A good first choice is something like **Uptime Kuma** (a status monitor) or **It-Tools** (a box of handy web utilities) — light, useful, nothing to lose if you delete it later.

## The steps

1. Click **App Store** in the top of the sidebar.

2. Use the **search box** at the top (it says *Search apps…*) or the category buttons (**All, Web, Database, Monitoring, Media, …**) to find an app. Type the name of the one you picked.

3. On the app you want, click its **Install** button. A window titled **Install [App Name]** opens.

4. Fill in the basics:
   - **Deploy To** — which server to install it on. If you only have one, it's already selected.
   - **Container Name** — a name for this app. A sensible default is filled in; you can keep it.
   - **Install Target** — choose how it runs. You'll usually see **Docker** and/or **LXC** pills. **If you're not sure, pick Docker** — it's the simplest.
   - **Any app-specific fields** — some apps ask for things like a password or a domain. Fill in what they ask for. If a field has a sensible default, you can leave it.

5. Click the **Install** button at the bottom.

## Watch it happen

A **task log** opens along the bottom of the screen and shows progress in real time — pulling the app, setting it up, starting it. When it finishes you'll get a confirmation that it deployed.

> The first install of any app is the slowest, because WolfStack has to download it. That's normal. Later installs of the same kind are much quicker.

## If something goes wrong

The task log shows the actual error text — you can read it and copy it. The most common first-time issue is a **port already in use**; if you see that, install again and change the host port (we cover ports in the Docker lesson). Nothing here is permanent — you can always remove the app and try again.

## ✓ What you just learned

- The **App Store** installs ready-made apps in a few clicks.
- The key fields are **Deploy To**, **Container Name**, and **Install Target** (pick **Docker** if unsure).
- The **task log** at the bottom shows live progress and any errors.

## Try it

Install one small app now. Seriously — do it before the next lesson. The next lesson is about finding and opening the thing you just installed.
