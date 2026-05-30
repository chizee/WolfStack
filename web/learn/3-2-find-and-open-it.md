# Find it and open it

You installed an app. Where did it go? Let's find it, confirm it's running, and open it in your browser. This is the other half of the App Store skill — and the moment it stops feeling like magic and starts feeling like *yours*.

## Find your app

1. In the sidebar, click the **server** you installed it on.
2. Click **Docker** (or **LXC**, if you chose LXC as the install target).
3. There's your app in the list, with a status showing it's **running** (usually a green dot or "running" badge).

If it's running, congratulations — that's a working service you stood up yourself.

## Open it

Most App Store apps are web apps — they have a page you open in your browser. There are two easy ways in:

- **The quick way:** the app runs on your server at an address like `http://YOUR-SERVER-IP:PORT`. The port is the **host port** you saw (or accepted the default for) during install. So if your server is `192.168.1.50` and the app uses port `3001`, you'd open `http://192.168.1.50:3001` in a new browser tab.
- **The tidy way:** add it as a **Bookmark** on your Datacenter home screen (there's a **Bookmarks** card with an **+ Add** button), so next time it's one click away.

> Not every app is a web page — some are background services (like a database) with no UI to open. That's expected. If there's nothing to open in a browser, the app is still doing its job quietly.

## Manage it

While you're looking at the app in the **Docker** (or **LXC**) list, notice the action buttons on its row — **start**, **stop**, **restart**, **logs**, a **terminal** icon, and a way to **remove** it. You don't need them now, but it's good to know they're right there when you do.

## ✓ What you just learned

- Installed apps live under their server's **Docker** or **LXC** list, showing a **running** status.
- Open a web app at `http://YOUR-SERVER-IP:PORT`, or add a **Bookmark** for one-click access.
- Each app's row has **start / stop / restart / logs / terminal / remove** controls.

## Try it

Open the app you installed in a new browser tab. If it loads — you've just deployed and accessed your first self-hosted service through WolfStack. That's the whole core loop.
