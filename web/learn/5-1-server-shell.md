# Open a shell on a server

Sooner or later you'll want a command line — to check something, run a one-off command, or follow a guide that says "type this." WolfStack gives you a full terminal right in your browser. No SSH client, no keys to set up.

## Open it

1. In the sidebar, click your **server**.
2. Click **Terminal**.

That's it. WolfStack connects you automatically. You'll see a status that changes from **Connecting…** to **Connected** (in green), and then a normal shell prompt — the same one you'd get if you SSH'd into the box.

You can now type commands exactly as you would in any Linux terminal. Output streams back live.

> This is a *real* root shell on your server. That's powerful and convenient — and it means the usual caution applies: don't paste commands you don't understand. When a guide tells you to run something, read it first.

## Pop it out

The terminal sits inside the WolfStack page by default. If you'd rather have it in its own window — say, to keep it open beside the dashboard — click **Pop Out**. It opens the same session in a separate browser window you can move and resize.

## A couple of handy facts

- The terminal **scrolls** — scroll up to see earlier output (it keeps a long history).
- If you navigate away to another screen, the inline terminal closes its connection cleanly. Come back to **Terminal** to start a fresh session.
- On a **Proxmox** host, this opens the host's shell, just as you'd expect.

## ✓ What you just learned

- **Server → Terminal** gives you a full browser-based command line, no setup.
- Wait for the green **Connected** status, then type as normal.
- **Pop Out** moves it to its own window.
- It's a real root shell — convenient, but treat it with the same care.

## Try it

Open a terminal on your server and run a harmless command like `uptime` or `df -h` (that one shows disk space). Watch the output appear. Now you know you can always get a command line in two clicks.
