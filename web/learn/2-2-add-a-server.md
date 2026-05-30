# Adding another server

This lesson is optional. If you only have one machine, you can skip it with a clear conscience and come back the day you get a second one. If you *do* have another server, here's how to bring it into WolfStack so you can manage both from one place.

## Before you start

You need WolfStack installed and running on the **other** machine too. Each machine runs its own copy; you're just teaching them to talk to each other.

## The steps

1. In the bottom-left of the sidebar, click the **Add Server** button (the **+** icon). A window titled **Add Server** opens.

2. On the **other** server's dashboard, go to **Settings → Join Token** and copy its join token. (A join token is just a secret password that proves the two servers are allowed to connect.)

3. Back in the **Add Server** window, fill in:
   - **Cluster Name** — optional. A label to group servers in the sidebar. Leave it as the default if you're not sure.
   - **Join Token** — paste the token you copied from the other server.
   - **Server Address** — the other server's IP address or hostname, e.g. `10.10.10.1`. *Just the address — don't type `https://` in front of it.*
   - **Port** — leave this as **8553** unless you deliberately changed it.

4. Click **Add Server**.

You'll see a confirmation that the server was added, and it will appear in your **Servers** list.

> After adding nodes, WolfStack may suggest running **"Update WolfNet Connections"** in Cluster Settings to wire up the private networking between them. If you see that prompt, it's safe to follow — it's just letting your servers reach each other over an encrypted link.

## If it doesn't connect

- Double-check the **Server Address** — no `https://`, no trailing slash, no port number stuck on the end.
- Make sure the **Join Token** was copied in full.
- Confirm the other machine is actually reachable from this one (same network, or a route between them).

## ✓ What you just learned

- Each server runs its own WolfStack; you link them with a **Join Token**.
- Use **+ Add Server**, paste the token, type the plain **Server Address**, keep port **8553**.
- You never *need* a second server — this is purely for when you have one.
