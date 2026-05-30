# Back something up right now

This is the lesson that lets you sleep at night. A backup is just a copy you can restore from when something breaks — and something always, eventually, breaks. The good news: WolfStack makes a backup a few clicks, and you can do one **right now**.

## Open the Backups screen

1. In the sidebar, click your **server**.
2. Click **Backups**.

You'll see the **Backup Manager**. It lists everything that *can* be backed up on this server — your Docker containers, LXC containers, VMs, and the WolfStack config itself — each with a checkbox.

## Choose what to back up

Tick the box next to each thing you want to copy. For your first backup, pick the one app you installed earlier — small and quick. You can use **Select All** if you want everything, but start small to see how it feels.

## Choose where it goes

Find the **Storage** dropdown. The default is:

- **Local — /var/lib/wolfstack/backups** — saved onto this same server.

Local is perfectly fine to start with. Later you'll want backups on a *different* machine or service (NFS, SMB, WolfDisk, or PBS if you've set one up) — because a backup that lives on the same box that dies isn't much of a backup. But for learning the flow, **Local is fine.**

## Make the backup

Click **Backup Now**.

A progress log appears, and when it's done a new row shows up in the **Backup History** table below — with the target, size, date, and a green **Completed** status. That row is your safety net.

> **The honest truth about backups:** the best backup strategy is the one you actually do. A local backup you take today beats the perfect off-site, encrypted, tested backup you keep meaning to set up. Do the easy one now; improve it later.

## ✓ What you just learned

- **Server → Backups** opens the **Backup Manager**.
- **Tick** what to back up, pick a **Storage** target (**Local** is a fine start), click **Backup Now**.
- Completed backups appear in the **Backup History** table.
- A backup on a *different* machine is better — but any backup beats none.

## Try it

Back up your one app right now. It takes under a minute and you'll have done the single most important operational habit there is.
