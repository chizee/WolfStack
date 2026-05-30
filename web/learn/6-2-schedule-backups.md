# Make backups happen automatically

A backup you have to *remember* to take is a backup you'll forget to take. The fix is to schedule it once and let WolfStack do it for you, on its own, forever. This is a five-minute task that pays off for years.

## Set up a schedule

1. Go to your **server → Backups** (same screen as the last lesson).
2. **Tick the things** you want backed up on a schedule, and pick your **Storage** target — exactly as you did for a manual backup.
3. Click **Schedule** (next to the **Backup Now** button).

A window titled **Schedule Backup** opens. Fill in:

- **Schedule Name** — a label, e.g. `Nightly Backup`.
- **Frequency** — **Daily**, **Weekly**, or **Monthly**. Daily is a great default.
- **Time (UTC, HH:MM)** — when it runs, in 24-hour time. The default **02:00** (2 a.m.) is sensible — quiet hours. *Note it's **UTC**, so adjust if your local time matters to you.*
- **Retention (keep N backups, 0 = unlimited)** — how many to keep before old ones are deleted. **7** (a week of daily backups) is a good starting point. Set `0` only if you have lots of space.

Click **Create Schedule**.

Your new schedule appears in the **Backup Schedules** table, marked **Active**. From now on, WolfStack takes that backup for you automatically.

## A sane first policy

If you want a "just tell me what to do" answer:

> **Daily, at 02:00, keep 7.** Set that for your important containers, to Local for now (and to a second machine when you can). Done. That single schedule puts you ahead of most people.

## Check on it later

The **Backup Schedules** table shows each job; the **Backup History** table shows that they're actually running and succeeding. Glance at History once in a while to confirm you're seeing fresh, green **Completed** rows — a schedule that silently stopped working is the one that bites.

## ✓ What you just learned

- **Backups → Schedule** opens the **Schedule Backup** window.
- Set a **Name**, **Frequency**, **Time (UTC)**, and **Retention**, then **Create Schedule**.
- A good default policy is **Daily / 02:00 / keep 7**.
- Check **Backup History** occasionally to confirm scheduled backups are still running.
