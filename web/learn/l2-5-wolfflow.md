# Automate the boring stuff with WolfFlow

Every operator ends up doing the same little chores by hand: check for updates, clean up old files, restart a flaky service, run a backup before a risky change. WolfFlow lets you build those as **flows** — visual "when *this* happens, do *that*" automations that run themselves, across your whole cluster.

## Open WolfFlow

1. Click the **Apps & Tools** drawer (the grid icon at the top of the sidebar).
2. Open **WolfFlow**.

It's a drag-and-drop canvas. You build a flow by connecting blocks: a **trigger** (what starts it) wired to one or more **actions** (what it does).

## The shape of a flow

Every flow is the same simple idea:

- **A trigger** — a schedule ("every night at 2am"), or an event ("when this container stops").
- **One or more actions** — take a backup, run a command, send an alert, restart something.

Wire a trigger to an action, save it, and WolfFlow runs it for you — no more remembering to do it yourself.

## A good first flow

Don't automate anything scary on day one. Build something you can *watch* and that can't hurt you:

- **Trigger:** every morning.
- **Action:** send yourself an alert with a quick health summary.

You'll get a daily ping, you'll see exactly how triggers and actions connect, and nothing is at risk. Once that feels natural, graduate to "back up before the weekly update" and other genuinely useful chores.

> **Automate boring before you automate scary.** The first flow's job is to teach you the tool, not to do something important. Build a harmless one, watch it fire a few times, *then* trust it with real work. Automation you don't understand is just a faster way to break things.

## ✓ What you just learned

- **Apps & Tools → WolfFlow** is a visual automation canvas.
- Every flow is a **trigger** (schedule or event) wired to **actions** (backup, command, alert, restart…).
- Start with a **harmless, watchable** flow (a daily summary) before automating anything that matters.

## Try it

Build the daily-summary flow above. When it pings you tomorrow morning, you'll *get* WolfFlow — and you'll already be thinking of three chores you never want to do by hand again.
