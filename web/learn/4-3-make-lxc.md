# Make an LXC container

When you want a small, complete Linux box to log into and tinker with — rather than a single boxed-up app — that's an **LXC container**. Like Docker, WolfStack does it in **two steps**.

## Get to the right screen

1. In the sidebar, click your **server**.
2. Click **LXC**.
3. Click the **+ Create Container** button (top-right of the LXC Containers card).

A window opens: **Create LXC Container — Step 1: Select Template**.

## Step 1 — pick a template

A "template" is which Linux distribution your container starts as — Debian, Ubuntu, Alpine, and so on.

- Use the **filter box** (*Filter templates (e.g. debian, ubuntu, alpine…)*) to narrow the list.
- You'll see variants tagged **server**, **cloud**, or **desktop**. For a normal little Linux box, pick a **server** variant of a distro you're comfortable with — **Debian** or **Ubuntu** are friendly defaults.
- Click **Select →** on the row you want.

The window moves to step 2.

## Step 2 — configure it

You'll see **Create LXC Container — Step 2: Configure**. The fields that matter:

- **Container Name** — a name (a sensible default like `debian-bookworm` is filled in).
- **Root Password** — set a password for the `root` user. **You'll need this to log in, so don't leave it blank.** Pick something you'll remember or store it safely.
- **Memory Limit** and **CPU Cores** — how much of the host this box may use. The defaults (around **1 GB** RAM, **1 core**) are fine for a first container.
- **Storage** — tucked inside a collapsible **Storage** section. The defaults are correct for almost everyone; only open it if you know you want the container to live on a specific disk.

Click **Create Container** at the bottom.

## Watch it

The **task log** shows WolfStack fetching the template and building the container. When it finishes, it appears in the LXC list. Start it, then you can open a shell inside it (that's the next module) and treat it like any small Linux server.

> Unlike a Docker container, an LXC container *persists* like a real machine — install packages, run a few services, reboot it. It's the right tool when "one app in a box" feels too restrictive.

## ✓ What you just learned

- **Server → LXC → + Create Container** opens a two-step wizard.
- **Step 1:** filter and **Select →** a distro template (a **server** variant of Debian/Ubuntu is a friendly start).
- **Step 2:** set a **Container Name** and a **Root Password** (don't skip it), keep Memory/CPU/Storage on defaults, then **Create Container**.
