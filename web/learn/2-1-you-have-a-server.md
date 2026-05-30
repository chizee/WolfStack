# You already have a server

Here's something reassuring: you don't need to *add* a server to start using WolfStack. You already have one — the machine you installed WolfStack on. Let's go look inside it.

## Find it

Look at the **Servers** list in the left sidebar. You'll see at least one entry there — that's your machine. It might show its hostname (a name like `pve-01` or `wolf-home`) and a little coloured dot telling you it's online.

**Click it.**

The main area now shows that server, and the sidebar expands to reveal the things *on* that server. Depending on what your machine can do, you'll see entries like:

- **Docker** — app containers
- **LXC** — lightweight Linux containers
- **VMs** — full virtual machines
- **Terminal** — a command line
- **Backups** — copies of your stuff

Don't click into them yet. Just notice: this is how WolfStack is organised. **Top level = your fleet. Click a server = what's on that one server.**

## What's a "cluster"?

You may see your server grouped under a heading like **WolfStack** or a cluster name. A *cluster* is just a fancy word for "a group of servers managed together." 

**One server is a perfectly good cluster of one.** You do not need more than one machine to use any of this. If you only ever have a single server, everything in this course still works exactly the same. Adding more servers is something you do when you *grow*, not something you have to do to start.

> If you came from Proxmox and you're used to thinking in clusters and quorum and nodes — you can let all of that go for now. One box. That's your whole world today.

## ✓ What you just learned

- The machine you installed on is already your first server — it's in the **Servers** list.
- **Click a server** to see what's running on it (Docker, LXC, VMs, Terminal, Backups…).
- A "cluster" is just a group of servers, and **one server on its own is completely fine.**

## Try it

Click your server in the sidebar, look at the list that appears under it, then click back to **Datacenter** (the house icon). That's all — you've just navigated WolfStack.
