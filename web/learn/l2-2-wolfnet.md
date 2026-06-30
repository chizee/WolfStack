# Link your servers with WolfNet

Here's a problem you'll hit the moment you have **two** servers: they can't easily talk to each other, especially if they're in different places — your house and a friend's, or home and a cloud box. Normally you'd be wrestling with firewalls, port forwarding, and VPN config files.

WolfNet skips all of that. It builds a **private, encrypted mesh network** that makes your servers (and even their containers) behave as if they're plugged into the same switch — wherever they actually are.

## Open WolfNet

1. In the sidebar, click the **server** you want to connect.
2. Open its **WolfNet** tab.

This is the per-server WolfNet screen. The first server you set up becomes part of the mesh; every other server you add **joins** the same mesh.

## What you're looking at

WolfNet gives each member a stable private address (in its own `10.x` range) that *doesn't change* even if the machine's real-world IP does. That stable address is the whole point: you can rely on it.

- On the **first** server, you turn WolfNet on. It becomes the anchor of the mesh.
- On **each other** server, you join — pointing it at the mesh so it gets its own private address.

Once two servers are both on WolfNet, they can reach each other by their WolfNet address as if they were side by side on the same LAN.

## A reason to do it

The classic one: you have a database on Server A and an app on Server B, in two different buildings. Put both on WolfNet, and the app talks to the database over the encrypted mesh — no ports opened to the internet, no VPN client to install on every machine.

> **Why this beats a normal VPN:** a VPN usually gives you a tunnel to *one* place. WolfNet is a **mesh** — every member can reach every other member directly, and it heals itself when an address changes. You set it up once and stop thinking about it.

## ✓ What you just learned

- **Server → WolfNet** opens the per-server WolfNet screen.
- WolfNet is a **private encrypted mesh** that gives each server a **stable address** and lets them talk as if on the same LAN.
- Turn it on once on your first server; **join** every other server to the same mesh.
- Best reason to use it: connecting servers in **different places** without opening ports.

## Try it (when you have two servers)

If you only have one server today, just remember this door exists — the day you add a second machine somewhere else, WolfNet is how you make them one network.
