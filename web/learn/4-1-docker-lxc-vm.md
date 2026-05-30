# Docker, LXC or VM — which one?

When you create something yourself (instead of using the App Store), WolfStack asks whether you want a **Docker container**, an **LXC container**, or a **VM**. This trips people up, so let's make it simple. You almost never need to agonise over this.

## The 20-second answer

> **If you're not sure, choose Docker.** It's the easiest, the most disposable, and the right answer most of the time.

## The slightly longer version

Think of it as **how much "computer" you're wrapping around your app.**

**Docker container** — *one app in a box.*
The lightest option. You're not running a whole operating system, just the app and exactly what it needs. Fast to start, easy to throw away and recreate. This is what most self-hosted apps want. **Start here.**

**LXC container** — *a lightweight whole Linux system.*
A step up. It feels like a small, complete Linux machine you can log into and treat like a normal server — install packages, run several things — but without the weight of a full virtual machine. Reach for this when you want "a little Linux box," not just one app.

**VM (virtual machine)** — *a full virtual computer.*
The heaviest, most isolated option. It boots its own operating system from scratch — even a different one, like Windows or a firewall appliance. Use this when you need complete separation, a non-Linux OS, or to run a kernel-level thing. It costs the most memory and disk.

## A rule of thumb

| You want to… | Use |
|---|---|
| Run a single app (the usual case) | **Docker** |
| Have a small Linux box to tinker in | **LXC** |
| Run a whole separate OS / Windows / a firewall | **VM** |

## Don't overthink it

You're not marrying this decision. If you pick Docker and later wish you had a full LXC box, you delete one and make the other in two minutes. The cost of choosing "wrong" is tiny. The cost of *not starting because you can't decide* is the real one — so just pick Docker and move.

## ✓ What you just learned

- **Docker** = one app, lightest, your default.
- **LXC** = a small whole Linux system to tinker in.
- **VM** = a full separate computer / non-Linux OS, heaviest.
- When unsure, **pick Docker** — the choice is cheap to change.
