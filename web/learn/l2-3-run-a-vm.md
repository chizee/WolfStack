# Run a full virtual machine

So far you've run **containers** — lightweight, fast, sharing the server's kernel. They're the right answer most of the time. But sometimes you need a *whole separate computer*: a different operating system, a Windows box, a firewall appliance, or something that simply demands its own kernel. That's a **virtual machine (VM)**.

## When a container isn't enough

Reach for a VM when you need:

- a **different OS** (Windows, BSD, a specific Linux you can't get as a container),
- **kernel-level** software (some VPNs, firewalls, or drivers),
- **strong isolation** — a VM is a sealed box, not a shared kernel.

If none of those apply, a container is lighter and you already know how to make one. **Don't reach for a VM out of habit.**

## Open the VMs screen

1. In the sidebar, click your **server**.
2. Open its **VMs** tab.

This lists the virtual machines on that server, with the controls to create and manage them. WolfStack drives whatever virtualization your server actually has (Proxmox VE, or native KVM/QEMU) behind the same screen — so it looks the same whether you're on a Proxmox host or a plain Linux box.

## What creating a VM involves

A VM needs a few more decisions than a container, because you're building a whole machine:

- **Resources** — how much CPU, memory, and disk to give it. Start modest; you can grow it later.
- **An OS to install** — usually an ISO image (the installer disc) you point it at.
- **A network** — which bridge it sits on (and, if you've done the last lesson, it can ride your WolfNet).

Create it, then open its **console** to click through the OS installer just like you would on a real machine.

> **The honest trade-off:** VMs are heavier than containers — more RAM, more disk, slower to start. That weight buys you a real, isolated machine. Use a container until something genuinely needs a VM, then don't feel bad about spending the resources.

## ✓ What you just learned

- A **VM** is a full virtual computer with its own kernel — heavier than a container, but fully isolated and able to run any OS.
- **Server → VMs** is where you create and manage them.
- Choose a VM for a **different OS, kernel-level software, or strong isolation** — otherwise a container is the better default.
- You install the OS through the VM's **console**, the same as a physical machine.

## Try it (if you have the room)

Spin up a small Linux VM with modest resources and click through its installer once. Doing it once removes all the mystery — and you'll know exactly when to choose a VM over a container in future.
