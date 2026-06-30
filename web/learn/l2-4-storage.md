# Storage that outgrows one disk

Every setup starts with one disk, and one disk is fine — until it isn't. Maybe you're running low on space, maybe you want your backups to live somewhere *other* than the machine they're protecting, or maybe you've got a NAS full of media you want a container to read. This is where WolfStack's storage features earn their keep.

## Two screens, two jobs

There are two different things people mean by "storage," and WolfStack splits them cleanly:

- **Mounting remote storage onto a server** — attach an S3 bucket, an NFS export, or an SMB share so it appears as a folder your containers and apps can use. This lives **per server**.
- **Sharing your storage out to the LAN** — turn a server into an SMB/NFS gateway so *other* machines on your network can use it. This lives in the **Apps & Tools** drawer as **Shares**.

## Mount remote storage onto a server

1. In the sidebar, click your **server**.
2. Open its **Storage** tab.

From here you connect remote storage — **S3** (and S3-compatible like Backblaze B2 or Cloudflare R2), **NFS**, **SMB/CIFS**, **SSHFS**, or a **WolfDisk** volume. Once mounted, it's just a path on the server: backups can target it, containers can use it, and it survives reboots.

The classic first use: **send your backups off-box.** Remember the honest truth from Getting Started — a backup on the same disk that dies isn't a backup. Mount an NFS share or an S3 bucket here, then point your scheduled backups at it. *Now* you have a real safety net.

## Share storage to your LAN

In the **Apps & Tools** drawer, **Shares** turns a server into a universal SMB/NFS gateway — handy when you want your other computers (laptops, media players) to read and write the storage WolfStack manages.

> **Pick the boring option first:** for most people the single highest-value storage move is "mount one off-box target and send backups there." Do that one thing before you go building parity arrays. Off-site-ish backups beat clever storage every time.

## ✓ What you just learned

- **Server → Storage** mounts remote storage (S3, NFS, SMB, SSHFS, WolfDisk) onto a server as a usable folder.
- **Apps & Tools → Shares** does the reverse: shares your storage *out* to the LAN.
- The #1 reason to learn this: **get your backups off the box they protect.**

## Try it

Mount one remote target — even a cheap S3 bucket or a spare NFS share — and re-point your scheduled backup at it. Ten minutes of work for a genuinely better night's sleep.
