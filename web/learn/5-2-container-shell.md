# Open a shell inside a container

A terminal *on the server* is one thing. Often what you actually want is a command line **inside** a specific container — to look at its files, check a config, or debug why an app is misbehaving. WolfStack makes that one click too.

## Open a container's shell

1. In the sidebar, click the **server** the container is on.
2. Click **Docker** (or **LXC**).
3. Find your container in the list. On its row, look at the action buttons and click the **terminal icon**.

A small console window pops open (about 960×600) and drops you straight into a shell **inside that container**. You're now "inside the box," not on the host.

## What this is good for

- **Look around:** `ls`, `cat some-config-file` to see how the app is set up.
- **Check it's alive:** run the app's own status command.
- **Fix small things:** edit a file, install a missing tool (in an LXC box), restart a process.

When you're done, type `exit` (or just close the window) to leave.

> **On the host or in the container?** It's easy to forget which shell you're in. A quick way to tell: the **prompt** usually shows the container's name or a different hostname. When in doubt, `hostname` tells you exactly where you are.

## Docker vs LXC shells

- In an **LXC** container it feels like logging into a normal little Linux machine — your changes stick around.
- In a **Docker** container the shell is more minimal (some images are stripped down and don't even have common tools), and remember that **changes to a container's filesystem can be lost when it's recreated**. For anything you want to keep, use the app's proper config/volumes rather than editing files by hand in the shell.

## ✓ What you just learned

- Each container's row has a **terminal icon** that opens a shell **inside** it.
- Use it to inspect files, check status, and fix small things; type `exit` to leave.
- `hostname` tells you whether you're in the container or on the host.
- Hand-edits inside a **Docker** container can vanish on recreate — keep important changes in the app's real config/volumes.
