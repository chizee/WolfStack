# Make a Docker container

The App Store is great, but sometimes you want to run an image that isn't in it. Here's how to create a Docker container by hand. WolfStack walks you through it in **two steps**, so you're never staring at a wall of options.

## Get to the right screen

1. In the sidebar, click your **server**.
2. Click **Docker**.
3. Click the **+ Create Container** button (top-right of the Docker Containers card).

A window opens: **Create Docker Container — Step 1: Select Image**.

## Step 1 — pick an image

An "image" is the template your container is built from (like `nginx`, `postgres`, or `homeassistant/home-assistant`).

- Type a name into the **search box** (*Search for images…*) and click **Search**. Results appear in a list — click **Select →** next to the one you want.
- Or, if you already know the exact image, type it into the **custom image** box (e.g. `myregistry/myimage:latest`) and click **Use This →**.

The window moves to step 2.

## Step 2 — configure it

You'll see **Create Docker Container — Step 2: Configure**. The only fields you usually touch:

- **Container Name** — a name for it. A default is filled in.
- **Image Tag** — which version. Leave it as **latest** unless you need a specific one.
- **Port Mappings** — how the app is reached. Click **+ Add Port** to map a **host port** (the number you'll type in your browser) to the **container port** (the one the app listens on inside). Example: host `8080` → container `80`.
- **Environment Variables** — settings the app reads at startup, as `KEY=VALUE`. Some images need one (e.g. `MYSQL_ROOT_PASSWORD=secret`); many need none. If you don't know, leave it empty.
- **Memory Limit** and **CPU Cores** — caps so one container can't hog the machine. **Leave both on the default** unless you have a reason.

When you're happy, click **Pull & Create** at the bottom.

## Watch it

The **task log** at the bottom shows WolfStack downloading the image and starting the container. When it's done, your new container appears in the Docker list with a running status.

> **The #1 first-timer snag:** "port is already in use." It means another app already grabbed that host port. Just create again and pick a different host port (e.g. `8081` instead of `8080`).

## ✓ What you just learned

- **Server → Docker → + Create Container** opens a two-step wizard.
- **Step 1:** search and **Select →** an image (or type a custom one and **Use This →**).
- **Step 2:** set the **Container Name**, **Ports**, optional **Env vars**, then **Pull & Create**.
- Leave **Memory/CPU** at defaults unless you have a reason to change them.
