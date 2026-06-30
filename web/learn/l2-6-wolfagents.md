# Your AI co-pilot: WolfAgents

You've met the AI assistant in the corner — the one you can ask "why is this container unhealthy?". **WolfAgents** is the next step up: **named** AI assistants with **persistent memory** that you set up for specific jobs and that remember your setup between conversations.

## First, a quick word on setup

WolfAgents (and the assistant generally) needs an AI provider configured. You can use a hosted model (Claude, Gemini, OpenAI) **or** a fully local one — LM Studio or Ollama on your own hardware, so nothing leaves your network. You set this once in **Settings → AI Agent**.

## Open WolfAgents

1. Click the **Apps & Tools** drawer (the grid icon).
2. Open **WolfAgents**.

Here you create agents and give each one a name and a purpose. Unlike a one-off chat, an agent **keeps its memory** — so it builds up context about your servers, your apps, and the way *you* like things done.

## What an agent is good for

Think of an agent as a junior operator who's read all your docs:

- **"Watch and explain"** — point it at a server and ask it to summarise health, flag oddities, and explain what an alert means in plain English.
- **"How do I…"** — ask it the WolfStack-specific questions you'd otherwise dig through menus for. It knows the platform.
- **"Draft the fix"** — have it propose the command or steps to fix something, so *you* stay in control and just approve.

The agent **proposes**; you **decide**. It won't run anything destructive on its own — you're always the one who presses the button.

> **Trust, but verify — every time.** An agent is a brilliant assistant and an occasionally confident liar. Let it explain, suggest, and draft. Read what it proposes before you run it, exactly as you'd check a junior's work. The moment you stop reading is the moment it does something you didn't want.

## ✓ What you just learned

- **Apps & Tools → WolfAgents** creates **named AI assistants with memory** that know your setup.
- They need an AI provider set in **Settings → AI Agent** — hosted **or** fully local (LM Studio / Ollama) so data stays on your network.
- Use them to **explain, answer, and draft fixes** — but you always review and approve.

## Try it

Create one agent, give it a clear name like "Ops helper," and ask it to explain the most recent item on your **Issues** page. A useful answer about *your* actual setup is the moment WolfAgents clicks.
