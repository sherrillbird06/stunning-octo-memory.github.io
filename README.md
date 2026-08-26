# HELP DESK QUEST

**[Play it in your browser](https://sherrillbird06.github.io/stunning-octo-memory.github.io/)** — no install, no dependencies, works on mobile.

An interactive IT support portfolio by **Jaylen Sherrill** — Nashville, TN.

[LinkedIn](https://www.linkedin.com/in/jaylen-sherrill-b91636327/) · [jaylenbaylen@icloud.com](mailto:jaylenbaylen@icloud.com) · 615-910-9432

---

Five floors. Twenty-five real tickets. Every one of them is a thing that actually lands in a Tier 1 queue, and every one is explained in the TICKETDEX after you close it.

You start on the floor with fifty tickets and one skill. Somebody says "they gave the queue to the student?" loud enough for you to hear it. Six shifts later they've stopped saying it.

## Controls

```
Arrows / WASD   move
Z               confirm, advance text, choose a move
X               back
Enter           menu (ticketdex, skills, badges, metrics, journal, map, resume)
M               the building
R               resume and contact
F               fullscreen
C               toggle CRT scanlines
```

On phones a D-pad and A/B buttons appear automatically. Sound stays silent until your first keypress — browsers block audio before a gesture — then the SOUND button in the top right reports its real state.

## The mechanic is the method

Tickets are fought with the actual troubleshooting sequence, and the game only rewards you for doing it properly:

- **Ask** gathers detail. Every later move scales with how much you have.
- **Isolate** rules causes out one at a time. With no detail gathered it barely moves the ticket.
- **Fix** applied on fewer than two pieces of detail *makes things worse* — you take damage for guessing.
- **Verify** is mandatory on anything touching an account. Fix an account ticket without it and the fix does not count, no matter how correct it was.
- **Escalate** closes genuinely out-of-scope tickets outright. Used on something you could have solved, Tier 2 sends it back and the clock keeps running.
- **Document** writes it up: observed, tried, result, next.

Every ticket has an **SLA timer** in turns. The user follows up each turn, and running past the limit breaches the ticket and reassigns it. Your **SHIFT METRICS** screen tracks tickets closed, SLA met, first-contact resolution and documentation rate across the whole run.

Each skill has a type — PEOPLE, HARDWARE, SOFTWARE, NETWORK, SECURITY — and tickets take double from the right one.

## The five floors

| Floor | Shift | What it teaches |
|---|---|---|
| S1 | **TIER ONE** | Peripherals, display faults, account lockouts, "my computer is slow" |
| 02 | **THE INBOX** | Lookalike domains, business email compromise, MFA fatigue, vishing |
| 03 | **THE CLOSET** | Docking stations, memory faults, driver rollback, PXE and imaging |
| 04 | **THE WIRE** | APIPA and DHCP, DNS resolution, VPN routing, VLAN misconfiguration |
| 06 | **THE BRIDGE** | Priority as impact × urgency, change control, SLA communication, handoff notes |

Each floor ends with a cluster incident — many users, one cause — which is the lesson in itself.

## The TICKETDEX

The reason this exists. Every closed ticket unlocks a full write-up: what the symptom actually means, the order to check things in, and the one line worth remembering. A few of them:

> **APIPA** — A 169.254.x.x address means the machine asked for DHCP and nothing answered. That is not an internet problem, it is a lease problem. One machine points at the port; the whole floor points at the scope.

> **GIFTCARD** — Business email compromise runs on three signals together: unusual request, artificial urgency, and a reason you cannot verify through the normal channel. Any one is odd. All three is an attack. *Reply-to is the attacker's field.*

> **WRONGVLAN** — A port on the wrong VLAN behaves like a broken cable that tests fine. You can prove it, but changing switch config is not a Tier 1 action. Document the port, the panel location and what you ruled out, then escalate. That handoff note is the whole job here.

## Built with

One HTML file. No frameworks, no build step, no dependencies, no network calls.

- **Rendering** — a 160×144 palette-indexed framebuffer, the real Game Boy resolution, scaled to fill the window. All art is authored in four indices and drawn through one of 33 palette banks, which is how the Game Boy Color did it. A new ticket type is one `bank()` line, not a repaint.
- **Sprites** — 21 hand-drawn 16×16 creatures plus tiles and characters, written as character grids in source.
- **Type** — a 5×7 bitmap font built glyph by glyph rather than loaded, so it renders identically everywhere.
- **Audio** — synthesised at runtime with the Web Audio API. Two pulse voices, a triangle bass and a noise channel, roughly the Game Boy's voice allocation. Six looping tracks and sixteen effects live as arrays of MIDI numbers; there are no audio files to host.
- **Testing** — `src/validate.js` checks every sprite row is exactly 16px and every NPC stands on a walkable tile; `src/overflow.js` proves no string in the game can overflow its box; `src/play.js` runs a headless five-floor playthrough and asserts the progression gates.

`src/` holds the game split into the eight parts it was built from. `index.html` is those parts concatenated.

## About

I'm working toward an A.A.S. in Information Technology at Nashville State Community College, with CompTIA Network+ booked for 2026. Before this I troubleshot self-checkout and POS systems at Walmart, ran handheld scanners and escalated system faults at Amazon, and worked ground operations for United Ground Express — three jobs that were help desk work without the title.

The full resume, with clickable contact links, is inside the game: press **R**.
