# CONTROL QUEST — Compliance Version

A GRC training RPG in the shape of a 1996 handheld, plus the evidence collector it teaches you to write.

**[Play it in your browser](https://sherrillbird06.github.io/stunning-octo-memory.github.io/)** — no install, no dependencies, works on mobile.

You start on Sublevel 2 with fifty open tickets and no privileges. You collect **CONTROLS**, battle **FINDINGS**, and the loot you carry away is **evidence**. Beat the act and the game hands you a real risk register and a real POA&M as downloadable files.

---

## What's in the box

| File | What it is |
|---|---|
| `index.html` | The game. One file, no build step, no dependencies. Also the GitHub Pages landing page. |
| `verify.py` | The evidence collector. Runs real read-only checks against a Linux host and produces the same artifacts the game exports. |
| `sample-assessment/` | Output from running `verify.py` against a live container, so you can see the artifacts before you run anything. |

---

## Playing

Play it at **[sherrillbird06.github.io/stunning-octo-memory.github.io/](https://sherrillbird06.github.io/stunning-octo-memory.github.io/)**, or open `index.html` from a local clone.

```
Arrows / WASD   move
Z               confirm, advance text, choose a move
X               back
Enter           menu (register, controls, evidence, export, status, save)
```

Talk to **DEV** on the desk floor to get your first CONTROL. Walk into the blinking tiles to find FINDINGS. **MARGIT** restores your party. The lift unlocks when the queue is dead.

### The one rule that makes it work

**You cannot win by lying.** Damage scales with evidence you actually hold:

- `Collect` pulls an artifact into the evidence bag. Low damage. It is the setup move.
- `Test` damage = base + 5 per evidence item. With zero evidence it barely scratches.
- `Attest` is strong at 3+ evidence and pathetic below that. Attesting on thin evidence is how real people get burned, so the game burns you for it.
- `Document` writes policy and blunts the finding's attack. It does not close the gap.
- `Remediate` hits hardest and costs budget you don't have much of.

Each CONTROL has a type (ACCESS, DETECT, HARDEN, RECOVER, GOVERN). Findings take double from the right type. Once you've collected any evidence, the enemy panel reveals the weakness — because assessment is how you learn which control applies.

Log a finding with zero evidence and it still goes in your register, but its **residual risk never drops below inherent**, and the exported POA&M flags it as unverified. That single behaviour is the whole lesson.

### Export

Menu → `EXPORT` writes two files:

- `risk-register.csv` — 17 columns: likelihood, impact, inherent and residual scores with ratings, treatment, owner, dates, evidence requirement and evidence count.
- `poam.md` — Plan of Action and Milestones with a summary, a register table, and one detailed block per open item.

These are the deliverables. The game is the tutorial.

---

## Running the collector

```bash
python3 verify.py --list                              # show the control catalogue
python3 verify.py --system "Lab VM 1" --out ./audit   # assess and write artifacts
```

Standard library only. Every check is read-only; nothing changes system state. Run it as root for full coverage — unprivileged runs report `NOT DETERMINED` rather than guessing, which is the correct assessor behaviour.

It assesses eleven safeguards: asset and software inventory, account inventory, password policy, dormant accounts, remote access authentication, listening services, patch status, audit logging, encryption at rest, and backups.

Output:

```
audit/
├── risk-register.csv        same shape as the game's export
├── poam.md                  summary, results table, open items with remediation plans
├── assessment.json          machine-readable, for a dashboard or a diff over time
└── evidence/
    ├── CIS-5_3.txt          one artifact per safeguard
    └── ...
```

Every evidence file carries a header an auditor will actually accept:

```
Safeguard      : CIS v8 5.3 - Disable dormant accounts
CSF function   : PROTECT
Host           : vm
Collected      : 2026-08-25 21:24:22 (local)
Collected by   : root
Method         : automated read-only collection (verify.py)
Command        : lastlog -b 45
Assessed status: PARTIALLY MET
Assessor note  : Only never-logged-in system accounts returned.
```

Timestamp, host, operator, method, exact command. A screenshot with none of that is a picture, not evidence.

---

## Building Acts 2 through 5

Act 1 is finished and playable. The rest is your project — and building it is the point, because the mapping layer is the GRC skill wearing a costume.

**Finish one act end to end before starting the next.** A complete Act 2 beats five acts of stubs. Scope creep is the specific way this project dies.

### Act 2 — THE DOMAIN
Stand up Windows Server with Active Directory on an eval licence. The quest chain is the onboarding/offboarding script: read a CSV of new hires, create accounts, assign groups by department, create home folders with correct ACLs, log everything. The boss is an acquisition dumping fifty malformed rows on you overnight. New findings: `PRIVCREEP` (weak GOVERN), `ORPHANGROUP`, `NOOFFBOARD`. Port `verify.py`'s catalogue pattern to PowerShell.

### Act 3 — THE CLOUD
Free-tier AWS or Azure. Terraform that stands up a VM, a network, and firewall rules, plus a teardown script. Side quest: the monitoring agent — disk, service state, uptime, alerting to Discord. The 3am outage boss is unwinnable if you skipped the side quest, so neglect in Act 2 has teeth in Act 3.

### Act 4 — THE FRAMEWORK
You get promoted out of the console and into the documents. Write the real policy set: access control, acceptable use, incident response, vendor management, data classification. Run a gap assessment against CIS IG1. New mechanic: the **crosswalk** works like a language skill — as you map SOC 2 Trust Services Criteria to ISO 27001 Annex A to NIST CSF, fluency lets one piece of evidence satisfy three NPC factions at once. That mechanic is worth building well; it's the thing companies pay real money for.

### Act 5 — THE AUDIT
The final boss is an external auditor who cannot be fought. She samples fifteen controls at random and asks for evidence. You win or lose entirely on preparation — no clutch play available. Stale evidence (the game already timestamps and ages artifacts at 90 days) fails the sample.

**Post-game:** vendor risk. NPCs hand you a completed SIG Lite. Some are lying. Your scoring rubric determines whether you catch it.

### Where to extend the code

- `CONTROLS` and `FINDINGS` in the game are plain objects — add entries and they work immediately.
- `MAPS` are arrays of strings, one character per tile. `TKEY` maps characters to tile art; `SOLID` decides what blocks movement.
- `MON` sprites are 16×16 arrays of `#`, `.`, `:`, ` `, `t` (transparent), drawn at 2× in battle. Keep every row exactly 16 characters — there's a validator in the build history that catches this, and it catches it a lot.
- `CATALOGUE` in `verify.py` is the mapping table. Adding a safeguard means adding one dict and one function that returns a `Finding`.

---

## Turning this into the thing that gets you hired

"I built a CTF-style GRC training platform" is a better interview opener than "I did a gap assessment." But the artifacts are what get read, so:

1. **Run `verify.py` against a real lab box**, not this container. Commit the output.
2. **Write the policy set by hand.** Five or six real policies. The automation can't do this for you and it's the skill most applicants can't demonstrate.
3. **Put the crosswalk in a spreadsheet** — CIS IG1 to NIST CSF 2.0 to SOC 2 TSC. One row per safeguard. This is the single most reusable artifact in the repo.
4. **Document a control that failed** and what you did about it. Assessors trust people who report bad news accurately far more than people whose every control is green.
5. **README with a diagram and what broke.** Half the job is explaining technical things to people who won't read. A good README proves you can.

Pair this with Security+, then eye CISA or CRISC once you have experience behind you.

---

## Caveats, stated plainly

**Verify the control IDs.** The CIS v8 safeguard numbers and NIST CSF 2.0 function names in both the game and `verify.py` are my mapping. They're close, but check every one against the published CIS Controls v8 document and the NIST CSF 2.0 core before this goes anywhere near an assessor or an interview. A wrong control ID is worse than no control ID, and being the person who checked is itself the skill.

**Risk scoring is a teaching model, not a methodology.** Likelihood × impact on a 5×5 grid with a fixed residual multiplier is the simplest defensible thing. Real programs argue about this for months. If you want the grown-up version, read NIST SP 800-30 and replace the scoring function — that's a good exercise in itself.

**The checks are shallow by design.** `verify.py` tells you a logging daemon is running. It does not tell you retention is 90 days, that logs ship anywhere, or that anyone reads them. Deepening those checks is Act 3 work.

**Original characters and world.** The monochrome palette, tile grid, and turn-based structure are a style homage; every creature, name, sprite, and line of dialogue here is original. Keep it that way if you publish it.

**Save data** uses the artifact storage API where available and falls back to session-only play. Nothing leaves your machine.

---

## Technical notes

The game is ~1,300 lines of vanilla JavaScript rendering to a 160×144 canvas — the actual Game Boy resolution — through a palette-indexed framebuffer, then integer-scaled up. The four colours are the real DMG palette (`#0f380f`, `#306230`, `#8bac0f`, `#9bbc0f`). The 5×7 bitmap font is hand-built glyph by glyph rather than loaded, so it renders identically everywhere and never falls back to a system face.

No build step, no dependencies, no network calls. Open the file.
