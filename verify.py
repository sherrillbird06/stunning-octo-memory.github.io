#!/usr/bin/env python3
"""
verify.py - collect control evidence from a Linux host and produce the same
artifacts CONTROL QUEST exports: an evidence pack, a risk register, and a POA&M.

The game teaches the model. This runs it against a real machine.

Every check is read-only. Nothing here changes system state.

Usage:
    python3 verify.py                      # assess localhost, write ./assessment
    python3 verify.py --out /tmp/audit     # choose the output directory
    python3 verify.py --system "Lab VM 1"  # label the scope
    python3 verify.py --list               # show the control catalogue and exit

CAVEAT ON SAFEGUARD NUMBERING
    CIS Controls v8 safeguard numbers and NIST CSF 2.0 function names below are
    the author's mapping. Verify each one against the published CIS Controls v8
    document and NIST CSF 2.0 core before putting this in front of an assessor.
    A wrong control ID is worse than no control ID.
"""

import argparse
import csv
import datetime as dt
import getpass
import json
import os
import platform
import shutil
import socket
import subprocess
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Result vocabulary. Deliberately matches how an assessor scores a safeguard.
# ─────────────────────────────────────────────────────────────────────────────
MET = "MET"
PARTIAL = "PARTIALLY MET"
NOT_MET = "NOT MET"
UNKNOWN = "NOT DETERMINED"

STATUS_RISK = {MET: 1, PARTIAL: 3, NOT_MET: 5, UNKNOWN: 4}


def run(cmd, timeout=20):
    """Run a shell command read-only. Returns (rc, combined output)."""
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "command timed out"
    except Exception as exc:  # noqa: BLE001
        return 1, f"command failed: {exc}"


def have(binary):
    return shutil.which(binary) is not None


def read(path, limit=8000):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except PermissionError:
        return None
    except OSError:
        return None


class Finding:
    """One assessed safeguard. This is the unit that becomes a register row."""

    def __init__(self, control, status, detail, evidence, command=""):
        self.control = control
        self.status = status
        self.detail = detail
        self.evidence = evidence
        self.command = command

    @property
    def likelihood(self):
        return STATUS_RISK[self.status]

    @property
    def impact(self):
        return self.control["impact"]

    @property
    def inherent(self):
        return self.likelihood * self.impact

    @property
    def residual(self):
        # Evidence reduces residual risk only where the safeguard is actually
        # met. A screenshot of a broken control does not reduce risk.
        if self.status == MET:
            return max(1, round(self.inherent * 0.25))
        if self.status == PARTIAL:
            return max(1, round(self.inherent * 0.65))
        return self.inherent

    @property
    def treatment(self):
        return "ACCEPTED" if self.status == MET else "MITIGATE"


def rating(score):
    if score >= 15:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MODERATE"
    return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Checks. Each returns a Finding. Keep them small and quotable.
# ─────────────────────────────────────────────────────────────────────────────

def check_asset_inventory(c):
    cmd = "hostname; uname -a; ip -brief address 2>/dev/null || ifconfig"
    _, out = run(cmd)
    facts = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "kernel": platform.release(),
        "arch": platform.machine(),
    }
    body = json.dumps(facts, indent=2) + "\n\n" + out
    return Finding(c, MET, "Asset detail captured for one host.", body, cmd)


def check_software_inventory(c):
    if have("dpkg-query"):
        cmd = "dpkg-query -W -f='${Package} ${Version}\\n'"
    elif have("rpm"):
        cmd = "rpm -qa"
    else:
        return Finding(c, UNKNOWN, "No supported package manager found.", "", "")
    _, out = run(cmd, timeout=60)
    n = len([ln for ln in out.splitlines() if ln.strip()])
    status = MET if n else UNKNOWN
    return Finding(c, status, f"{n} packages enumerated.", out[:6000], cmd)


def check_account_inventory(c):
    cmd = "getent passwd"
    _, out = run(cmd)
    humans = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        uid, shell = int(parts[2]) if parts[2].isdigit() else -1, parts[6]
        if uid >= 1000 and not shell.endswith(("nologin", "false")):
            humans.append(parts[0])
    detail = f"{len(humans)} interactive account(s): {', '.join(humans) or 'none'}"
    return Finding(c, MET if out else UNKNOWN, detail, out, cmd)


def check_dormant_accounts(c):
    if not have("lastlog"):
        return Finding(c, UNKNOWN, "lastlog not available on this host.", "", "")
    cmd = "lastlog -b 45"
    _, out = run(cmd)
    rows = [ln for ln in out.splitlines()[1:] if ln.strip()]
    stale = [r.split()[0] for r in rows if "Never logged in" not in r]
    if not rows:
        return Finding(c, MET, "No accounts dormant beyond 45 days.", out, cmd)
    status = NOT_MET if stale else PARTIAL
    detail = (f"{len(stale)} account(s) dormant >45 days: {', '.join(stale[:8])}"
              if stale else "Only never-logged-in system accounts returned.")
    return Finding(c, status, detail, out, cmd)


def check_password_policy(c):
    parts, cmd = [], "grep -E 'PASS_(MIN_LEN|MAX_DAYS)' /etc/login.defs; cat /etc/security/pwquality.conf 2>/dev/null"
    login_defs = read("/etc/login.defs") or ""
    pwq = read("/etc/security/pwquality.conf") or ""
    minlen = None
    for line in (login_defs + "\n" + pwq).splitlines():
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        if s.upper().startswith("PASS_MIN_LEN"):
            parts.append(s)
            try:
                minlen = int(s.split()[-1])
            except ValueError:
                pass
        if s.lower().startswith("minlen"):
            parts.append(s)
            try:
                minlen = int(s.split("=")[-1].strip())
            except ValueError:
                pass
        if s.upper().startswith("PASS_MAX_DAYS"):
            parts.append(s)
    body = "\n".join(parts) or "(no explicit length or age policy found)"
    if minlen is None:
        return Finding(c, NOT_MET, "No minimum password length enforced.", body, cmd)
    if minlen >= 14:
        return Finding(c, MET, f"Minimum length {minlen}.", body, cmd)
    return Finding(c, PARTIAL, f"Minimum length {minlen}; below a 14-char target.",
                   body, cmd)


def check_remote_access_auth(c):
    conf = read("/etc/ssh/sshd_config")
    cmd = "sshd -T 2>/dev/null | grep -Ei 'passwordauth|permitroot|pubkeyauth' || grep -Ei '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication)' /etc/ssh/sshd_config"
    _, out = run(cmd)
    body = out or (conf or "(sshd_config unreadable)")
    if conf is None and not out:
        return Finding(c, UNKNOWN, "SSH configuration not readable.", body, cmd)
    low = body.lower()
    mfa = "pam_google_authenticator" in (read("/etc/pam.d/sshd") or "").lower()
    pw_off = "passwordauthentication no" in low
    if mfa:
        return Finding(c, MET, "A second factor is configured for SSH.", body, cmd)
    if pw_off:
        return Finding(c, PARTIAL,
                       "Keys only, no second factor. Strong, but not MFA.", body, cmd)
    return Finding(c, NOT_MET, "Password authentication permitted, no second factor.",
                   body, cmd)


def check_listening_services(c):
    cmd = "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"
    _, out = run(cmd)
    if not out:
        return Finding(c, UNKNOWN, "Could not enumerate listening sockets.", "", cmd)
    listeners = [ln for ln in out.splitlines()[1:] if ln.strip()]
    external = [ln for ln in listeners
                if "0.0.0.0:" in ln or "[::]:" in ln or "*:" in ln]
    if not external:
        return Finding(c, MET, "No services listening on all interfaces.", out, cmd)
    status = PARTIAL if len(external) <= 2 else NOT_MET
    return Finding(c, status,
                   f"{len(external)} service(s) listening on all interfaces.",
                   out, cmd)


def check_audit_logging(c):
    cmd = ("systemctl is-active auditd rsyslog systemd-journald 2>/dev/null; "
           "ls -la /var/log/auth.log /var/log/secure /var/log/audit/audit.log 2>/dev/null")
    _, out = run(cmd)
    active = "active" in out
    have_files = any(k in out for k in ("auth.log", "secure", "audit.log"))
    body = out or "(no logging daemons or log files found)"
    if active and have_files:
        return Finding(c, MET, "Logging daemon active and log files present.", body, cmd)
    if active or have_files:
        return Finding(c, PARTIAL,
                       "Logging partially configured; retention not evidenced.",
                       body, cmd)
    return Finding(c, NOT_MET, "No audit logging evidence found.", body, cmd)


def check_patch_status(c):
    if have("apt-get"):
        cmd = "apt-get -s upgrade 2>/dev/null | grep -c '^Inst' ; ls -l --time-style=+%Y-%m-%d /var/lib/apt/periodic/update-success-stamp 2>/dev/null"
    elif have("dnf"):
        cmd = "dnf -q check-update 2>/dev/null | grep -c . ; true"
    else:
        return Finding(c, UNKNOWN, "No supported package manager.", "", "")
    _, out = run(cmd, timeout=90)
    first = out.splitlines()[0] if out.splitlines() else "0"
    try:
        pending = int(first.strip())
    except ValueError:
        pending = -1
    if pending == 0:
        return Finding(c, MET, "No pending package updates.", out, cmd)
    if pending < 0:
        return Finding(c, UNKNOWN, "Could not determine pending updates.", out, cmd)
    status = PARTIAL if pending <= 10 else NOT_MET
    return Finding(c, status, f"{pending} package update(s) pending.", out, cmd)


def check_encryption_at_rest(c):
    cmd = "lsblk -o NAME,FSTYPE,TYPE,MOUNTPOINT 2>/dev/null; ls /dev/mapper 2>/dev/null"
    _, out = run(cmd)
    if not out:
        return Finding(c, UNKNOWN, "Could not enumerate block devices.", "", cmd)
    encrypted = "crypto_LUKS" in out or "crypt" in out
    if encrypted:
        return Finding(c, MET, "Encrypted volume detected.", out, cmd)
    return Finding(c, NOT_MET, "No encrypted volumes detected.", out, cmd)


def check_backup_evidence(c):
    cmd = ("systemctl list-timers --all 2>/dev/null | grep -Ei 'backup|snapshot|restic|borg'; "
           "crontab -l 2>/dev/null | grep -Ei 'backup|restic|borg|rsync'")
    _, out = run(cmd)
    if out.strip():
        return Finding(c, PARTIAL,
                       "Backup job found. No restore test evidenced.", out, cmd)
    return Finding(c, NOT_MET,
                   "No scheduled backup job found on this host.",
                   out or "(no matching timers or cron entries)", cmd)


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue. This mapping table is the actual GRC artifact.
# ─────────────────────────────────────────────────────────────────────────────
CATALOGUE = [
    {"id": "1.1", "title": "Establish and maintain detailed enterprise asset inventory",
     "csf": "IDENTIFY", "impact": 3, "creature": "INVENTORY", "fn": check_asset_inventory,
     "evidence": "Host inventory record with hostname, OS, kernel and addresses.",
     "fix": "Maintain an asset inventory reviewed at least twice a year, with an owner per asset."},
    {"id": "2.1", "title": "Establish and maintain a software inventory",
     "csf": "IDENTIFY", "impact": 3, "creature": "INVENTORY", "fn": check_software_inventory,
     "evidence": "Full installed-package listing with versions.",
     "fix": "Enumerate installed software on a schedule and reconcile against an approved-software list."},
    {"id": "5.1", "title": "Establish and maintain an inventory of accounts",
     "csf": "PROTECT", "impact": 4, "creature": "MULTIFACTOR", "fn": check_account_inventory,
     "evidence": "Account listing with UID and shell, interactive accounts identified.",
     "fix": "Reconcile the account list against HR records quarterly and record the reviewer."},
    {"id": "5.2", "title": "Use unique passwords",
     "csf": "PROTECT", "impact": 4, "creature": "MULTIFACTOR", "fn": check_password_policy,
     "evidence": "Password length and age policy as configured on the host.",
     "fix": "Enforce a 14-character minimum and deploy a password manager so uniqueness is achievable."},
    {"id": "5.3", "title": "Disable dormant accounts",
     "csf": "PROTECT", "impact": 5, "creature": "MULTIFACTOR", "fn": check_dormant_accounts,
     "evidence": "Last-login report showing accounts dormant beyond 45 days.",
     "fix": "Disable accounts after 45 days of inactivity; automate against the HR leaver feed."},
    {"id": "6.4", "title": "Require MFA for remote network access",
     "csf": "PROTECT", "impact": 5, "creature": "MULTIFACTOR", "fn": check_remote_access_auth,
     "evidence": "Effective SSH authentication configuration and PAM stack.",
     "fix": "Add a second factor to remote access and disable password authentication."},
    {"id": "4.8", "title": "Uninstall or disable unnecessary services",
     "csf": "PROTECT", "impact": 5, "creature": "PATCHLING", "fn": check_listening_services,
     "evidence": "Listening socket table with owning process.",
     "fix": "Disable services that have no business justification; review the remainder quarterly."},
    {"id": "7.3", "title": "Perform automated operating system patch management",
     "csf": "PROTECT", "impact": 4, "creature": "PATCHLING", "fn": check_patch_status,
     "evidence": "Pending update count and last successful update timestamp.",
     "fix": "Enable unattended security upgrades and report monthly on patch latency."},
    {"id": "8.2", "title": "Collect audit logs",
     "csf": "DETECT", "impact": 5, "creature": "LOGKEEPER", "fn": check_audit_logging,
     "evidence": "Logging daemon state and log file listing with sizes and dates.",
     "fix": "Enable audit logging on all assets, forward to a central store, retain 90 days."},
    {"id": "3.11", "title": "Encrypt sensitive data at rest",
     "csf": "PROTECT", "impact": 5, "creature": "ENCRYPTOR", "fn": check_encryption_at_rest,
     "evidence": "Block device table showing filesystem types and mapper devices.",
     "fix": "Encrypt volumes holding sensitive data and document where the keys are held."},
    {"id": "11.2", "title": "Perform automated backups",
     "csf": "RECOVER", "impact": 5, "creature": "BACKUPWYRM", "fn": check_backup_evidence,
     "evidence": "Scheduled backup timers or cron entries, plus restore-test records.",
     "fix": "Schedule automated backups and perform a documented restore test twice a year."},
]


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def write_evidence(findings, outdir, system, stamp):
    evdir = os.path.join(outdir, "evidence")
    os.makedirs(evdir, exist_ok=True)
    operator = getpass.getuser()
    for f in findings:
        safe = f.control["id"].replace(".", "_")
        path = os.path.join(evdir, f"CIS-{safe}.txt")
        with open(path, "w") as fh:
            fh.write("EVIDENCE ARTIFACT\n")
            fh.write("=" * 68 + "\n")
            fh.write(f"Safeguard      : CIS v8 {f.control['id']} - {f.control['title']}\n")
            fh.write(f"CSF function   : {f.control['csf']}\n")
            fh.write(f"System         : {system}\n")
            fh.write(f"Host           : {socket.gethostname()}\n")
            fh.write(f"Collected      : {stamp} (local)\n")
            fh.write(f"Collected by   : {operator}\n")
            fh.write(f"Method         : automated read-only collection (verify.py)\n")
            fh.write(f"Command        : {f.command or 'n/a'}\n")
            fh.write(f"Assessed status: {f.status}\n")
            fh.write(f"Assessor note  : {f.detail}\n")
            fh.write("=" * 68 + "\n\n")
            fh.write(f.evidence or "(no output captured)\n")
    return evdir


def write_register(findings, outdir, stamp):
    path = os.path.join(outdir, "risk-register.csv")
    due = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Risk ID", "Safeguard", "Title", "NIST CSF 2.0 Function",
                    "Assessed Status", "Likelihood (1-5)", "Impact (1-5)",
                    "Inherent Score", "Inherent Rating", "Residual Score",
                    "Residual Rating", "Treatment", "Owner", "Date Opened",
                    "Due Date", "Evidence Artifact", "Assessor Note"])
        for i, f in enumerate(findings, 1):
            c = f.control
            w.writerow([f"R-{i:03d}", f"CIS {c['id']}", c["title"], c["csf"],
                        f.status, f.likelihood, f.impact,
                        f.inherent, rating(f.inherent),
                        f.residual, rating(f.residual),
                        f.treatment, "IT Operations",
                        dt.date.today().isoformat(), due,
                        f"evidence/CIS-{c['id'].replace('.', '_')}.txt",
                        f.detail])
    return path


def write_poam(findings, outdir, system, stamp):
    path = os.path.join(outdir, "poam.md")
    due = (dt.date.today() + dt.timedelta(days=30)).isoformat()
    open_items = [f for f in findings if f.status != MET]
    crit = [f for f in findings if rating(f.residual) == "CRITICAL"]
    high = [f for f in findings if rating(f.residual) == "HIGH"]
    with open(path, "w") as fh:
        fh.write("# Plan of Action and Milestones (POA&M)\n\n")
        fh.write(f"**System:** {system}  \n")
        fh.write(f"**Host:** {socket.gethostname()}  \n")
        fh.write("**Framework:** CIS Controls v8 mapped to NIST CSF 2.0  \n")
        fh.write(f"**Assessment date:** {stamp}  \n")
        fh.write(f"**Assessor:** {getpass.getuser()} (self-assessment)  \n")
        fh.write("**Method:** automated read-only collection, `verify.py`\n\n")
        fh.write("> Safeguard numbering is the author's mapping and must be verified\n")
        fh.write("> against the published CIS Controls v8 document before external use.\n\n")

        fh.write("## Summary\n\n")
        fh.write(f"- Safeguards assessed: **{len(findings)}**\n")
        fh.write(f"- Met: **{sum(1 for f in findings if f.status == MET)}** | "
                 f"Partial: **{sum(1 for f in findings if f.status == PARTIAL)}** | "
                 f"Not met: **{sum(1 for f in findings if f.status == NOT_MET)}** | "
                 f"Not determined: **{sum(1 for f in findings if f.status == UNKNOWN)}**\n")
        fh.write(f"- Residual CRITICAL: **{len(crit)}** | Residual HIGH: **{len(high)}**\n")
        fh.write(f"- Open items requiring remediation: **{len(open_items)}**\n\n")

        fh.write("## Assessment results\n\n")
        fh.write("| ID | Safeguard | CSF | Status | Inherent | Residual | Due |\n")
        fh.write("|---|---|---|---|---|---|---|\n")
        for i, f in enumerate(findings, 1):
            c = f.control
            fh.write(f"| R-{i:03d} | CIS {c['id']} | {c['csf']} | {f.status} | "
                     f"{f.inherent} {rating(f.inherent)} | "
                     f"{f.residual} {rating(f.residual)} | "
                     f"{due if f.status != MET else 'n/a'} |\n")
        fh.write("\n")

        fh.write("## Open items\n\n")
        if not open_items:
            fh.write("No open items. Every assessed safeguard was met.\n\n")
        for i, f in enumerate(findings, 1):
            if f.status == MET:
                continue
            c = f.control
            fh.write(f"### R-{i:03d} - CIS {c['id']} {c['title']}\n\n")
            fh.write("| Field | Value |\n|---|---|\n")
            fh.write(f"| NIST CSF 2.0 function | {c['csf']} |\n")
            fh.write(f"| Assessed status | {f.status} |\n")
            fh.write(f"| Likelihood / Impact | {f.likelihood} / {f.impact} |\n")
            fh.write(f"| Inherent risk | {f.inherent} ({rating(f.inherent)}) |\n")
            fh.write(f"| Residual risk | {f.residual} ({rating(f.residual)}) |\n")
            fh.write(f"| Treatment | {f.treatment} |\n")
            fh.write(f"| Owner | IT Operations |\n")
            fh.write(f"| Opened | {dt.date.today().isoformat()} |\n")
            fh.write(f"| Due | {due} |\n\n")
            fh.write(f"**What was observed.** {f.detail}\n\n")
            fh.write(f"**Remediation plan.** {c['fix']}\n\n")
            fh.write(f"**Evidence required.** {c['evidence']}\n\n")
            fh.write(f"**Evidence collected.** `evidence/CIS-{c['id'].replace('.', '_')}.txt`\n\n")
    return path


def write_json(findings, outdir, system, stamp):
    path = os.path.join(outdir, "assessment.json")
    payload = {
        "system": system,
        "host": socket.gethostname(),
        "assessed_at": stamp,
        "assessor": getpass.getuser(),
        "framework": "CIS Controls v8 / NIST CSF 2.0",
        "findings": [{
            "risk_id": f"R-{i:03d}",
            "safeguard": f.control["id"],
            "title": f.control["title"],
            "csf_function": f.control["csf"],
            "status": f.status,
            "likelihood": f.likelihood,
            "impact": f.impact,
            "inherent": f.inherent,
            "inherent_rating": rating(f.inherent),
            "residual": f.residual,
            "residual_rating": rating(f.residual),
            "treatment": f.treatment,
            "note": f.detail,
            "command": f.command,
            "game_creature": f.control["creature"],
        } for i, f in enumerate(findings, 1)],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return path


# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Collect control evidence and build a POA&M.")
    ap.add_argument("--out", default="./assessment", help="output directory")
    ap.add_argument("--system", default="Unnamed system", help="scope label for the report")
    ap.add_argument("--list", action="store_true", help="print the control catalogue and exit")
    args = ap.parse_args()

    if args.list:
        print(f"{'CIS':<6} {'CSF':<10} {'CREATURE':<12} TITLE")
        for c in CATALOGUE:
            print(f"{c['id']:<6} {c['csf']:<10} {c['creature']:<12} {c['title']}")
        return 0

    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs(args.out, exist_ok=True)

    print(f"CONTROL QUEST evidence collector")
    print(f"System : {args.system}")
    print(f"Host   : {socket.gethostname()}")
    print(f"Time   : {stamp}")
    if os.geteuid() != 0:
        print("Note   : not running as root. Some checks will report NOT DETERMINED.")
    print("-" * 72)

    findings = []
    for c in CATALOGUE:
        try:
            f = c["fn"](c)
        except Exception as exc:  # noqa: BLE001
            f = Finding(c, UNKNOWN, f"Check raised an error: {exc}", "", "")
        findings.append(f)
        print(f"CIS {c['id']:<5} {f.status:<16} {f.detail}")

    print("-" * 72)
    evdir = write_evidence(findings, args.out, args.system, stamp)
    reg = write_register(findings, args.out, stamp)
    poam = write_poam(findings, args.out, args.system, stamp)
    js = write_json(findings, args.out, args.system, stamp)

    crit = sum(1 for f in findings if rating(f.residual) == "CRITICAL")
    print(f"Assessed {len(findings)} safeguards. {crit} at CRITICAL residual risk.")
    print(f"  {reg}")
    print(f"  {poam}")
    print(f"  {js}")
    print(f"  {evdir}/  ({len(findings)} artifacts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
