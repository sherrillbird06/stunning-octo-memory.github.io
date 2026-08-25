# Plan of Action and Milestones (POA&M)

**System:** Sublevel 2 Lab  
**Host:** vm  
**Framework:** CIS Controls v8 mapped to NIST CSF 2.0  
**Assessment date:** 2026-08-25 21:24:22  
**Assessor:** root (self-assessment)  
**Method:** automated read-only collection, `verify.py`

> Safeguard numbering is the author's mapping and must be verified
> against the published CIS Controls v8 document before external use.

## Summary

- Safeguards assessed: **11**
- Met: **4** | Partial: **1** | Not met: **5** | Not determined: **1**
- Residual CRITICAL: **6** | Residual HIGH: **1**
- Open items requiring remediation: **7**

## Assessment results

| ID | Safeguard | CSF | Status | Inherent | Residual | Due |
|---|---|---|---|---|---|---|
| R-001 | CIS 1.1 | IDENTIFY | MET | 3 LOW | 1 LOW | n/a |
| R-002 | CIS 2.1 | IDENTIFY | MET | 3 LOW | 1 LOW | n/a |
| R-003 | CIS 5.1 | PROTECT | MET | 4 LOW | 1 LOW | n/a |
| R-004 | CIS 5.2 | PROTECT | NOT MET | 20 CRITICAL | 20 CRITICAL | 2026-09-24 |
| R-005 | CIS 5.3 | PROTECT | PARTIALLY MET | 15 CRITICAL | 10 HIGH | 2026-09-24 |
| R-006 | CIS 6.4 | PROTECT | NOT MET | 25 CRITICAL | 25 CRITICAL | 2026-09-24 |
| R-007 | CIS 4.8 | PROTECT | NOT DETERMINED | 20 CRITICAL | 20 CRITICAL | 2026-09-24 |
| R-008 | CIS 7.3 | PROTECT | MET | 4 LOW | 1 LOW | n/a |
| R-009 | CIS 8.2 | DETECT | NOT MET | 25 CRITICAL | 25 CRITICAL | 2026-09-24 |
| R-010 | CIS 3.11 | PROTECT | NOT MET | 25 CRITICAL | 25 CRITICAL | 2026-09-24 |
| R-011 | CIS 11.2 | RECOVER | NOT MET | 25 CRITICAL | 25 CRITICAL | 2026-09-24 |

## Open items

### R-004 - CIS 5.2 Use unique passwords

| Field | Value |
|---|---|
| NIST CSF 2.0 function | PROTECT |
| Assessed status | NOT MET |
| Likelihood / Impact | 5 / 4 |
| Inherent risk | 20 (CRITICAL) |
| Residual risk | 20 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** No minimum password length enforced.

**Remediation plan.** Enforce a 14-character minimum and deploy a password manager so uniqueness is achievable.

**Evidence required.** Password length and age policy as configured on the host.

**Evidence collected.** `evidence/CIS-5_2.txt`

### R-005 - CIS 5.3 Disable dormant accounts

| Field | Value |
|---|---|
| NIST CSF 2.0 function | PROTECT |
| Assessed status | PARTIALLY MET |
| Likelihood / Impact | 3 / 5 |
| Inherent risk | 15 (CRITICAL) |
| Residual risk | 10 (HIGH) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** Only never-logged-in system accounts returned.

**Remediation plan.** Disable accounts after 45 days of inactivity; automate against the HR leaver feed.

**Evidence required.** Last-login report showing accounts dormant beyond 45 days.

**Evidence collected.** `evidence/CIS-5_3.txt`

### R-006 - CIS 6.4 Require MFA for remote network access

| Field | Value |
|---|---|
| NIST CSF 2.0 function | PROTECT |
| Assessed status | NOT MET |
| Likelihood / Impact | 5 / 5 |
| Inherent risk | 25 (CRITICAL) |
| Residual risk | 25 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** Password authentication permitted, no second factor.

**Remediation plan.** Add a second factor to remote access and disable password authentication.

**Evidence required.** Effective SSH authentication configuration and PAM stack.

**Evidence collected.** `evidence/CIS-6_4.txt`

### R-007 - CIS 4.8 Uninstall or disable unnecessary services

| Field | Value |
|---|---|
| NIST CSF 2.0 function | PROTECT |
| Assessed status | NOT DETERMINED |
| Likelihood / Impact | 4 / 5 |
| Inherent risk | 20 (CRITICAL) |
| Residual risk | 20 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** Could not enumerate listening sockets.

**Remediation plan.** Disable services that have no business justification; review the remainder quarterly.

**Evidence required.** Listening socket table with owning process.

**Evidence collected.** `evidence/CIS-4_8.txt`

### R-009 - CIS 8.2 Collect audit logs

| Field | Value |
|---|---|
| NIST CSF 2.0 function | DETECT |
| Assessed status | NOT MET |
| Likelihood / Impact | 5 / 5 |
| Inherent risk | 25 (CRITICAL) |
| Residual risk | 25 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** No audit logging evidence found.

**Remediation plan.** Enable audit logging on all assets, forward to a central store, retain 90 days.

**Evidence required.** Logging daemon state and log file listing with sizes and dates.

**Evidence collected.** `evidence/CIS-8_2.txt`

### R-010 - CIS 3.11 Encrypt sensitive data at rest

| Field | Value |
|---|---|
| NIST CSF 2.0 function | PROTECT |
| Assessed status | NOT MET |
| Likelihood / Impact | 5 / 5 |
| Inherent risk | 25 (CRITICAL) |
| Residual risk | 25 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** No encrypted volumes detected.

**Remediation plan.** Encrypt volumes holding sensitive data and document where the keys are held.

**Evidence required.** Block device table showing filesystem types and mapper devices.

**Evidence collected.** `evidence/CIS-3_11.txt`

### R-011 - CIS 11.2 Perform automated backups

| Field | Value |
|---|---|
| NIST CSF 2.0 function | RECOVER |
| Assessed status | NOT MET |
| Likelihood / Impact | 5 / 5 |
| Inherent risk | 25 (CRITICAL) |
| Residual risk | 25 (CRITICAL) |
| Treatment | MITIGATE |
| Owner | IT Operations |
| Opened | 2026-08-25 |
| Due | 2026-09-24 |

**What was observed.** No scheduled backup job found on this host.

**Remediation plan.** Schedule automated backups and perform a documented restore test twice a year.

**Evidence required.** Scheduled backup timers or cron entries, plus restore-test records.

**Evidence collected.** `evidence/CIS-11_2.txt`

