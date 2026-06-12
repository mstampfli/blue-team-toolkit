# Blue Team Toolkit (btd)

A menu-driven defensive-security toolkit for rapidly assessing, hardening, and
monitoring Windows and Linux hosts under time pressure. It wraps a curated set
of well-known DFIR, hardening, and recon tools behind a single workflow:
**install tools -> map the host -> get a prioritized punch list -> harden ->
triage and hunt**. Each platform has its own entry point but the two sides
mirror each other in structure and output format.

## Scope

This is **defensive (blue team) tooling intended for authorized use only** —
Collegiate Cyber Defense Competition (CCDC) style exercises, lab environments,
and systems you own or are explicitly cleared to defend. The menus and inline
comments reference competition workflow ("battle plan" sections, a "CyLG kill
chain") because that is the context it was built for. Some bundled tools (nmap,
NetExec, nuclei, LinPEAS/WinPEAS, SharpHound) are dual-use; run them only
against in-scope assets.

## What's included

Two entry points launch identical menu structures: `prep.ps1` (Windows console
menu) and `prep.sh` (Linux whiptail menu; needs `whiptail`, `jq`, `curl`). Both
create `output/` (reports, logs, `findings.jsonl`, `facts.json`) and
`tools/` (downloaded tools) next to the script. Per-platform logic lives in
`lib/windows/*.ps1` and `lib/linux/*.sh`:

- **installer** — reads `tools.json` and installs every Windows/Linux tool, or a
  custom selection. Supports `winget`, `apt`, `pipx`/`pip`, direct URL download,
  `git clone`, and GitHub-release asset matching.
- **map** — discovery pass that writes `facts.json`: OS identity, role detection
  (Windows: DC/IIS/Exchange/AD CS/SQL/RDP/WinRM/Hyper-V; Linux:
  docker/nginx/apache/samba/bind/postgres/mysql/redis/SSSD), security posture,
  listening ports with bind-interface exposure analysis, privileged services,
  firewall posture, and which bundled tools are present. Optional heavy passes
  (WinPEAS/autoruns/nmap, or lynis/linpeas/nmap).
- **recommend** — reads `facts.json` and prints a prioritized P0/P1/P2 hardening
  punch list with the matching hardening step, plus tools present vs. missing.
- **harden** — semi-automated checklist; **dry-run by default**, with per-step
  confirmation and a rollback hint for every change. Windows items include LSA
  RunAsPPL, disabling SMBv1, SMB signing, the SMBGhost workaround, Print Spooler,
  LLMNR/NetBIOS/WPAD, NTLMv2-only, PowerShell logging, audit policy, and a
  persistence baseline snapshot. Linux items include SSH lockdown, auditd with
  the Neo23x0 ruleset, fail2ban, UFW default-deny, sysctl hardening, the PwnKit
  pkexec workaround, and package/service baselines.
- **triage** — per-host raw-state collection to a timestamped report; dispatches
  installed scanners first (WinPEAS/autoruns/sigcheck, or
  lynis/linpeas/rkhunter/chkrootkit) then dumps processes, sockets, persistence,
  accounts, and other live state.
- **hunt** — backdoor/persistence hunt. Dispatches autoruns/chainsaw/hayabusa/
  hollows_hunter/loki where present, then runs high-specificity ("CLEAR") checks:
  recent accounts, services and tasks in writable paths, masquerading processes,
  Defender tamper/exclusions, suspicious listen ports, privileged-group changes,
  WMI/AppInit persistence, web-shell paths, and drift against the saved baseline.
- **recon** — network recon, air-gap aware. INTERNAL: nmap host discovery +
  service scan + NetExec SMB enum + nuclei against web hosts. EXTERNAL: Shodan
  InternetDB, crt.sh subdomain pull, DNS enum, and NAT-hairpin nmap. Auto-detects
  targets into an editable `recon-targets.txt`.
- **findings** — viewer for the persistent `findings.jsonl` accumulated across
  runs; summary, recent, by-type, and deduped CSV export.

`tools.json` is the shared tool manifest (~50 tools across EDR/DFIR, telemetry,
SIEM/network, recon, vuln scanning, privesc audit, AD, rootkit hunting, memory
forensics, network defense, honeypots, and detection configs).

## Usage

Windows (run PowerShell **as Administrator**):

```powershell
.\prep.ps1
```

Linux:

```bash
./prep.sh
```

Then follow the suggested order shown in the menu: **1 (install) -> 6 (map) ->
7 (recommend) -> 3 (harden) -> 2/4 (triage/hunt)**.

## Requirements

- **Windows:** Windows PowerShell 5.1+ (uses CIM, `Get-NetTCPConnection`, and
  Defender cmdlets). The hardening module **requires an elevated session** and
  refuses to run otherwise; map/triage/hunt are most complete when elevated.
  `winget`, `git`, and `pipx`/`pip` are optional and only used by the installer.
- **Linux:** bash with `whiptail`, `jq`, and `curl` (checked at startup);
  Debian/Ubuntu-family assumed (`apt`, `dpkg`, `debsums`). Hardening and parts of
  triage use `sudo`.
- Bundled third-party tools are downloaded into `tools/` on demand via the
  installer; nothing is committed to the repo.

## Status

Single-author project built for CCDC-style competition prep and lab use; the
Windows and Linux sides are at feature parity. No automated tests — review the
hardening dry-run output before applying changes to any host you care about.
