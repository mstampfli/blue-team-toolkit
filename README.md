# Blue Team Toolkit

A menu-driven defensive-security toolkit for rapidly assessing, hardening, and
monitoring Windows and Linux hosts. It wraps a curated set of well-known DFIR,
hardening, and recon tools behind one workflow:

**install tools -> map the host -> get a prioritized punch list -> harden ->
triage and hunt -> grade the result.**

Each platform has its own entry point but the two sides mirror each other in
structure and output, and everything funnels into a single graded report card.

## Scope and authorization

This is **defensive tooling for authorized use only**: systems you own, or are
explicitly cleared to assess and defend (production hardening, lab work, CTFs,
incident response). Some bundled tools (nmap, NetExec, nuclei, LinPEAS/WinPEAS,
SharpHound) are dual-use; run them only against in-scope assets. The hardening
module is **dry-run by default**, backs up every file it touches, and asks before
each change.

## What's included

Two entry points launch identical menu structures: `prep.ps1` (Windows console
menu) and `prep.sh` (Linux whiptail menu; needs `whiptail`, `jq`, `curl`). Both
create `output/` (reports, logs, `findings.jsonl`, `facts.json`) and `tools/`
(downloaded tools) next to the script. Per-platform logic lives in
`lib/windows/*.ps1` and `lib/linux/*.sh`:

1. **install**, reads `tools.json` and installs every tool, or a custom
   selection. Supports `winget`, `apt`, `pipx`/`pip`, direct URL download,
   `git clone`, and GitHub-release asset matching (archives are auto-extracted).
2. **map**, a discovery pass that writes `facts.json`: OS identity, role
   detection (Windows: DC/IIS/Exchange/AD CS/SQL/RDP/WinRM/Hyper-V; Linux:
   docker/nginx/apache/samba/bind/postgres/mysql/redis/SSSD), security posture,
   listening ports with bind-interface exposure analysis, privileged services,
   firewall posture, and which tools are present.
3. **recommend**, reads `facts.json` and prints a prioritized P0/P1/P2 hardening
   punch list with the matching hardening step, plus tools present vs. missing.
4. **harden**, a semi-automated checklist, **dry-run by default**, with per-step
   confirmation, a real file backup before each edit, and a rollback hint for
   every change. Steps that remove functionality (for example disabling the
   nftables module, or stripping setuid from pkexec) are labeled as such and
   gated behind an extra confirmation. Windows items include LSA RunAsPPL,
   disabling SMBv1, SMB signing, the SMBGhost workaround, Print Spooler (gated to
   DCs), LLMNR/NetBIOS/WPAD, NTLMv2-only, PowerShell logging, and audit policy.
   Linux items include SSH lockdown (with an authorized-keys safety check),
   auditd with the Neo23x0 ruleset, fail2ban, UFW default-deny, sysctl
   hardening, and package/service baselines.
5. **triage**, per-host raw-state collection to a timestamped report; dispatches
   installed scanners first (WinPEAS/autoruns/sigcheck, or
   lynis/linpeas/rkhunter/chkrootkit), then dumps processes, sockets,
   persistence, accounts, and other live state.
6. **hunt**, a backdoor/persistence hunt. Dispatches autoruns/chainsaw/hayabusa/
   hollows_hunter/loki where present, then runs high-specificity `[CLEAR]`
   checks (recent accounts, services and tasks in writable paths, masquerading
   processes, Defender tamper/exclusions, web-shell paths, ld.so.preload, ...)
   and separately labels noisier `[REVIEW]` exposure checks so the confidence
   labels mean what they say.
7. **recon**, network recon. INTERNAL: nmap host discovery + service scan +
   NetExec SMB enum + nuclei against web hosts. EXTERNAL: Shodan InternetDB,
   crt.sh subdomain pull, DNS enum, and NAT-hairpin nmap. Auto-detects targets
   into an editable `recon-targets.txt`.
8. **findings**, viewer for the persistent `findings.jsonl` accumulated across
   runs; summary, recent, by-type, and deduped CSV export.
9. **report card**, rolls `facts.json` + `findings.jsonl` into a single graded
   report (**A-F posture grade**, prioritized critical/high/medium issues, what
   is already in good shape, and open findings by type) as a self-contained
   **HTML** page and a **Markdown** file in `output/`. It runs nothing intrusive;
   it just grades what the other modules already collected.

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

The menu runs in workflow order: **1 install, 2 map, 3 recommend, 4 harden, then
5 triage / 6 hunt, 7 recon, 8 findings, and 9 to generate the graded report card.**

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

Single-author project. The Windows and Linux sides are at feature parity. No
automated tests; the hardening module is dry-run by default, but review its
output before applying changes to any host you care about.
