# Security report card: roll facts.json + findings.jsonl up into a single graded
# report (A-F posture grade, prioritized issues, open findings) as HTML + Markdown.
# Reads what map/triage/hunt already wrote; runs nothing intrusive itself.
$ErrorActionPreference = 'Continue'

$ToolkitDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$OutputDir  = Join-Path $ToolkitDir 'output'
$Script:OutputDir = $OutputDir
$Script:LogFile   = Join-Path $OutputDir 'toolkit.log'
. (Join-Path $PSScriptRoot 'common.ps1')

$factsPath = Join-Path $OutputDir 'facts.json'
$findPath  = Join-Path $OutputDir 'findings.jsonl'
if (-not (Test-Path $factsPath)) {
    Write-Host "No facts.json yet. Run option 2 (Map) first." -ForegroundColor Yellow
    Pause-Toolkit; return
}

$facts = Get-Content $factsPath -Raw | ConvertFrom-Json
$ss = $facts.security_state; $role = $facts.role; $exp = $facts.exposure

$crit = @(); $high = @(); $med = @(); $good = @()

# ---- critical ----
if ($ss.smb1_state -eq 'Enabled') { $crit += 'SMBv1 enabled (EternalBlue family)' } else { $good += 'SMBv1 disabled' }
if ($role.is_dc -and $role.print_spooler) { $crit += 'Print Spooler running on a domain controller (PrintNightmare)' }
if ($ss.lsa_protection_runasppl -ne 1) { $crit += 'LSA Protection (RunAsPPL) not set (LSASS readable)' } else { $good += 'LSA Protection on' }
if ($ss.defender_realtime -eq $false) { $crit += 'Defender real-time protection is off' } else { $good += 'Defender real-time on' }
if ($exp -and $exp.firewall_profiles_enabled -lt 3) { $crit += "Only $($exp.firewall_profiles_enabled)/3 Windows Firewall profiles enabled" } elseif ($exp) { $good += 'All firewall profiles enabled' }

# ---- high ----
if ($ss.smb_signing_required -ne $true) { $high += 'SMB signing not required (NTLM relay risk)' } else { $good += 'SMB signing required' }
if ($ss.llmnr_disabled -ne $true) { $high += 'LLMNR enabled' } else { $good += 'LLMNR disabled' }
if ($ss.lm_compat_level -ne 5) { $high += 'NTLMv2-only not enforced (LmCompatibilityLevel != 5)' } else { $good += 'NTLMv2-only enforced' }
if ($ss.ps_scriptblock_logging -ne $true) { $high += 'PowerShell ScriptBlock logging off' } else { $good += 'PowerShell ScriptBlock logging on' }
if ($ss.sysmon_running -ne $true) { $high += 'Sysmon not running' } else { $good += 'Sysmon running' }
if ($exp -and $exp.ports_bound_all_interfaces -gt 0) { $high += "$($exp.ports_bound_all_interfaces) port(s) bound to 0.0.0.0" }
if ($exp -and $exp.services_localsystem_outside_standard_paths -gt 0) { $high += "$($exp.services_localsystem_outside_standard_paths) LocalSystem service(s) from non-standard paths" }

# ---- medium ----
if ($ss.smb3_compression_disabled -ne 1) { $med += 'SMBv3 compression not disabled (SMBGhost workaround missing)' }
if ($ss.wpad_running) { $med += 'WPAD service (WinHttpAutoProxySvc) running' }
if ($ss.credential_guard_running -ne $true) { $med += 'Credential Guard not running' }
if (-not $facts.baselines.runkeys) { $med += 'No persistence baseline captured' }
if ($exp -and $exp.firewall_inbound_allow_any_rules -gt 0) { $med += "$($exp.firewall_inbound_allow_any_rules) inbound firewall rule(s) allow from Any" }

# ---- findings.jsonl ----
$fTotal = 0; $fTypes = @()
if (Test-Path $findPath) {
    $objs = Get-Content $findPath | Where-Object { $_.Trim() } | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} }
    $fTotal = @($objs).Count
    $fTypes = $objs | Group-Object type | Sort-Object Count -Descending | Select-Object -First 12
}

# ---- grade ----
$nc = $crit.Count; $nh = $high.Count; $nm = $med.Count
$score = $nc*30 + $nh*12 + $nm*4
if ($fTotal -gt 0) { $score += [Math]::Min(20, $fTotal) }
$grade = if ($score -eq 0) { 'A' } elseif ($score -lt 12) { 'B' } elseif ($score -lt 30) { 'C' } elseif ($score -lt 60) { 'D' } else { 'F' }
if ($nc -gt 0 -and $grade -in 'A','B','C') { $grade = 'D' }

$hostName = if ($facts.host) { $facts.host } else { $env:COMPUTERNAME }
$osLine = "$($facts.os.product) build $($facts.os.build) ($($facts.os.arch))"
$roles = (@('iis_running','exchange','adcs','sql_server','rdp_listening','winrm_listening','print_spooler','is_dc') | Where-Object { $role.$_ -eq $true }) -join ', '
if (-not $roles) { $roles = '(none detected)' }
$gen = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$htmlPath = Join-Path $OutputDir 'report.html'
$mdPath   = Join-Path $OutputDir 'report.md'

function Esc([string]$s) { ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') }
$gcolor = switch ($grade) { 'A' {'#2ecc71'} 'B' {'#7fce4b'} 'C' {'#f1c40f'} 'D' {'#e67e22'} default {'#e74c3c'} }
function LiHtml($cls, $arr) { if (@($arr).Count -eq 0) { "<li class='none'>none</li>" } else { ($arr | ForEach-Object { "<li class='$cls'>$(Esc $_)</li>" }) -join "`n" } }

# ---------- HTML ----------
$css = @'
:root{--bg:#15110d;--card:#1d1812;--fg:#ece3d6;--mut:#a08f7a;--bd:#3a2f24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:32px}
.wrap{max-width:900px;margin:0 auto}h1{font-size:20px;margin:0 0 4px}.mut{color:var(--mut)}
.grade{display:flex;align-items:center;gap:20px;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:20px;margin:18px 0}
.badge{width:84px;height:84px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:46px;font-weight:700;color:#15110d}
.score{font-size:13px;color:var(--mut)}h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin:24px 0 6px;border-bottom:1px solid var(--bd);padding-bottom:4px}
ul{margin:8px 0;padding-left:20px}li{margin:3px 0}li.crit{color:#ff8a80}li.high{color:#ffb74d}li.med{color:#fff3b0}li.good{color:#9be59b}li.none{color:var(--mut);list-style:none;margin-left:-12px}
table{border-collapse:collapse;width:100%;margin:8px 0}td{padding:3px 10px;border-bottom:1px solid var(--bd)}
.foot{color:var(--mut);font-size:12px;margin-top:28px;border-top:1px solid var(--bd);padding-top:10px}
'@
$rows = if (@($fTypes).Count) { ($fTypes | ForEach-Object { "<tr><td>$(Esc $_.Name)</td><td class='mut'>$($_.Count)</td></tr>" }) -join "`n" } else { "<tr><td class='mut'>none recorded yet</td></tr>" }
$html = @"
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report card: $(Esc $hostName)</title><style>$css</style></head><body><div class="wrap">
<h1>Security report card</h1>
<div class="mut">$(Esc $hostName) &middot; $(Esc $osLine)</div>
<div class="grade"><div class="badge" style="background:$gcolor">$grade</div><div>
<div>$nc critical &middot; $nh high &middot; $nm medium &middot; $fTotal open findings</div>
<div class="score">posture score $score (lower is better) &middot; roles: $(Esc $roles)</div></div></div>
<h2>Critical, do now</h2><ul>$(LiHtml 'crit' $crit)</ul>
<h2>High, before exposure</h2><ul>$(LiHtml 'high' $high)</ul>
<h2>Medium, when time allows</h2><ul>$(LiHtml 'med' $med)</ul>
<h2>Already in good shape</h2><ul>$(LiHtml 'good' $good)</ul>
<h2>Open findings ($fTotal) by type</h2><table>$rows</table>
<div class="foot">Generated $gen by Blue Team Toolkit from facts.json + findings.jsonl.
Run map (2), then hunt/triage (5/6), then regenerate for a fuller picture. Authorized defensive use only.</div>
</div></body></html>
"@
$html | Out-File -FilePath $htmlPath -Encoding utf8

# ---------- Markdown ----------
function MdList($arr) { if (@($arr).Count) { ($arr | ForEach-Object { "- $_" }) -join "`n" } else { "- none" } }
$mdTypes = if (@($fTypes).Count) { ($fTypes | ForEach-Object { "- $($_.Name): $($_.Count)" }) -join "`n" } else { "- none recorded yet" }
$md = @"
# Security report card: $hostName

**Grade $grade** ($nc critical, $nh high, $nm medium, $fTotal open findings; posture score $score, lower is better)

- Host: $hostName
- OS: $osLine
- Roles: $roles
- Generated: $gen

## Critical, do now
$(MdList $crit)

## High, before exposure
$(MdList $high)

## Medium, when time allows
$(MdList $med)

## Already in good shape
$(MdList $good)

## Open findings by type
$mdTypes

_Generated by Blue Team Toolkit from facts.json + findings.jsonl. Authorized defensive use only._
"@
$md | Out-File -FilePath $mdPath -Encoding utf8

Write-Log "REPORT grade=$grade score=$score -> $htmlPath"
Write-Host ""
Write-Host "Security report card written:" -ForegroundColor Green
Write-Host "  Grade: $grade  (score $score, lower is better)"
Write-Host "  $nc critical, $nh high, $nm medium, $fTotal open findings"
Write-Host "  HTML:     $htmlPath"
Write-Host "  Markdown: $mdPath"
Pause-Toolkit
