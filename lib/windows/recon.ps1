# Network recon — INTERNAL sweep + EXTERNAL exposure check (Windows).
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$Script:TargetsFile = Join-Path $Script:OutputDir 'recon-targets.txt'
$Script:Thorough    = $false
$Script:InternetOK  = $false

# --- target file management ---

function Rebuild-Targets {
    $lines = @(
        "# Recon targets — auto-detected $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')."
        "# Format: <type> <value>  [# comment]"
        "# type = internal_cidr | external_ip | external_domain"
        ""
    )
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixLength -lt 32 } |
        ForEach-Object {
            $cidr = Convert-IPCidr -IP $_.IPAddress -Prefix $_.PrefixLength
            $lines += "internal_cidr $cidr  # auto-detected"
        }
    $lines += ""
    $pubip = $null
    foreach ($u in 'https://ifconfig.me','https://api.ipify.org','https://icanhazip.com') {
        try {
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $cand = $r.Content.Trim()
            if ($cand -match '^\d+\.\d+\.\d+\.\d+$') { $pubip = $cand; break }
        } catch { }
    }
    if ($pubip) { $lines += "external_ip $pubip  # auto-detected" }
    # Try domain from FQDN
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs.Domain -and $cs.Domain -notmatch 'WORKGROUP|^$') {
        $lines += "external_domain $($cs.Domain)  # auto-detected from domain"
    } else {
        $lines += "# external_domain example.com  # add manually if you have a public domain"
    }
    $lines | Set-Content -Path $Script:TargetsFile -Encoding UTF8
}

function Init-Targets { if (-not (Test-Path $Script:TargetsFile)) { Rebuild-Targets } }

function Get-Targets {
    param([string]$Type)
    if (-not (Test-Path $Script:TargetsFile)) { return @() }
    Get-Content $Script:TargetsFile | Where-Object { $_ -match "^$Type " } | ForEach-Object { ($_ -split '\s+')[1] }
}

function Edit-Targets {
    if (Get-Command notepad.exe -ErrorAction SilentlyContinue) {
        Start-Process notepad.exe -ArgumentList $Script:TargetsFile -Wait
    } else {
        Write-Host "Edit manually: $Script:TargetsFile"
        Pause-Toolkit
    }
}

function Show-Targets {
    Clear-Host
    Write-Host "=== $Script:TargetsFile ===" -ForegroundColor Cyan
    Get-Content $Script:TargetsFile | Where-Object { $_ -notmatch '^\s*#|^\s*$' } | Out-Host
    Pause-Toolkit
}

# --- depth + internet ---

function Choose-Thoroughness {
    Write-Host ""
    Write-Host "Scan depth:" -ForegroundColor Cyan
    Write-Host "  1) QUICK -- top-1000 ports + default scripts (~5-15 min/24)"
    Write-Host "  2) FULL  -- all 65k ports + vuln scripts + nuclei (~1-4 HOURS/24)"
    $c = Read-Host "Pick [1]"
    $Script:Thorough = ($c -eq '2')
}

function Get-NmapPath {
    foreach ($p in 'nmap', 'C:\Program Files (x86)\Nmap\nmap.exe', 'C:\Program Files\Nmap\nmap.exe') {
        $cmd = Get-Command $p -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

function Nmap-DiscoArgs { '-sn -T4 -PE -PP -PS21,22,23,25,80,113,443,445,3389 -PA80,443,3389' -split ' ' }
function Nmap-ServiceArgs {
    if ($Script:Thorough) {
        '-sV -sC -A -p- --script default,vuln,vulners -T4 --version-intensity 9 --max-retries 2' -split ' '
    } else {
        '-sV -sC -T4 --top-ports 1000' -split ' '
    }
}

# --- nmap output parsing -> findings ---

function Parse-NmapFindings {
    param([string]$NmapFile, [string]$Context)
    if (-not (Test-Path $NmapFile)) { return }
    $currentHost = ''
    Get-Content $NmapFile | ForEach-Object {
        if ($_ -match '^Nmap scan report for (.+)$') {
            $currentHost = ($Matches[1] -split ' ')[0]
        } elseif ($_ -match '^(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)$') {
            $port = $Matches[1]; $proto = $Matches[2]; $svc = $Matches[3]
            $banner = $Matches[4].Trim()
            if ($banner.Length -gt 100) { $banner = $banner.Substring(0,100) }
            $conf = if ($Context -match 'external') { 'clear' } else { 'informational' }
            Record-Finding -Type ($Context + '_open_port') -Target ("$currentHost`:$port/$proto") -Extra @{
                service    = $svc
                banner     = $banner
                confidence = $conf
            }
        } elseif ($Script:Thorough -and $_ -match 'CVE-(\d{4}-\d+)') {
            $cve = "CVE-$($Matches[1])"
            Record-Finding -Type 'nmap_vulners_cve' -Target ($_.Trim().Substring(0, [Math]::Min($_.Length, 200))) -Extra @{
                cve        = $cve
                confidence = 'clear'
            }
        }
    }
}

# --- INTERNAL ---

function Internal-Recon {
    $cidrs = Get-Targets internal_cidr
    if (-not $cidrs) {
        Write-Host "No 'internal_cidr' lines in $Script:TargetsFile" -ForegroundColor Yellow
        Pause-Toolkit; return
    }
    $nmap = Get-NmapPath
    if (-not $nmap) {
        Write-Host "nmap not on PATH and not at standard install location." -ForegroundColor Red
        Write-Host "Install via: winget install Insecure.Nmap   (or option 1 in main menu)"
        Pause-Toolkit; return
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $liveFile = Join-Path $Script:OutputDir "recon-internal-live-$stamp.txt"
    Set-Content -Path $liveFile -Value ''

    foreach ($cidr in $cidrs) {
        $clean = $cidr -replace '/', '_'
        $LH = Join-Path $Script:OutputDir "recon-internal-livehosts-$clean-$stamp.log"
        Clear-Host
        $args = (Nmap-DiscoArgs) + @('-oG','-', $cidr)
        Invoke-Silent -Label "nmap-sn $cidr" -LogFile $LH -FilePath $nmap -ArgumentList $args
        Get-Content $LH -ErrorAction SilentlyContinue |
            Where-Object { $_ -match 'Status: Up' } |
            ForEach-Object { ($_ -split '\s+')[1] } |
            Add-Content -Path $liveFile
    }

    $live = @(Get-Content $liveFile)
    Write-Host ""
    Write-Host "[recon] $($live.Count) live hosts in $($cidrs.Count) CIDR(s) -> $liveFile" -ForegroundColor Cyan
    if ($live.Count -eq 0) { Pause-Toolkit; return }

    # Service detect
    $SVC = Join-Path $Script:OutputDir "recon-internal-services-$stamp"
    $desc = if ($Script:Thorough) { 'FULL: -p- + vuln scripts' } else { 'QUICK: top-1000 + default scripts' }
    Clear-Host
    $args = (Nmap-ServiceArgs) + @('-iL', $liveFile, '-oA', $SVC)
    Invoke-Silent -Label "nmap $desc x$($live.Count)" -LogFile "$SVC.log" -FilePath $nmap -ArgumentList $args
    Parse-NmapFindings -NmapFile "$SVC.nmap" -Context 'internal'

    # SMB enum via NetExec if installed
    $nxc = Get-Command nxc -ErrorAction SilentlyContinue
    if ($nxc) {
        $smbHosts = @()
        if (Test-Path "$SVC.nmap") {
            $cur = ''
            Get-Content "$SVC.nmap" | ForEach-Object {
                if ($_ -match '^Nmap scan report for (.+)$') { $cur = ($Matches[1] -split ' ')[0] }
                elseif ($_ -match '^445/tcp\s+open' -and $cur) { $smbHosts += $cur }
            }
            $smbHosts = $smbHosts | Sort-Object -Unique
        }
        if ($smbHosts.Count -gt 0) {
            $SMB = Join-Path $Script:OutputDir "recon-internal-smb-$stamp.log"
            Clear-Host
            Invoke-Silent -Label "nxc smb --shares" -LogFile $SMB -FilePath 'nxc' `
                -ArgumentList (@('smb') + $smbHosts + @('--shares'))
            Get-Content $SMB -ErrorAction SilentlyContinue |
                Where-Object { $_ -match 'READ.*ALL|Anonymous|signing:False' } |
                ForEach-Object {
                    Record-Finding -Type 'smb_weak_config' `
                        -Target ($_.Substring(0, [Math]::Min($_.Length, 200))) `
                        -Extra @{ confidence = 'clear' }
                }
        }
    }

    # Web fingerprint + nuclei
    $webHosts = @()
    if (Test-Path "$SVC.nmap") {
        $cur = ''
        Get-Content "$SVC.nmap" | ForEach-Object {
            if ($_ -match '^Nmap scan report for (.+)$') { $cur = ($Matches[1] -split ' ')[0] }
            elseif ($_ -match '^(80|443|8080|8443|8000|8888|9000|9090|9443)/tcp\s+open' -and $cur) { $webHosts += $cur }
        }
        $webHosts = $webHosts | Sort-Object -Unique
    }
    if ($webHosts.Count -gt 0) {
        $nucleiBin = Ensure-Extracted -ArchivePattern 'nuclei*windows*.zip' -BinaryName 'nuclei'
        if ($nucleiBin) {
            $urls = Join-Path $Script:OutputDir ".nuclei-urls-$stamp.txt"
            $list = @()
            foreach ($h in $webHosts) { $list += "http://$h"; $list += "https://$h" }
            Set-Content -Path $urls -Value $list
            $NU = Join-Path $Script:OutputDir "recon-internal-nuclei-$stamp.log"
            $sevs = if ($Script:Thorough) { 'critical,high,medium,low' } else { 'critical,high' }
            Clear-Host
            Invoke-Silent -Label "nuclei vs $($list.Count) URLs sev=$sevs" -LogFile $NU `
                -FilePath $nucleiBin -ArgumentList @('-l', $urls, '-severity', $sevs, '-nc', '-silent')
            Get-Content $NU -ErrorAction SilentlyContinue | ForEach-Object {
                $cve = if ($_ -match 'CVE-\d{4}-\d+') { $Matches[0] } else { 'unknown' }
                $sev = if ($_ -match '\[(critical|high|medium|low)\]') { $Matches[1] } else { 'unknown' }
                $tgt = if ($_ -match 'https?://\S+') { $Matches[0] } else { '' }
                if ($tgt) {
                    Record-Finding -Type 'nuclei_cve' -Target $tgt -Extra @{ cve = $cve; severity = $sev; confidence = 'clear' }
                }
            }
            Remove-Item $urls -ErrorAction SilentlyContinue
        }
    }
    Clear-Host
    Write-Host "[recon] internal sweep complete." -ForegroundColor Green
    Write-Host "  live    : $liveFile  ($($live.Count) hosts)"
    Write-Host "  services: $SVC.{nmap,gnmap,xml}"
    Pause-Toolkit
}

# --- EXTERNAL ---

function External-Recon {
    $ips     = Get-Targets external_ip
    $domains = Get-Targets external_domain
    if (-not $ips -and -not $domains) {
        Write-Host "No external_ip or external_domain in $Script:TargetsFile" -ForegroundColor Yellow
        Pause-Toolkit; return
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    if (-not $Script:InternetOK) {
        Write-Host @"
[recon] No internet detected.

In an air-gapped exercise, "external" view means scanning your assets from a
DIFFERENT VLAN. Add those CIDRs as 'internal_cidr' lines and run INTERNAL.

Skipping Shodan + crt.sh. Doing local-only DNS + nmap.
"@ -ForegroundColor Yellow
        Pause-Toolkit
    }

    # Shodan InternetDB
    if ($ips -and $Script:InternetOK) {
        $SH = Join-Path $Script:OutputDir "recon-external-shodan-$stamp.json"
        Set-Content -Path $SH -Value ''
        foreach ($ip in $ips) {
            Write-Host "[recon] Shodan InternetDB -> $ip" -ForegroundColor Cyan
            try {
                $r = Invoke-RestMethod -Uri "https://internetdb.shodan.io/$ip" -TimeoutSec 10 `
                    -Headers @{ 'User-Agent' = 'blueteam-toolkit' } -ErrorAction Stop
                $r | Add-Member -NotePropertyName queried_ip -NotePropertyValue $ip -Force
                Add-Content -Path $SH -Value ($r | ConvertTo-Json -Compress -Depth 6)
                $r.ports | ForEach-Object {
                    if ($_) { Record-Finding -Type 'exposed_external_port' -Target ("$ip`:$_") -Extra @{ source = 'shodan_internetdb'; confidence = 'clear' } }
                }
                $r.vulns | ForEach-Object {
                    if ($_) { Record-Finding -Type 'external_known_vuln' -Target $ip -Extra @{ cve = $_; source = 'shodan_internetdb'; confidence = 'clear' } }
                }
                $r.tags | ForEach-Object {
                    if ($_) { Record-Finding -Type 'external_service_tag' -Target $ip -Extra @{ tag = $_; source = 'shodan_internetdb' } }
                }
                Write-Host "  ports: $($r.ports -join ',')"
                Write-Host "  vulns: $($r.vulns -join ',')"
                Write-Host "  tags : $($r.tags  -join ',')"
            } catch {
                Write-Host "  (not in Shodan dataset)" -ForegroundColor DarkGray
            }
        }
        Pause-Toolkit
    }

    # NAT-hairpin nmap
    $nmap = Get-NmapPath
    if ($ips -and $nmap) {
        foreach ($ip in $ips) {
            $clean = $ip -replace '\.', '_'
            $NM = Join-Path $Script:OutputDir "recon-external-nmap-$clean-$stamp"
            Clear-Host
            $args = @('-sV', '--top-ports', '1000', '-T4', '-Pn', '-oA', $NM, $ip)
            Invoke-Silent -Label "nmap external $ip" -LogFile "$NM.log" -FilePath $nmap -ArgumentList $args
            Parse-NmapFindings -NmapFile "$NM.nmap" -Context 'external_via_lan'
        }
    }

    # DNS enum
    if ($domains) {
        foreach ($d in $domains) {
            $DNS = Join-Path $Script:OutputDir "recon-external-dns-$d-$stamp.log"
            Clear-Host
            Write-Host "[recon] DNS enum for $d"
            $sb = {
                param($dom, $haveNet)
                "=== A ===";   try { Resolve-DnsName -Name $dom -Type A -ErrorAction SilentlyContinue }   catch {}
                "=== AAAA ==="; try { Resolve-DnsName -Name $dom -Type AAAA -ErrorAction SilentlyContinue } catch {}
                "=== MX ==="; try { Resolve-DnsName -Name $dom -Type MX -ErrorAction SilentlyContinue } catch {}
                "=== NS ==="; try { Resolve-DnsName -Name $dom -Type NS -ErrorAction SilentlyContinue } catch {}
                "=== TXT ==="; try { Resolve-DnsName -Name $dom -Type TXT -ErrorAction SilentlyContinue } catch {}
                "=== DMARC ==="; try { Resolve-DnsName -Name "_dmarc.$dom" -Type TXT -ErrorAction SilentlyContinue } catch {}
                if ($haveNet) {
                    "=== Subdomains via crt.sh ==="
                    try {
                        $rs = Invoke-RestMethod -Uri "https://crt.sh/?q=%25.$dom&output=json" -TimeoutSec 30
                        $rs | ForEach-Object { $_.name_value -split ',' } | Sort-Object -Unique | Where-Object { $_ -notmatch '^\*' }
                    } catch { "  (crt.sh failed)" }
                } else { "=== crt.sh skipped (no internet) ===" }
            }
            & $sb $d $Script:InternetOK | Tee-Object -FilePath $DNS | Out-Host
            Get-Content $DNS | Select-String -Pattern "[a-z0-9.-]+\.$([regex]::Escape($d))" -AllMatches |
                ForEach-Object { $_.Matches.Value } | Sort-Object -Unique |
                ForEach-Object { Record-Finding -Type 'external_subdomain' -Target $_ }
        }
        Pause-Toolkit
    }
    Clear-Host
    Write-Host "[recon] external check complete." -ForegroundColor Green
    Write-Host "Reminder: NAT-hairpin nmap is unreliable. For ground-truth external view,"
    Write-Host "scan from a cloud VM outside your network."
    Pause-Toolkit
}

function Auto-Recon {
    Write-Host "[recon] AUTO mode -- re-detecting targets..." -ForegroundColor Cyan
    Rebuild-Targets
    Get-Content $Script:TargetsFile | Where-Object { $_ -notmatch '^\s*#|^\s*$' } | Out-Host
    Write-Host ""
    Write-Host "[recon] Sleeping 3s -- Ctrl-C to abort"
    Start-Sleep 3
    Internal-Recon
    External-Recon
    Clear-Host
    Write-Host "[recon] AUTO complete. Findings appended; see option 7 + 8." -ForegroundColor Green
    Pause-Toolkit
}

# --- main loop ---

Init-Targets
$Script:InternetOK = Test-InternetAvailable
while ($true) {
    Clear-Host
    $depth = if ($Script:Thorough) { 'FULL' } else { 'QUICK' }
    $net   = if ($Script:InternetOK) { 'OK' } else { 'NONE' }
    Write-Host "Recon  |  Depth: $depth  |  Internet: $net  |  Targets: $Script:TargetsFile" -ForegroundColor Cyan
    Write-Host "  A) AUTO     -- re-detect + INTERNAL + EXTERNAL with no prompts"
    Write-Host "  T) TARGETS  -- view/edit recon-targets.txt"
    Write-Host "  D) DEPTH    -- toggle QUICK / FULL"
    Write-Host "  I) INTERNAL -- nmap discover + service + SMB + nuclei"
    Write-Host "  E) EXTERNAL -- Shodan/DNS/crt.sh + NAT-hairpin nmap"
    Write-Host "  B) BOTH"
    Write-Host "  V) VIEW current targets"
    Write-Host "  Q) Quit"
    $c = Read-Host "Pick"
    switch ($c.ToUpper()) {
        'A' { Auto-Recon }
        'T' { Edit-Targets }
        'D' { Choose-Thoroughness }
        'I' { Internal-Recon }
        'E' { External-Recon }
        'B' { Internal-Recon; External-Recon }
        'V' { Show-Targets }
        'Q' { return }
    }
}
