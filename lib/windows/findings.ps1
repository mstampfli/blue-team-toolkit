# View persistent findings accumulated across all hunt/triage/map runs.
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'common.ps1')

$F = Join-Path $Script:OutputDir 'findings.jsonl'
if (-not (Test-Path $F)) {
    Write-Host "No findings.jsonl yet. Run option 4 (Hunt) or 6 (Map) first." -ForegroundColor Yellow
    Pause-Toolkit; return
}

Write-Host "Findings history:" -ForegroundColor Cyan
Write-Host "  1) SUMMARY  -- group by host+type+target, count + first/last seen"
Write-Host "  2) RECENT   -- last 50 findings"
Write-Host "  3) BY_TYPE  -- filter by type"
Write-Host "  4) EXPORT   -- write deduped CSV to findings-summary.csv"
Write-Host "  Q) Back"
$mode = Read-Host "Pick"

$all = Get-Content $F | ForEach-Object {
    try { $_ | ConvertFrom-Json } catch { }
} | Where-Object { $_ }

switch ($mode.ToUpper()) {
    '1' {
        Clear-Host
        Write-Host "=== FINDINGS SUMMARY ($(($all | Measure-Object).Count) raw events) ===" -ForegroundColor Cyan
        $all | Group-Object host, type, target | ForEach-Object {
            [PSCustomObject]@{
                Count  = $_.Count
                First  = ($_.Group | Sort-Object ts | Select-Object -First 1).ts
                Last   = ($_.Group | Sort-Object ts | Select-Object -Last 1).ts
                Host   = $_.Group[0].host
                Type   = $_.Group[0].type
                Target = $_.Group[0].target
            }
        } | Sort-Object Last -Descending | Format-Table -AutoSize | Out-Host
        Pause-Toolkit
    }
    '2' {
        Clear-Host
        $all | Select-Object -Last 50 | ForEach-Object {
            $sha = if ($_.sha256) { "  sha256=$(($_.sha256).Substring(0,12))…" } else { '' }
            "{0}  [{1}]  {2}  {3}{4}" -f $_.ts, $_.host, $_.type, $_.target, $sha
        } | Out-Host
        Pause-Toolkit
    }
    '3' {
        $types = $all | Select-Object -ExpandProperty type | Sort-Object -Unique
        Write-Host "Types:"
        for ($i = 0; $i -lt $types.Count; $i++) {
            $cnt = ($all | Where-Object { $_.type -eq $types[$i] }).Count
            "  {0,3}) {1,-40} ({2})" -f $i, $types[$i], $cnt | Out-Host
        }
        $idx = Read-Host "Pick index"
        if ($idx -match '^\d+$' -and [int]$idx -lt $types.Count) {
            $pick = $types[[int]$idx]
            Clear-Host
            $all | Where-Object { $_.type -eq $pick } | ForEach-Object {
                $sha = if ($_.sha256) { "  sha256=$(($_.sha256).Substring(0,12))…" } else { '' }
                "{0}  [{1}]  {2}{3}" -f $_.ts, $_.host, $_.target, $sha
            } | Out-Host
            Pause-Toolkit
        }
    }
    '4' {
        $out = Join-Path $Script:OutputDir 'findings-summary.csv'
        $all | Group-Object host, type, target | ForEach-Object {
            [PSCustomObject]@{
                count        = $_.Count
                first_seen   = ($_.Group | Sort-Object ts | Select-Object -First 1).ts
                last_seen    = ($_.Group | Sort-Object ts | Select-Object -Last 1).ts
                host         = $_.Group[0].host
                type         = $_.Group[0].type
                target       = $_.Group[0].target
                latest_sha256 = (($_.Group | Where-Object sha256 | Select-Object -Last 1).sha256)
            }
        } | Sort-Object last_seen -Descending | Export-Csv -Path $out -NoTypeInformation
        Write-Host "Exported: $out  ($(($all | Group-Object host,type,target).Count) deduped rows)" -ForegroundColor Green
        Pause-Toolkit
    }
}
