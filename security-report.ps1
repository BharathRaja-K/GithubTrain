$owner = "BharathRaja-K"
$repo = "GithubTrain"
$OutputPath = "$env:USERPROFILE\Desktop\Reports"

if (!(Test-Path $OutputPath)) { mkdir $OutputPath | Out-Null }

Write-Host "Enter GitHub Token:" -ForegroundColor Yellow
$Token = Read-Host

$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github+json"
}

$allFindings = @()

# Code Scanning
Write-Host "[1/3] Code Scanning..." -ForegroundColor Yellow
try {
    $r = Invoke-WebRequest -Uri "https://api.github.com/repos/$owner/$repo/code-scanning/alerts" -Headers $headers -UseBasicParsing
    $a = $r.Content | ConvertFrom-Json
    Write-Host "Found $($a.Count) alerts" -ForegroundColor Green
    foreach ($item in $a) {
        $allFindings += [PSCustomObject]@{Type='Code Scanning';Number=$item.number;State=$item.state;Severity=$item.rule.severity;Rule=$item.rule.name;File=$item.most_recent_instance.location.path;Line=$item.most_recent_instance.location.start_line}
    }
} catch { Write-Host "Error: $_" -ForegroundColor Red }

# Secret Scanning
Write-Host "[2/3] Secret Scanning..." -ForegroundColor Yellow
try {
    $r = Invoke-WebRequest -Uri "https://api.github.com/repos/$owner/$repo/secret-scanning/alerts" -Headers $headers -UseBasicParsing
    $a = $r.Content | ConvertFrom-Json
    Write-Host "Found $($a.Count) alerts" -ForegroundColor Green
    foreach ($item in $a) {
        $secretPath = if ($item.locations -and $item.locations.Count -gt 0) { $item.locations[0].path } else { "N/A" }
        $secretLine = if ($item.locations -and $item.locations.Count -gt 0) { $item.locations[0].start_line } else { "" }
        $allFindings += [PSCustomObject]@{Type='Secret Scanning';Number=$item.number;State=$item.state;Severity='Critical';Rule=$item.secret_type;File=$secretPath;Line=$secretLine}
    }
} catch { Write-Host "Error: $_" -ForegroundColor Red }

# Dependabot
Write-Host "[3/3] Dependabot..." -ForegroundColor Yellow
try {
    $r = Invoke-WebRequest -Uri "https://api.github.com/repos/$owner/$repo/dependabot/alerts" -Headers $headers -UseBasicParsing
    $a = $r.Content | ConvertFrom-Json
    Write-Host "Found $($a.Count) alerts" -ForegroundColor Green
    foreach ($item in $a) {
        $allFindings += [PSCustomObject]@{Type='Dependabot';Number=$item.number;State=$item.state;Severity=$item.security_advisory.severity;Rule=$item.dependency.package.name;File=$item.dependency.manifest_path;Line=''}
    }
} catch { Write-Host "Error: $_" -ForegroundColor Red }

# Save CSV
$csv = "$OutputPath\Security-$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
$allFindings | Export-Csv -Path $csv -NoTypeInformation

Write-Host ""
Write-Host "SUMMARY:" -ForegroundColor Green
Write-Host "Code Scanning:    $(($allFindings | Where-Object {$_.Type -eq 'Code Scanning'}).Count) alerts"
Write-Host "Secret Scanning:  $(($allFindings | Where-Object {$_.Type -eq 'Secret Scanning'}).Count) alerts"
Write-Host "Dependabot:       $(($allFindings | Where-Object {$_.Type -eq 'Dependabot'}).Count) alerts"
Write-Host "TOTAL:            $($allFindings.Count) findings"
Write-Host ""
Write-Host "Saved to: $csv" -ForegroundColor Green
Write-Host ""
$allFindings | Format-Table -AutoSize
Write-Host ""
Read-Host "Press Enter to exit"
