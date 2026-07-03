param(
    [string]$Token,
    [string]$OutputPath = "D:\Workspace\Bharath Raja K\GitHub\Report"
)

$owner = "BharathRaja-K"
$repo = "GithubTrain"

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "GitHub Security Report Generator" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get token if not provided
if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "Enter your GitHub Personal Access Token:" -ForegroundColor Yellow
    Write-Host "(Get one at: https://github.com/settings/personal-access-tokens/new)" -ForegroundColor Gray
    $Token = Read-Host
}

if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "ERROR: Token required" -ForegroundColor Red
    exit
}

$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github+json"
    "User-Agent" = "PowerShell"
}

# Initialize collections
$allFindings = @()

# ============================================================
# 1. FETCH CODE SCANNING ALERTS
# ============================================================
Write-Host "[1/3] Fetching Code Scanning alerts..." -ForegroundColor Yellow
try {
    $uri = "https://api.github.com/repos/$owner/$repo/code-scanning/alerts"
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
    $codeAlerts = $response.Content | ConvertFrom-Json
    
    Write-Host "  ✓ Found $($codeAlerts.Count) code scanning alerts" -ForegroundColor Green
    
    foreach ($alert in $codeAlerts) {
        $allFindings += [PSCustomObject]@{
            'Type' = 'Code Scanning'
            'Alert #' = $alert.number
            'State' = $alert.state
            'Severity' = $alert.rule.severity
            'Rule' = $alert.rule.name
            'File' = $alert.most_recent_instance.location.path
            'Line' = $alert.most_recent_instance.location.start_line
            'Created' = $alert.created_at
            'URL' = $alert.html_url
        }
    }
}
catch {
    Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================
# 2. FETCH SECRET SCANNING ALERTS
# ============================================================
Write-Host "[2/3] Fetching Secret Scanning alerts..." -ForegroundColor Yellow
try {
    $uri = "https://api.github.com/repos/$owner/$repo/secret-scanning/alerts"
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
    $secretAlerts = $response.Content | ConvertFrom-Json
    
    Write-Host "  ✓ Found $($secretAlerts.Count) secret scanning alerts" -ForegroundColor Green
    
    foreach ($alert in $secretAlerts) {
        $allFindings += [PSCustomObject]@{
            'Type' = 'Secret Scanning'
            'Alert #' = $alert.number
            'State' = $alert.state
            'Severity' = 'Critical'
            'Rule' = $alert.secret_type
            'File' = $alert.locations[0].path
            'Line' = $alert.locations[0].start_line
            'Created' = $alert.created_at
            'URL' = $alert.html_url
        }
    }
}
catch {
    Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================
# 3. FETCH DEPENDABOT VULNERABILITIES
# ============================================================
Write-Host "[3/3] Fetching Dependabot vulnerabilities..." -ForegroundColor Yellow
try {
    $uri = "https://api.github.com/repos/$owner/$repo/dependabot/alerts"
    $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
    $depAlerts = $response.Content | ConvertFrom-Json
    
    Write-Host "  ✓ Found $($depAlerts.Count) dependency vulnerabilities" -ForegroundColor Green
    
    foreach ($alert in $depAlerts) {
        $allFindings += [PSCustomObject]@{
            'Type' = 'Dependabot'
            'Alert #' = $alert.number
            'State' = $alert.state
            'Severity' = $alert.security_advisory.severity
            'Rule' = "$($alert.dependency.package.name) - CVE"
            'File' = $alert.dependency.manifest_path
            'Line' = ''
            'Created' = $alert.created_at
            'URL' = $alert.html_url
        }
    }
}
catch {
    Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# ============================================================
# SAVE TO CSV
# ============================================================
Write-Host ""
Write-Host "Saving results..." -ForegroundColor Yellow

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$csvPath = "$OutputPath\Security-Report-$timestamp.csv"

if ($allFindings.Count -gt 0) {
    $allFindings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "✓ CSV saved: $csvPath" -ForegroundColor Green
    
    # Show summary
    Write-Host ""
    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "--------"
    Write-Host "Code Scanning:    $(($allFindings | Where-Object {$_.Type -eq 'Code Scanning'}).Count) alerts"
    Write-Host "Secret Scanning:  $(($allFindings | Where-Object {$_.Type -eq 'Secret Scanning'}).Count) alerts"
    Write-Host "Dependabot:       $(($allFindings | Where-Object {$_.Type -eq 'Dependabot'}).Count) alerts"
    Write-Host "TOTAL:            $($allFindings.Count) findings"
    Write-Host ""
    
    # Display in table
    Write-Host "Details:" -ForegroundColor Cyan
    $allFindings | Select-Object 'Type','Alert #','State','Severity','Rule' | Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "Open report? (Y/N)" -ForegroundColor Yellow
    $response = Read-Host
    if ($response -eq "Y" -or $response -eq "y") {
        Invoke-Item $csvPath
    }
}
else {
    Write-Host "No security findings detected!" -ForegroundColor Green
}

Write-Host ""
Read-Host "Press Enter to exit"
