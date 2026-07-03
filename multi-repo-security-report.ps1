param(
    [string]$Token,
    [string]$OutputPath = "$env:USERPROFILE\Desktop\Reports"
)

if (!(Test-Path $OutputPath)) { mkdir $OutputPath | Out-Null }

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Multi-Repo Security Report Generator" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Get token
if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "Enter your GitHub Personal Access Token:" -ForegroundColor Yellow
    Write-Host "(Get one at: https://github.com/settings/personal-access-tokens/new)" -ForegroundColor Gray
    $Token = Read-Host
}

if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "ERROR: Token required" -ForegroundColor Red
    exit
}

# Get repo list
Write-Host ""
Write-Host "Enter repository list (format: owner/repo, one per line)" -ForegroundColor Yellow
Write-Host "Example:" -ForegroundColor Gray
Write-Host "  BharathRaja-K/GithubTrain" -ForegroundColor Gray
Write-Host "  microsoft/vscode" -ForegroundColor Gray
Write-Host "  (Press Ctrl+Z then Enter when done on Windows, or Ctrl+D on Mac/Linux)" -ForegroundColor Gray
Write-Host ""

$repos = @()
while ($true) {
    $input = Read-Host
    if ([string]::IsNullOrWhiteSpace($input)) { break }
    $repos += $input.Trim()
}

if ($repos.Count -eq 0) {
    Write-Host "ERROR: No repositories provided" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Processing $($repos.Count) repository(ies)..." -ForegroundColor Yellow
Write-Host ""

$headers = @{
    "Authorization" = "token $Token"
    "Accept" = "application/vnd.github+json"
    "User-Agent" = "PowerShell"
}

# Check if ImportExcel module exists, if not use CSV
$useExcel = $false
try {
    Import-Module ImportExcel -ErrorAction SilentlyContinue
    $useExcel = $true
}
catch {
    Write-Host "Note: ImportExcel module not found. Will create separate CSVs instead." -ForegroundColor Yellow
}

$allRepoData = @{}
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"

# Process each repo
foreach ($repo in $repos) {
    Write-Host "[$($repos.IndexOf($repo)+1)/$($repos.Count)] Processing: $repo" -ForegroundColor Cyan
    
    $repoFindings = @()
    
    # Code Scanning
    Write-Host "  - Code Scanning..." -ForegroundColor Yellow -NoNewline
    try {
        $uri = "https://api.github.com/repos/$repo/code-scanning/alerts"
        $r = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
        $a = $r.Content | ConvertFrom-Json
        Write-Host " $($a.Count) alerts" -ForegroundColor Green
        
        foreach ($item in $a) {
            $repoFindings += [PSCustomObject]@{
                Type = 'Code Scanning'
                'Alert #' = $item.number
                State = $item.state
                Severity = $item.rule.severity
                Rule = $item.rule.name
                File = $item.most_recent_instance.location.path
                Line = $item.most_recent_instance.location.start_line
                Created = $item.created_at
            }
        }
    }
    catch {
        Write-Host " Error" -ForegroundColor Red
    }
    
    # Secret Scanning
    Write-Host "  - Secret Scanning..." -ForegroundColor Yellow -NoNewline
    try {
        $uri = "https://api.github.com/repos/$repo/secret-scanning/alerts"
        $r = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
        $a = $r.Content | ConvertFrom-Json
        Write-Host " $($a.Count) alerts" -ForegroundColor Green
        
        foreach ($item in $a) {
            $secretPath = if ($item.locations -and $item.locations.Count -gt 0) { $item.locations[0].path } else { "N/A" }
            $secretLine = if ($item.locations -and $item.locations.Count -gt 0) { $item.locations[0].start_line } else { "" }
            
            $repoFindings += [PSCustomObject]@{
                Type = 'Secret Scanning'
                'Alert #' = $item.number
                State = $item.state
                Severity = 'Critical'
                Rule = $item.secret_type
                File = $secretPath
                Line = $secretLine
                Created = $item.created_at
            }
        }
    }
    catch {
        Write-Host " Error" -ForegroundColor Red
    }
    
    # Dependabot
    Write-Host "  - Dependabot..." -ForegroundColor Yellow -NoNewline
    try {
        $uri = "https://api.github.com/repos/$repo/dependabot/alerts"
        $r = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
        $a = $r.Content | ConvertFrom-Json
        Write-Host " $($a.Count) alerts" -ForegroundColor Green
        
        foreach ($item in $a) {
            $repoFindings += [PSCustomObject]@{
                Type = 'Dependabot'
                'Alert #' = $item.number
                State = $item.state
                Severity = $item.security_advisory.severity
                Rule = $item.dependency.package.name
                File = $item.dependency.manifest_path
                Line = ''
                Created = $item.created_at
            }
        }
    }
    catch {
        Write-Host " Error" -ForegroundColor Red
    }
    
    $allRepoData[$repo] = $repoFindings
}

# Save to Excel or CSV
Write-Host ""
Write-Host "Saving report..." -ForegroundColor Yellow

if ($useExcel) {
    $excelPath = "$OutputPath\Multi-Repo-Security-Report-$timestamp.xlsx"
    
    # Create Excel file with separate sheets
    foreach ($repo in $allRepoData.Keys) {
        $sheetName = $repo.Replace("/", "-").Substring(0, [Math]::Min(31, $repo.Replace("/", "-").Length))
        
        if ($allRepoData[$repo].Count -gt 0) {
            $allRepoData[$repo] | Export-Excel -Path $excelPath -WorksheetName $sheetName -AutoSize -FreezeTopRow
        }
        else {
            # Create empty sheet with headers
            @() | Export-Excel -Path $excelPath -WorksheetName $sheetName
        }
    }
    
    Write-Host "✓ Excel file saved: $excelPath" -ForegroundColor Green
}
else {
    # Create separate CSV files
    foreach ($repo in $allRepoData.Keys) {
        $csvName = $repo.Replace("/", "-")
        $csvPath = "$OutputPath\Security-Report-$csvName-$timestamp.csv"
        
        if ($allRepoData[$repo].Count -gt 0) {
            $allRepoData[$repo] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "✓ CSV saved: $csvPath" -ForegroundColor Green
        }
        else {
            Write-Host "  (No findings for $repo)" -ForegroundColor Gray
        }
    }
}

# Display summary
Write-Host ""
Write-Host "SUMMARY:" -ForegroundColor Cyan
Write-Host "--------"

$grandTotal = 0
foreach ($repo in $repos) {
    if ($allRepoData[$repo]) {
        $count = $allRepoData[$repo].Count
        $grandTotal += $count
        Write-Host "$repo : $count findings"
    }
}

Write-Host "--------"
Write-Host "TOTAL: $grandTotal findings across $($repos.Count) repo(s)"
Write-Host ""
Write-Host "Report location: $OutputPath" -ForegroundColor Green
Write-Host ""
Read-Host "Press Enter to exit"
