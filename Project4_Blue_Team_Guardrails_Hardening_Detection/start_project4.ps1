$ErrorActionPreference = "Stop"

$projectDir = $PSScriptRoot
$repoRoot = Split-Path -Parent $projectDir
$activateScript = Join-Path $projectDir ".venv\Scripts\Activate.ps1"

Write-Host "`n========================================"
Write-Host " SECURENOVA - PROJECT 4 STARTUP"
Write-Host "========================================`n"

# 1. Check virtual environment
if (-not (Test-Path $activateScript)) {
    Write-Error "Project 4 virtual environment not found."
    return
}

# 2. Locate Ollama
$ollama = Get-Command ollama -ErrorAction SilentlyContinue

if (-not $ollama) {
    Write-Error "Ollama is not installed or not available in PATH."
    return
}

# 3. Check whether Ollama server is already running
$serverReady = $false

try {
    $null = Invoke-RestMethod `
        -Uri "http://127.0.0.1:11434/api/tags" `
        -TimeoutSec 3
    $serverReady = $true
}
catch {
    Write-Host "Ollama server is not running. Starting it..."

    Start-Process `
        -FilePath $ollama.Source `
        -ArgumentList "serve" `
        -WindowStyle Hidden
}

# 4. Wait for Ollama server
if (-not $serverReady) {
    for ($i = 1; $i -le 20; $i++) {
        Start-Sleep -Seconds 1

        try {
            $null = Invoke-RestMethod `
                -Uri "http://127.0.0.1:11434/api/tags" `
                -TimeoutSec 2

            $serverReady = $true
            break
        }
        catch {}
    }
}

if (-not $serverReady) {
    Write-Error "Ollama failed to start. Check the Ollama application."
    return
}

Write-Host "[OK] Ollama server is running." -ForegroundColor Green

# 5. Verify Qwen model availability
$tags = Invoke-RestMethod `
    -Uri "http://127.0.0.1:11434/api/tags"

$modelAvailable = @(
    $tags.models | Where-Object {
        $_.name -like "qwen2.5:7b-instruct*"
    }
).Count -gt 0

if (-not $modelAvailable) {
    Write-Error "Qwen model missing. Run: ollama pull qwen2.5:7b-instruct"
    return
}

Write-Host "[OK] Qwen 2.5 7B model is available." -ForegroundColor Green

# 6. Activate Project 4 environment in the current PowerShell session
Set-Location $repoRoot
. $activateScript

Write-Host "[OK] Project 4 virtual environment activated." -ForegroundColor Green

# 7. Verify NeMo Guardrails
python -c "import nemoguardrails; print('NeMo Guardrails: INSTALLED')"

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Install NeMo using: python -m pip install nemoguardrails"
}

# 8. Verify cryptography
python -c "import cryptography; print('Cryptography: INSTALLED')"

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Install using: python -m pip install cryptography"
}

Write-Host "`n========================================"
Write-Host " PROJECT 4 READY"
Write-Host "========================================"
Write-Host "Ollama: RUNNING"
Write-Host "Model: qwen2.5:7b-instruct"
Write-Host "Python environment: ACTIVE"
Write-Host "`nYou can now execute your Python test scripts."
