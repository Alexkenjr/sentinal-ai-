$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$downloadDir = Join-Path $projectRoot 'downloads'
$statusPath = Join-Path $downloadDir 'ai-setup-status.txt'
$installer = Join-Path $downloadDir 'OllamaSetup.exe'
$expectedSize = 1658535520
function Report($message) {
    $line = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' ' + $message
    Add-Content -LiteralPath $statusPath -Value $line -Encoding utf8
    Write-Output $line
}
try {
    Report 'Waiting for official Ollama installer download to complete.'
    $lastSize = -1
    $unchanged = 0
    while ($true) {
        $size = if (Test-Path -LiteralPath $installer) { (Get-Item -LiteralPath $installer).Length } else { 0 }
        if ($size -eq $expectedSize) { break }
        if ($size -gt $expectedSize) { throw 'Unexpected installer length; refusing installation.' }
        if ($size -eq $lastSize) { $unchanged++ } else { $unchanged = 0 }
        if ($unchanged -ge 60) { throw 'Download stalled for 10 minutes. Download must be resumed before installation.' }
        $lastSize = $size
        Start-Sleep -Seconds 10
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid') { throw ('Invalid installer signature: ' + $signature.Status) }
    Report ('Installer signature verified: ' + $signature.SignerCertificate.Subject)
    $install = Start-Process -FilePath $installer -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-' -WindowStyle Hidden -Wait -PassThru
    if ($install.ExitCode -notin @(0,3010)) { throw ('Installer failed: ' + $install.ExitCode) }
    $ollama = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
    if (-not (Test-Path -LiteralPath $ollama)) { throw 'Installed Ollama executable not found.' }
    Report 'Ollama installed. Starting/checking local server.'
    try { $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3 }
    catch {
        Start-Process -FilePath $ollama -ArgumentList 'serve' -WindowStyle Hidden -RedirectStandardOutput (Join-Path $downloadDir 'ollama-server.log') -RedirectStandardError (Join-Path $downloadDir 'ollama-server-error.log') | Out-Null
        $ready = $false
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Seconds 2
            try { $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2; $ready = $true; break } catch {}
        }
        if (-not $ready) { throw 'Local Ollama server did not become ready.' }
    }
    Report 'Downloading qwen3:1.7b local model. Model weights are additional to installer.'
    & $ollama pull 'qwen3:1.7b' *> (Join-Path $downloadDir 'model-download.log')
    if ($LASTEXITCODE -ne 0) { throw 'Model download failed. See model-download.log.' }
    [Environment]::SetEnvironmentVariable('SENTINELAI_BOT_MODEL', 'qwen3:1.7b', 'User')
    $env:SENTINELAI_BOT_MODEL = 'qwen3:1.7b'
    Report 'Model downloaded. Testing actual local inference.'
    $body = @{model='qwen3:1.7b';messages=@(@{role='user';content='Reply with exactly: SENTINEL_READY'});stream=$false;think=$false;options=@{num_predict=40;num_ctx=2048}} | ConvertTo-Json -Depth 5
    $reply = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/chat' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 180
    if (-not $reply.message.content -or -not $reply.done) { throw 'Model did not return a complete text reply.' }
    $reply | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $downloadDir 'ai-inference-verification.json') -Encoding utf8
    Report ('COMPLETE: installed Ollama, downloaded model, verified local inference: ' + $reply.message.content)
} catch {
    Report ('FAILED: ' + $_.Exception.Message)
    exit 1
}
