$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repo = Split-Path -Parent $PSScriptRoot
$tool = Join-Path $repo 'codex-auth.ps1'
$root = Join-Path $env:TEMP ('codex-auth-tests-' + [Guid]::NewGuid().ToString('N'))
$home = Join-Path $root 'codex'
$local = Join-Path $root 'local'
$oldHome, $oldLocal, $oldElevated = $env:CODEX_HOME, $env:LOCALAPPDATA, $env:CODEX_AUTH_SWITCHER_TEST_ALLOW_ELEVATED

function Assert([bool]$Value, [string]$Message) {
    if (-not $Value) { throw "Assertion failed: $Message" }
}

function Auth([string]$Id, [string]$Access, [string]$Refresh) {
    $value = [ordered]@{ auth_mode = 'chatgpt'; tokens = [ordered]@{
        account_id = $Id; access_token = $Access; refresh_token = $Refresh; id_token = 'fixture_id'
    }} | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText((Join-Path $home 'auth.json'), $value, (New-Object Text.UTF8Encoding($false)))
}

function Field([string]$Name) {
    $value = Get-Content -LiteralPath (Join-Path $home 'auth.json') -Raw | ConvertFrom-Json
    return [string]$value.tokens.PSObject.Properties[$Name].Value
}

function Run([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments) {
    $output = & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tool @Arguments 2>&1 | Out-String
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output }
}

function Pass($Result, [string]$Name) {
    Assert ($Result.Code -eq 0) "$Name failed: $($Result.Output)"
}

function Fail($Result, [string]$Name) {
    Assert ($Result.Code -ne 0) "$Name unexpectedly succeeded"
}

try {
    New-Item -ItemType Directory -Path $home, $local -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $home 'sessions'), (Join-Path $home 'skills') | Out-Null
    [IO.File]::WriteAllText((Join-Path $home 'config.toml'), "model = `"fixture`"`r`n")
    [IO.File]::WriteAllText((Join-Path $home 'history.jsonl'), '{"fixture":true}')
    [IO.File]::WriteAllText((Join-Path $home 'sessions\keep'), 'session')
    [IO.File]::WriteAllText((Join-Path $home 'skills\keep'), 'skill')
    $env:CODEX_HOME, $env:LOCALAPPDATA, $env:CODEX_AUTH_SWITCHER_TEST_ALLOW_ELEVATED = $home, $local, '1'

    $hashes = @{}
    foreach ($file in @('config.toml', 'history.jsonl', 'sessions\keep', 'skills\keep')) {
        $hashes[$file] = (Get-FileHash (Join-Path $home $file) -Algorithm SHA256).Hash
    }

    Auth acct_alpha fixture_access_alpha_1 fixture_refresh_alpha_1
    Pass (Run save alpha) 'save alpha'
    Auth acct_beta fixture_access_beta_1 fixture_refresh_beta_1
    Pass (Run save beta) 'save beta'
    Pass (Run switch alpha) 'switch alpha'
    Assert ((Field account_id) -ceq 'acct_alpha') 'alpha should be active'
    Auth acct_alpha fixture_access_alpha_2 fixture_refresh_alpha_2
    Pass (Run switch beta) 'switch beta after refresh'
    Pass (Run switch alpha) 'switch back to alpha'
    Assert ((Field access_token) -ceq 'fixture_access_alpha_2') 'refreshed token should survive'

    $accounts = Join-Path $local 'TerminatedCable\CodexAuthSwitcher\accounts'
    foreach ($profile in Get-ChildItem $accounts -Filter '*.auth.dpapi') {
        $text = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($profile.FullName))
        Assert (-not $text.Contains('fixture_access_')) 'encrypted profile exposed an access token'
        Assert (-not $text.Contains('fixture_refresh_')) 'encrypted profile exposed a refresh token'
    }

    Auth acct_gamma fixture_access_gamma fixture_refresh_gamma
    Fail (Run save alpha) 'label collision'
    Pass (Run save gamma) 'save gamma'
    Auth acct_alpha fixture_access_alpha_3 fixture_refresh_alpha_3
    Fail (Run save alpha-copy) 'duplicate account'
    Fail (Run save '..\unsafe') 'unsafe label'
    [IO.File]::WriteAllText((Join-Path $home 'auth.json'), '{not-json')
    Fail (Run save invalid) 'invalid JSON'
    Auth acct_alpha fixture_access_alpha_2 fixture_refresh_alpha_2

    $config = Join-Path $home 'config.toml'
    [IO.File]::WriteAllText($config, "cli_auth_credentials_store = `"keyring`"`r`n")
    Fail (Run list) 'keyring mode'
    [IO.File]::WriteAllText($config, "model = `"fixture`"`r`n")

    $lock = Join-Path $local 'TerminatedCable\CodexAuthSwitcher\.lock'
    $held = [IO.File]::Open($lock, 'OpenOrCreate', 'ReadWrite', 'None')
    try { Fail (Run list) 'concurrent lock' } finally { $held.Dispose() }

    $authPath = Join-Path $home 'auth.json'
    $before = [Convert]::ToBase64String([IO.File]::ReadAllBytes($authPath))
    $held = [IO.File]::Open($authPath, 'Open', 'Read', 'Read')
    try { Fail (Run switch beta) 'locked auth replacement' } finally { $held.Dispose() }
    Assert ([Convert]::ToBase64String([IO.File]::ReadAllBytes($authPath)) -ceq $before) 'failed replacement changed auth.json'

    Pass (Run switch beta) 'switch before restore'
    Pass (Run restore) 'restore'
    Assert ((Field account_id) -ceq 'acct_alpha') 'restore should return to alpha'

    $real, $link = (Join-Path $root 'real'), (Join-Path $root 'link')
    New-Item -ItemType Directory $real | Out-Null
    [IO.File]::Copy($authPath, (Join-Path $real 'auth.json'))
    New-Item -ItemType Junction -Path $link -Target $real | Out-Null
    $env:CODEX_HOME = $link
    Fail (Run list) 'reparse-point CODEX_HOME'
    $env:CODEX_HOME = $home

    foreach ($file in $hashes.Keys) {
        Assert ((Get-FileHash (Join-Path $home $file) -Algorithm SHA256).Hash -ceq $hashes[$file]) "$file changed"
    }
    $source = [IO.File]::ReadAllText($tool)
    foreach ($word in @('Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'System.Net.', 'Invoke-Expression', 'Stop-Process', '.Kill(')) {
        Assert (-not $source.Contains($word)) "source contains forbidden primitive $word"
    }
    Write-Host 'All codex-auth-switcher tests passed.' -ForegroundColor Green
}
finally {
    $env:CODEX_HOME, $env:LOCALAPPDATA, $env:CODEX_AUTH_SWITCHER_TEST_ALLOW_ELEVATED = $oldHome, $oldLocal, $oldElevated
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
