[CmdletBinding()]
param([switch]$ReplaceGroqKey, [switch]$SkipGroqPrompt, [switch]$Background)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-LoopbackPort([int]$Port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.Connect([Net.IPAddress]::Loopback, $Port)
        return $true
    } catch [Net.Sockets.SocketException] {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Read-LocalResponse([string]$Url, [string]$ZapKey = '') {
    $response = $null
    $reader = $null
    try {
        $request = [Net.HttpWebRequest]::Create($Url)
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.Timeout = 2000
        $request.ReadWriteTimeout = 2000
        if ($ZapKey) { $request.Headers.Add('X-ZAP-API-Key', $ZapKey) }
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { return }
        $reader = [IO.StreamReader]::new($response.GetResponseStream())
        $buffer = [char[]]::new(32768)
        $read = $reader.ReadBlock($buffer, 0, $buffer.Length)
        return [string]::new($buffer, 0, $read)
    } catch {
        return
    } finally {
        if ($reader) { $reader.Dispose() }
        if ($response) { $response.Dispose() }
    }
}

function Test-ZapKey([string]$Key) {
    return $Key -and (Read-LocalResponse 'http://127.0.0.1:8080/JSON/core/view/version/' $Key) -match '^\s*\{\s*"version"\s*:\s*"\d+\.\d+\.\d+[^"]*"\s*\}\s*$'
}

function Read-DesktopZapKey {
    try {
        $config = [Xml.XmlDocument]::new()
        $config.XmlResolver = $null
        $config.Load((Join-Path $env:USERPROFILE 'ZAP\config.xml'))
        $key = $config.SelectSingleNode('/config/api/key')
        if ($null -ne $key) { return $key.InnerText.Trim() }
    } catch {
        return
    }
}

function Read-ManagedZapKey([string]$SettingsPath) {
    if (Test-Path -LiteralPath $SettingsPath -PathType Leaf) {
        $line = Get-Content -LiteralPath $SettingsPath -TotalCount 1 -ErrorAction SilentlyContinue
        if ($line -match '^api\.key=([a-f0-9]{64})$') { return $Matches[1] }
    }
}

function Find-ZapJar {
    $directories = @($env:ZAP_INSTALL_DIR)
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { $directories += Join-Path $root 'ZAP\Zed Attack Proxy' }
    }
    foreach ($directory in $directories) {
        if (-not $directory -or -not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        $jar = Get-ChildItem -LiteralPath $directory -Filter 'zap-*.jar' -File |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($jar) { return $jar }
    }
}

function Find-ZapJava {
    $bundled = Join-Path (Split-Path -Parent $PSScriptRoot) 'practice-lab\runtime\java\bin\java.exe'
    if (Test-Path -LiteralPath $bundled -PathType Leaf) { return $bundled }
    if ($env:JAVA_HOME) {
        $installed = Join-Path $env:JAVA_HOME 'bin\java.exe'
        if (Test-Path -LiteralPath $installed -PathType Leaf) { return $installed }
    }
    $java = Get-Command java.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($java) { return $java.Source }
}

function Stop-ManagedZap([Diagnostics.Process]$Process, [string]$Key) {
    if ($null -eq $Process) { return }
    try {
        if ($Process.HasExited) { return }
        if ($Key) {
            $null = Read-LocalResponse 'http://127.0.0.1:8080/JSON/core/action/shutdown/' $Key
            if ($Process.WaitForExit(4000)) { return }
        }
        Stop-Process -InputObject $Process -ErrorAction SilentlyContinue
        $null = $Process.WaitForExit(4000)
    } finally {
        $Process.Dispose()
    }
}

function Connect-Zap([string]$DataDirectory, [string]$ExplicitKey, [ref]$ManagedProcess) {
    $settings = Join-Path $DataDirectory 'zap-api.properties'
    $managedKey = Read-ManagedZapKey $settings

    if (Test-LoopbackPort 8080) {
        $candidates = @($ExplicitKey)
        if ((Read-LocalResponse 'http://127.0.0.1:8080/') -match 'Welcome to (the Zed Attack Proxy|ZAP)') {
            $candidates += @($managedKey, (Read-DesktopZapKey))
        }
        foreach ($candidate in $candidates) {
            if (Test-ZapKey $candidate) {
                Write-Host 'Connected to the running local ZAP.'
                return $candidate
            }
        }
        Write-Warning 'Could not connect to ZAP on port 8080. Close the app using that port and reopen ScopeWeave for live ZAP checks.'
        return
    }

    $jar = Find-ZapJar
    $java = Find-ZapJava
    if (-not $jar -or -not $java) {
        Write-Host 'Live ZAP checks are optional. Install ZAP and Java to enable them.'
        return
    }

    $zapHome = Join-Path $DataDirectory 'zap'
    $null = New-Item -ItemType Directory -Path $zapHome -Force
    if (-not $managedKey) {
        $random = [Security.Cryptography.RandomNumberGenerator]::Create()
        try {
            $bytes = [byte[]]::new(32)
            $random.GetBytes($bytes)
            $managedKey = [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
        } finally {
            $random.Dispose()
        }
    }
    [IO.File]::WriteAllLines($settings, [string[]]@("api.key=$managedKey", 'api.disablekey=false', 'api.nokeyforviews=false'))

    Write-Host 'Starting ZAP in the background. First launch can take a minute.'
    $arguments = @(
        '-Xmx512m', '-jar', ('"{0}"' -f $jar.FullName),
        '-daemon', '-silent', '-host', '127.0.0.1', '-port', '8080',
        '-dir', ('"{0}"' -f $zapHome), '-configfile', ('"{0}"' -f $settings)
    )
    $ManagedProcess.Value = Start-Process -FilePath $java -ArgumentList $arguments -WorkingDirectory $jar.DirectoryName -WindowStyle Hidden -PassThru
    return $managedKey
}

$appUrl = 'http://127.0.0.1:8765/'
$dataDirectory = Join-Path $env:LOCALAPPDATA 'SentinelDesk'
$keyFile = Join-Path $dataDirectory 'groq-key.dpapi'
$mutex = [Threading.Mutex]::new($false, 'Local\SentinelDeskLauncher')
$ownsMutex = $false
$managedZap = $null
$zapKey = $null
$secureGroqKey = $null
$temporaryKeyFile = $null
$previousGroqKey = $env:GROQ_API_KEY
$previousZapKey = $env:ZAP_API_KEY

try {
    try { $ownsMutex = $mutex.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $ownsMutex = $true }

    if (Test-LoopbackPort 8765) {
        if ((Read-LocalResponse $appUrl) -match '<title>(ScopeWeave|Sentinel Desk)') {
            if ($ReplaceGroqKey) { throw 'Stop ScopeWeave with Ctrl+C in its launcher window, then open Update Groq Key again.' }
            if (-not $Background) {
                Write-Host 'ScopeWeave is already running. Opening it in your browser.'
                Start-Process $appUrl
            }
            return
        }
        throw 'Port 8765 is in use. Stop the old ScopeWeave window with Ctrl+C if it is running, then try again.'
    }
    if (-not $ownsMutex) {
        Write-Host 'ScopeWeave is starting in another launcher window.'
        return
    }

    $python = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $python) { throw 'Python 3 was not found. Install Python 3, reopen Windows Terminal and try again.' }

    $groqKey = $previousGroqKey
    if ($ReplaceGroqKey) { $groqKey = $null }
    if (-not $groqKey -and -not $ReplaceGroqKey -and (Test-Path -LiteralPath $keyFile -PathType Leaf)) {
        try {
            $secureGroqKey = ConvertTo-SecureString (Get-Content -LiteralPath $keyFile -Raw).Trim()
            $groqKey = [Net.NetworkCredential]::new('', $secureGroqKey).Password.Trim()
            if ($groqKey) { Write-Host 'Loaded the Groq key saved for this Windows account.' }
        } catch {
            Write-Warning 'Windows could not load the saved Groq key. Enter it again to continue.'
        }
    }
    if (-not $groqKey -and -not $Background -and ($ReplaceGroqKey -or -not $SkipGroqPrompt)) {
        if ($secureGroqKey) { $secureGroqKey.Dispose() }
        $secureGroqKey = Read-Host 'Paste your Groq API key (hidden), or press Enter to skip Groq' -AsSecureString
        $groqKey = [Net.NetworkCredential]::new('', $secureGroqKey).Password.Trim()
        if ($groqKey) {
            $remember = Read-Host 'Remember this key for this Windows account? [y/N]'
            if ($remember -match '^y(es)?$') {
                try {
                    $null = New-Item -ItemType Directory -Path $dataDirectory -Force
                    $temporaryKeyFile = Join-Path $dataDirectory ([Guid]::NewGuid().ToString('N') + '.tmp')
                    [IO.File]::WriteAllText($temporaryKeyFile, (ConvertFrom-SecureString -SecureString $secureGroqKey))
                    Move-Item -LiteralPath $temporaryKeyFile -Destination $keyFile -Force
                    Write-Host 'Groq key saved with Windows encryption.'
                } catch {
                    Write-Warning 'Could not save the Groq key. It will be used for this session.'
                }
            } elseif ($ReplaceGroqKey -and (Test-Path -LiteralPath $keyFile -PathType Leaf)) {
                Remove-Item -LiteralPath $keyFile
            }
        }
    }

    # Only ScopeWeave needs the cloud key. Keep it out of the ZAP process.
    $env:GROQ_API_KEY = $null
    $env:ZAP_API_KEY = $null
    try {
        $zapKey = Connect-Zap $dataDirectory $previousZapKey ([ref]$managedZap)
    } catch {
        Write-Warning 'Could not set up background ZAP. ScopeWeave will open with imports and the planner available.'
        Stop-ManagedZap $managedZap ''
        $managedZap = $null
    }
    $env:GROQ_API_KEY = $groqKey
    $env:ZAP_API_KEY = if ($zapKey) { $zapKey } else { $previousZapKey }
    $serverArguments = @((Join-Path $PSScriptRoot 'server.py'))
    if (-not $Background) {
        Write-Host 'Opening ScopeWeave in your browser. You can minimize this window. Press Ctrl+C here to stop.'
        $serverArguments += '--open-browser'
    }
    & $python.Source @serverArguments
    if ($LASTEXITCODE -ne 0) { throw 'ScopeWeave could not start. See the startup message above.' }
    if ($Background) { throw 'ScopeWeave background server stopped.' }
} finally {
    try {
        Stop-ManagedZap $managedZap $zapKey
    } finally {
        $env:GROQ_API_KEY = $previousGroqKey
        $env:ZAP_API_KEY = $previousZapKey
        if ($secureGroqKey) { $secureGroqKey.Dispose() }
        if ($temporaryKeyFile -and (Test-Path -LiteralPath $temporaryKeyFile -PathType Leaf)) {
            Remove-Item -LiteralPath $temporaryKeyFile -ErrorAction SilentlyContinue
        }
        if ($ownsMutex) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}
