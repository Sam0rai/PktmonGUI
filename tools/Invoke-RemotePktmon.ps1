#Requires -Version 5.1

<#
.SYNOPSIS
    Runs PktmonGUI headless captures on remote hosts over WinRM: copies the exe, starts detached
    captures, stops them, and pulls the zipped results back.

.DESCRIPTION
    Every action runs on all hosts in parallel and returns one object per host
    (ComputerName, Action, ExitCode, Meaning, Phase, RunFolder, RemoteZip, LocalZip, Message).

      Start    Copy PktmonGUI.exe (and settings.json) to -RemoteFolder if they changed, then run
               PktmonGUI.exe --capture --detach. Returns once each host is recording; the capture
               keeps running after this script's sessions close.
      Stop     PktmonGUI.exe --stop: stop, restore the host's pktmon filters, convert, zip.
               Waits up to -StopTimeoutSeconds.
      Status   PktmonGUI.exe --status.
      Collect  Copy each host's last result zip to -Destination\<host>\ and check its SHA-256.
               A zip no longer on the host (already collected with -RemoveRemoteZip) gives 7.
      Cleanup  PktmonGUI.exe --cleanup, after a capture was killed (-Purge also deletes old runs).
      Run      Start, wait for -Duration to pass, Stop any host still recording, then Collect.
               Sessions that break meanwhile (the host slept, rebooted or dropped off the
               network) are reopened; a capture keeps running on the host either way.

    A host that can't be reached, or whose session is lost, gets a row of its own; the others go on.

    Results come back over the WinRM session instead of being pushed to a share with --collect:
    a WinRM session has no credentials it can pass on to a third server (the "double hop"), so
    --collect \\server\share fails from here. --collect is for runs as SYSTEM (GPO, SCCM, psexec -s).

.PARAMETER ComputerName
    Target hosts. They need WinRM, and the account must be a local administrator on them.

.PARAMETER Session
    Existing PSSessions to use instead of -ComputerName. They are left open.

.PARAMETER Action
    Start, Stop, Status, Collect, Cleanup or Run. Default: Status.

.PARAMETER Duration
    Capture length, e.g. 10m or 1h30m. Without it a detached capture stops after 24 hours
    (or earlier, with -Action Stop). Required for -Action Run.

.PARAMETER Filter
    pktmon filters, each written as for 'pktmon filter add', e.g. '-t TCP -p 443'.

.PARAMETER Preset
    Built-in filter sets: dns, rdp, smb, ldap-kerberos, tcp-syn, tcp-rst, icmp, cdp-lldp, arp, dhcp, https.

.PARAMETER Comp
    Adapters to capture on (--comp): nics (default), default, an ID, a MAC or a name.

.PARAMETER ArgumentList
    Further PktmonGUI.exe capture options, e.g. '--pkt-size','128','--file-size','2GB'.

.PARAMETER ExePath
    The local PktmonGUI.exe to deploy. Default: PktmonGUI.exe beside this script.

.PARAMETER SettingsPath
    A settings.json saved from the GUI, deployed beside the exe: it gives each capture its defaults
    (output folder, file size and log mode, packet size, process attribution, filter rules); flags
    still win. Default: settings.json beside -ExePath. When there's none, a settings.json left in
    -RemoteFolder by an earlier deployment is removed, so hosts never use stale defaults.

.PARAMETER RemoteFolder
    Where the exe goes on each host; environment variables are expanded there. Default:
    %ProgramFiles%\PktmonGUI, where only administrators can create or change anything. SYSTEM runs
    the exe from this folder, so a folder other accounts can change is refused.

.PARAMETER Destination
    Local folder for collected zips (one subfolder per host). Default: .\pktmon-results.

.PARAMETER UseAdminShare
    Collect through \\host\C$ instead of the WinRM session (faster for large zips; needs SMB access).

.EXAMPLE
    .\Invoke-RemotePktmon.ps1 -ComputerName SRV01,SRV02 -Action Start -Duration 30m -Preset dns
    .\Invoke-RemotePktmon.ps1 -ComputerName SRV01,SRV02 -Action Status
    .\Invoke-RemotePktmon.ps1 -ComputerName SRV01,SRV02 -Action Stop
    .\Invoke-RemotePktmon.ps1 -ComputerName SRV01,SRV02 -Action Collect -Destination D:\captures

.EXAMPLE
    .\Invoke-RemotePktmon.ps1 -ComputerName (Get-Content .\hosts.txt) -Action Run -Duration 5m -Filter '-t TCP -p 443' -RemoveRemoteZip

.NOTES
    For local (non-domain) administrator accounts, UAC filters remote tokens unless
    LocalAccountTokenFilterPolicy is 1 on the target.

    Windows PowerShell 5.1 quotes arguments to native programs itself: keep filter text free of
    double quotes, and don't end a path argument with a backslash.
#>
[CmdletBinding(DefaultParameterSetName = 'Computer')]
param(
    [Parameter(ParameterSetName = 'Computer', Mandatory = $true, Position = 0)]
    [string[]]$ComputerName,
    [Parameter(ParameterSetName = 'Session', Mandatory = $true)]
    [System.Management.Automation.Runspaces.PSSession[]]$Session,
    [ValidateSet('Start', 'Stop', 'Status', 'Collect', 'Cleanup', 'Run')]
    [string]$Action = 'Status',
    [Parameter(ParameterSetName = 'Computer')]
    [pscredential]$Credential,
    [Parameter(ParameterSetName = 'Computer')]
    [switch]$UseSSL,
    [int]$ThrottleLimit = 32,

    [string]$Duration,
    [string[]]$Filter,
    [string[]]$Preset,
    [string]$Comp,
    [string[]]$ArgumentList,

    [string]$ExePath = (Join-Path $PSScriptRoot 'PktmonGUI.exe'),
    [string]$SettingsPath = (Join-Path (Split-Path -Parent $ExePath) 'settings.json'),
    [string]$RemoteFolder = '%ProgramFiles%\PktmonGUI',
    [string]$Destination = '.\pktmon-results',
    [int]$StopTimeoutSeconds = 900,
    [switch]$RemoveRemoteZip,
    [switch]$Purge,
    [switch]$RemoveExe,
    [switch]$UseAdminShare
)

$ErrorActionPreference = 'Stop'
$remoteExe = Join-Path $RemoteFolder 'PktmonGUI.exe'
$meanings = @{
    0 = 'ok'; 1 = 'failed'; 2 = 'usage error'; 3 = 'unsupported'; 4 = 'busy / running'; 5 = 'collect failed';
    6 = 'done with warnings'; 7 = 'nothing to stop / leftovers'; 8 = 'machine not restored'; 9 = 'timed out'
}

function New-Row([string]$Computer, [string]$Act, $Code, [string]$Message, $Json) {
    $zip = $null; $runFolder = $null; $phase = $null
    if ($Json) {
        $last = if ($Json.PSObject.Properties['lastResult']) { $Json.lastResult } else { $Json }
        if ($Json.PSObject.Properties['zip']) { $zip = $Json.zip }
        elseif ($last -and $last.PSObject.Properties['zip']) { $zip = $last.zip }
        if ($Json.PSObject.Properties['runFolder']) { $runFolder = $Json.runFolder }
        elseif ($last -and $last.PSObject.Properties['runFolder']) { $runFolder = $last.runFolder }
        if ($Json.PSObject.Properties['phase']) { $phase = $Json.phase }
        elseif ($Json.PSObject.Properties['headless']) { $phase = $Json.headless }
        elseif ($Json.PSObject.Properties['status']) { $phase = $Json.status }
    }
    [pscustomobject]@{
        ComputerName = $Computer
        Action       = $Act
        ExitCode     = $Code
        Meaning      = if ($null -ne $Code -and $meanings.ContainsKey([int]$Code)) { $meanings[[int]$Code] } else { $null }
        Phase        = $phase
        RunFolder    = $runFolder
        RemoteZip    = $zip
        LocalZip     = $null
        Message      = $Message
        Json         = $Json
    }
}

# Runs PktmonGUI.exe on every session. Piping its output makes PowerShell wait for the
# GUI-subsystem exe and set $LASTEXITCODE (unpiped, it would return at once).
$runExe = {
    param([string]$Exe, [string[]]$Arguments)
    $Exe = [Environment]::ExpandEnvironmentVariables($Exe)
    if (-not (Test-Path -LiteralPath $Exe)) {
        return [pscustomobject]@{ ExitCode = -1; Output = "$Exe isn't on this host: run -Action Start first, or pass -RemoteFolder." }
    }
    $out = & $Exe @Arguments 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

$lostMessage = "Lost the WinRM session: the host may have gone to sleep, rebooted or dropped off the network. A capture there keeps running; check it later with -Action Status."

# Only sessions that are still open can run anything; the others become rows saying so.
function Split-Sessions([System.Management.Automation.Runspaces.PSSession[]]$Sessions, [string]$Act) {
    $open = New-Object System.Collections.Generic.List[object]
    foreach ($s in $Sessions) {
        if ($s.State -eq 'Opened') { $open.Add($s) }
        else { $results.Add((New-Row $s.ComputerName $Act $null "$lostMessage (session $($s.State))" $null)) }
    }
    , $open.ToArray()
}

function Invoke-Exe([System.Management.Automation.Runspaces.PSSession[]]$Sessions, [string]$Act, [string[]]$Arguments) {
    $Sessions = @($Sessions | Where-Object { $_ })
    if (-not $Sessions) { return @() }
    foreach ($s in $Sessions | Where-Object { $_.State -ne 'Opened' }) { New-Row $s.ComputerName $Act $null "$lostMessage (session $($s.State))" $null }
    $Sessions = @($Sessions | Where-Object { $_.State -eq 'Opened' })
    if (-not $Sessions) { return }
    $failed = @()
    try {
        $results = Invoke-Command -Session $Sessions -ScriptBlock $runExe -ArgumentList $remoteExe, $Arguments -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue -ErrorVariable failed
    }
    catch {
        # Every session broke between the check above and the call.
        foreach ($s in $Sessions) { New-Row $s.ComputerName $Act $null "$lostMessage ($($_.Exception.Message))" $null }
        return
    }
    foreach ($e in $failed) {
        $computer = if ($e.OriginInfo) { $e.OriginInfo.PSComputerName } else { [string]$e.TargetObject }
        New-Row $computer $Act $null ("Remote command failed: " + $e.Exception.Message) $null
    }
    foreach ($r in $results) {
        $json = $null
        try { $json = $r.Output | ConvertFrom-Json } catch { }
        $message = if ($json -and $json.PSObject.Properties['error']) { $json.error }
                   elseif ($json -and $json.PSObject.Properties['message']) { $json.message }
                   elseif ($json -and $json.PSObject.Properties['problems'] -and @($json.problems).Count -gt 0) { @($json.problems) -join ' ' }
                   elseif ($json -and $json.PSObject.Properties['done'] -and @($json.done).Count -gt 0) { @($json.done) -join ' ' }
                   elseif ($json -and $json.PSObject.Properties['meaning']) { $json.meaning }
                   elseif (-not $json) { $r.Output }
                   else { $null }
        New-Row $r.PSComputerName $Act $r.ExitCode $message $json
    }
}

# Makes the exe's folder on each host and reports the deployed exe's hash. SYSTEM runs PktmonGUI.exe
# from there, so a folder that any account besides SYSTEM, Administrators and TrustedInstaller can
# change (or a link) is refused; one owned by another account gets Administrators as owner. The exe
# makes its own data folder, %ProgramData%\PktmonGUI, safe when it runs.
$prepare = {
    param([string]$Folder)
    $Folder = [Environment]::ExpandEnvironmentVariables($Folder)
    $sidType = [System.Security.Principal.SecurityIdentifier]
    $admins = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    # SYSTEM, Administrators, TrustedInstaller, and CREATOR OWNER (Program Files has it; only administrators create there).
    $trusted = 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0'
    # Write data, append, write EA, delete child, write attributes, delete, write DAC, write owner, generic all/write.
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

    if (-not (Test-Path -LiteralPath $Folder)) { [void](New-Item -ItemType Directory -Path $Folder) }
    $item = Get-Item -LiteralPath $Folder -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Folder is a link, not a folder." }
    $acl = $item.GetAccessControl('Owner, Access')
    foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
        if ($rule.AccessControlType -ne 'Allow' -or $trusted -contains $rule.IdentityReference.Value) { continue }
        if (([int64]$rule.FileSystemRights -band $writeMask) -ne 0) {
            $who = try { $rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value } catch { $rule.IdentityReference.Value }
            throw "$Folder lets $who change it, and SYSTEM runs PktmonGUI.exe from it. Use a folder only administrators can change (the default is %ProgramFiles%\PktmonGUI)."
        }
    }
    if ($trusted -notcontains $acl.GetOwner($sidType).Value) {
        # An administrator owns what it creates on client Windows; that account's unelevated processes could change the ACL.
        $owner = New-Object System.Security.AccessControl.DirectorySecurity
        $owner.SetOwner($admins)
        $item.SetAccessControl($owner)
    }
    $exe = Join-Path $Folder 'PktmonGUI.exe'
    $settings = Join-Path $Folder 'settings.json'
    [pscustomobject]@{
        Folder       = $Folder
        Hash         = if (Test-Path -LiteralPath $exe) { (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash } else { $null }
        SettingsHash = if (Test-Path -LiteralPath $settings) { (Get-FileHash -LiteralPath $settings -Algorithm SHA256).Hash } else { $null }
    }
}

# Returns the sessions whose host has the exe ready; each host that failed becomes a result row.
function Install-PktmonExe([System.Management.Automation.Runspaces.PSSession[]]$Sessions, [string]$Act) {
    if (-not (Test-Path -LiteralPath $ExePath)) { throw "No PktmonGUI.exe at $ExePath; build it (dotnet build src/PktmonGUI -c Release) or pass -ExePath." }
    $localHash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
    $localSettingsHash = if ($SettingsPath -and (Test-Path -LiteralPath $SettingsPath)) { (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash } else { $null }
    $Sessions = Split-Sessions $Sessions $Act
    if (-not $Sessions) { return }
    $failed = @()
    $hashes = @(Invoke-Command -Session $Sessions -ScriptBlock $prepare -ArgumentList $RemoteFolder -ThrottleLimit $ThrottleLimit -ErrorAction SilentlyContinue -ErrorVariable failed)
    foreach ($e in $failed) {
        $computer = if ($e.OriginInfo) { $e.OriginInfo.PSComputerName } else { [string]$e.TargetObject }
        $results.Add((New-Row $computer $Act $null ("Couldn't prepare $RemoteFolder`: " + $e.Exception.Message) $null))
    }
    foreach ($h in $hashes) {
        $s = $Sessions | Where-Object { $_.ComputerName -eq $h.PSComputerName } | Select-Object -First 1
        # The exe uses a settings.json beside it for its defaults: keep the host's copy the same as ours, or none.
        if ($h.SettingsHash -ne $localSettingsHash) {
            try {
                if ($localSettingsHash) {
                    Copy-Item -LiteralPath $SettingsPath -Destination (Join-Path $h.Folder 'settings.json') -ToSession $s -Force
                    Write-Verbose "$($h.PSComputerName): copied settings.json to $($h.Folder)"
                }
                else {
                    Invoke-Command -Session $s -ScriptBlock { param($f) Remove-Item -LiteralPath (Join-Path $f 'settings.json') -Force } -ArgumentList $h.Folder
                    Write-Verbose "$($h.PSComputerName): removed the settings.json an earlier deployment left in $($h.Folder)"
                }
            }
            catch { Write-Warning "$($h.PSComputerName): couldn't update settings.json in $($h.Folder) ($($_.Exception.Message))." }
        }
        if ($h.Hash -eq $localHash) { Write-Verbose "$($h.PSComputerName): PktmonGUI.exe is current"; continue }
        try {
            Copy-Item -LiteralPath $ExePath -Destination $h.Folder -ToSession $s -Force
            Write-Verbose "$($h.PSComputerName): copied PktmonGUI.exe to $($h.Folder)"
        }
        catch {
            # In use by a running capture: that one keeps its exe, and a new start would be refused as busy anyway.
            Write-Warning "$($h.PSComputerName): couldn't update $remoteExe ($($_.Exception.Message)); using the copy there."
        }
    }
    $ready = @($hashes | ForEach-Object { $_.PSComputerName })
    , @($Sessions | Where-Object { $ready -contains $_.ComputerName -and $_.State -eq 'Opened' })
}

function Get-Status([System.Management.Automation.Runspaces.PSSession[]]$Sessions) {
    Invoke-Exe $Sessions 'Status' @('--status', '--json')
}

function Receive-CaptureZip([System.Management.Automation.Runspaces.PSSession[]]$Sessions) {
    foreach ($row in (Get-Status $Sessions)) {
        $row.Action = 'Collect'
        $s = $Sessions | Where-Object { $_.ComputerName -eq $row.ComputerName } | Select-Object -First 1
        if ($null -eq $row.ExitCode) { $row; continue } # no answer from the host: keep its error
        $last = if ($row.Json -and $row.Json.PSObject.Properties['lastResult']) { $row.Json.lastResult } else { $null }
        if (-not $s -or -not $last) { $row.Message = 'No finished capture to collect.'; $row.ExitCode = 7; $row.Meaning = $meanings[7]; $row; continue }
        if ($last.collectedTo) {
            $row.Message = "The host already copied it to $($last.collectedTo) (--collect)."
            $row.ExitCode = 7; $row.Meaning = $meanings[7]; $row; continue
        }
        if (-not $last.zip) {
            $row.Message = "The last capture left no zip (status $($last.status)); its files are in $($last.runFolder) on the host."
            $row.ExitCode = 7; $row.Meaning = $meanings[7]; $row; continue
        }
        $present = $true
        try { $present = Invoke-Command -Session $s -ScriptBlock { param($z) Test-Path -LiteralPath $z } -ArgumentList $last.zip -ErrorAction Stop } catch { }
        if (-not $present) {
            $row.RemoteZip = $last.zip
            $row.Message = "$($last.zip) is no longer on the host: already collected (-RemoveRemoteZip) or deleted."
            $row.ExitCode = 7; $row.Meaning = $meanings[7]; $row; continue
        }
        $row.RemoteZip = $last.zip
        $dir = Join-Path $Destination $row.ComputerName
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $local = Join-Path $dir (Split-Path -Leaf $last.zip)
        try {
            if ($UseAdminShare) {
                $unc = '\\' + $row.ComputerName + '\' + $last.zip.Substring(0, 1) + '$' + $last.zip.Substring(2)
                Copy-Item -LiteralPath $unc -Destination $local -Force
            }
            else { Copy-Item -LiteralPath $last.zip -Destination $local -FromSession $s -Force }
            if ($last.zipSha256 -and (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash -ne $last.zipSha256.ToUpperInvariant()) {
                throw "the copy's SHA-256 doesn't match the host's"
            }
            $row.LocalZip = (Resolve-Path -LiteralPath $local).Path
            $row.ExitCode = 0; $row.Meaning = $meanings[0]; $row.Message = "Collected ($([math]::Round((Get-Item -LiteralPath $local).Length / 1MB, 1)) MB)"
            if ($RemoveRemoteZip) {
                Invoke-Command -Session $s -ScriptBlock { param($z) Remove-Item -LiteralPath $z -Force } -ArgumentList $last.zip
                $row.Message += '; removed on the host'
            }
        }
        catch {
            $row.ExitCode = 5; $row.Meaning = $meanings[5]; $row.Message = "Couldn't copy $($last.zip): $($_.Exception.Message)"
        }
        $row
    }
}

# ---- Sessions ----------------------------------------------------------------------------------

$results = New-Object System.Collections.Generic.List[object]
$ownSessions = $false
$connectOpts = @{}
if ($Credential) { $connectOpts.Credential = $Credential }
if ($UseSSL) { $connectOpts.UseSSL = $true }
$allSessions = New-Object System.Collections.Generic.List[object] # every session this script opened, to close at the end

# Reopens sessions this script opened that broke (the host slept, rebooted or dropped off the network
# for a while). Sessions passed in with -Session are the caller's and are left as they are.
function Restore-Sessions([System.Management.Automation.Runspaces.PSSession[]]$Sessions) {
    $out = foreach ($s in $Sessions) {
        if ($s.State -eq 'Opened' -or -not $ownSessions) { $s; continue }
        $new = New-PSSession -ComputerName $s.ComputerName @connectOpts -ErrorAction SilentlyContinue
        if ($new) {
            Write-Verbose "$($s.ComputerName): the WinRM session was $($s.State); reconnected."
            $allSessions.Add($new)
            Remove-PSSession -Session $s -ErrorAction SilentlyContinue
            $new
        }
        else { $s }
    }
    , @($out)
}

if ($PSCmdlet.ParameterSetName -eq 'Computer') {
    $opts = @{ ComputerName = $ComputerName; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'connectErrors' } + $connectOpts
    $Session = @(New-PSSession @opts)
    $Session | ForEach-Object { $allSessions.Add($_) }
    $ownSessions = $true
    $connected = @($Session | ForEach-Object { $_.ComputerName })
    $unreached = @($ComputerName | Where-Object { $connected -notcontains $_ })
    foreach ($c in $unreached) {
        $why = $connectErrors | Where-Object { "$($_.TargetObject)" -like "*$c*" -or $_.Exception.Message -like "*$c*" } | Select-Object -First 1
        if (-not $why -and $unreached.Count -eq 1) { $why = $connectErrors | Select-Object -First 1 }
        $text = if ($why) { ($why.Exception.Message -split "`n")[0].Trim() } else { 'no WinRM session' }
        $results.Add((New-Row $c $Action $null ("Couldn't connect: " + $text) $null))
    }
}
$Session = @($Session | Where-Object { $_.State -eq 'Opened' })

try {
    if ($Session.Count -gt 0) {
        switch ($Action) {
            'Status' { Get-Status $Session | ForEach-Object { $results.Add($_) } }

            'Start' {
                $ready = Install-PktmonExe $Session 'Start'
                $capture = @('--capture', '--detach', '--json')
                if ($Duration) { $capture += @('--duration', $Duration) }
                if ($Comp) { $capture += @('--comp', $Comp) }
                foreach ($f in $Filter) { $capture += @('--filter', $f) }
                foreach ($p in $Preset) { $capture += @('--preset', $p) }
                if ($ArgumentList) { $capture += $ArgumentList }
                Invoke-Exe $ready 'Start' $capture | ForEach-Object { $results.Add($_) }
            }

            'Stop' {
                Invoke-Exe $Session 'Stop' @('--stop', '--json', '--timeout', "$($StopTimeoutSeconds)s") | ForEach-Object { $results.Add($_) }
            }

            'Collect' { Receive-CaptureZip $Session | ForEach-Object { $results.Add($_) } }

            'Cleanup' {
                $cleanup = @('--cleanup', '--json')
                if ($Purge) { $cleanup += '--purge' }
                Invoke-Exe $Session 'Cleanup' $cleanup | ForEach-Object { $results.Add($_) }
                $open = @($Session | Where-Object { $_.State -eq 'Opened' })
                if ($RemoveExe -and $open) {
                    Invoke-Command -Session $open -ScriptBlock { param($e) Remove-Item -LiteralPath ([Environment]::ExpandEnvironmentVariables($e)) -Force -ErrorAction SilentlyContinue } -ArgumentList $remoteExe -ErrorAction SilentlyContinue
                }
            }

            'Run' {
                if (-not $Duration) { throw '-Action Run needs -Duration.' }
                $ready = Install-PktmonExe $Session 'Start'
                $capture = @('--capture', '--detach', '--json', '--duration', $Duration)
                if ($Comp) { $capture += @('--comp', $Comp) }
                foreach ($f in $Filter) { $capture += @('--filter', $f) }
                foreach ($p in $Preset) { $capture += @('--preset', $p) }
                if ($ArgumentList) { $capture += $ArgumentList }
                $started = @(Invoke-Exe $ready 'Start' $capture)
                $started | Where-Object { $_.ExitCode -ne 0 } | ForEach-Object { $results.Add($_) }
                $recording = @($ready | Where-Object { $name = $_.ComputerName; $started | Where-Object { $_.ComputerName -eq $name -and $_.ExitCode -eq 0 } })

                if ($recording.Count -gt 0) {
                    # The .NET parser in PktmonGUI.exe is the authority on durations; ask the host when it stops.
                    $stopAt = ($started | Where-Object { $_.ExitCode -eq 0 -and $_.Json.stopAt } | ForEach-Object { [datetime]$_.Json.stopAt } | Measure-Object -Maximum).Maximum
                    if ($stopAt) {
                        Write-Host "Recording on $($recording.Count) host(s) until about $stopAt."
                        while ((Get-Date) -lt $stopAt) { Start-Sleep -Seconds ([math]::Min(30, [math]::Max(1, ($stopAt - (Get-Date)).TotalSeconds))) }
                    }
                    else { $stopAt = Get-Date } # --duration 0: no end of its own; stop it now
                    # Give each host time to convert and zip, then stop any that is still recording.
                    # A host may have dropped off meanwhile; its session is reopened before each check.
                    $deadline = (Get-Date).AddSeconds($StopTimeoutSeconds)
                    do {
                        Start-Sleep -Seconds 15
                        $recording = Restore-Sessions $recording
                        $busy = @(Get-Status $recording | Where-Object { $_.Json -and $_.Json.headless -eq 'running' -and $_.Json.phase -eq 'Running' })
                    } while ($busy.Count -gt 0 -and (Get-Date) -lt $stopAt.AddMinutes(2))
                    if ($busy.Count -gt 0) {
                        $late = @($recording | Where-Object { $busy.ComputerName -contains $_.ComputerName })
                        Invoke-Exe $late 'Stop' @('--stop', '--json', '--timeout', "$($StopTimeoutSeconds)s") | Where-Object { $_.ExitCode -notin 0, 6 } | ForEach-Object { $results.Add($_) }
                    }
                    do {
                        $recording = Restore-Sessions $recording
                        $finishing = @(Get-Status $recording | Where-Object { $_.Json -and $_.Json.headless -eq 'running' })
                        if ($finishing.Count -gt 0) { Start-Sleep -Seconds 10 }
                    } while ($finishing.Count -gt 0 -and (Get-Date) -lt $deadline)
                    $recording = Restore-Sessions $recording
                    Receive-CaptureZip $recording | ForEach-Object { $results.Add($_) }
                }
            }
        }
    }
}
finally {
    if ($allSessions.Count -gt 0) { Remove-PSSession -Session $allSessions.ToArray() -ErrorAction SilentlyContinue }
}

$results | Select-Object ComputerName, Action, ExitCode, Meaning, Phase, RunFolder, RemoteZip, LocalZip, Message

# Failure: no connection, or a code that means something went wrong for this action.
$bad = @(1, 2, 3, 5, 8, 9, -1)
if ($Action -in 'Start', 'Run') { $bad += 4 }
if (@($results | Where-Object { $null -eq $_.ExitCode -or $bad -contains [int]$_.ExitCode }).Count -gt 0) { exit 1 }
exit 0
