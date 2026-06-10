#Requires -Version 5.1
<#
.SYNOPSIS
    Checks and fixes common Remote Desktop (RDP) configuration issues on Windows.

.DESCRIPTION
    Diagnoses TermService, firewall rules, registry settings, port 3389 and user
    permissions. Works correctly on localised Windows (e.g. Hungarian).
    Use -Fix to apply safe remediations automatically.

.PARAMETER Fix
    Apply fixes for detected issues. Without this switch the script runs in check-only mode.

.PARAMETER Port
    RDP TCP port to verify (default: 3389).

.PARAMETER User
    Optional account to verify membership in the Remote Desktop Users group
    (e.g. DOMAIN\user or .\username).

.EXAMPLE
    .\Fix-RdpErrors.ps1
    Report issues only.

.EXAMPLE
    .\Fix-RdpErrors.ps1 -Fix
    Check and fix detected issues (run as Administrator).

.EXAMPLE
    .\Fix-RdpErrors.ps1 -Fix -User ".\krivanszkij-admin"
    Fix issues and verify the specified user can use RDP.
#>

[CmdletBinding()]
param(
    [switch]$Fix,
    [int]$Port = 3389,
    [string]$User
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IssuesFound = 0
$script:IssuesFixed = 0
$script:Warnings    = [System.Collections.Generic.List[string]]::new()

# Well-known SID for the built-in "Remote Desktop Users" group (locale-independent).
$script:RdpUsersGroupSid = 'S-1-5-32-555'
$script:ScriptVersion    = '2.1'

# ── output helpers ──────────────────────────────────────────────────────────

function Write-Section ([string]$Title) {
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}
function Write-Ok    ([string]$Msg) { Write-Host "[OK]   $Msg" -ForegroundColor Green   }
function Write-Issue ([string]$Msg) { $script:IssuesFound++
                                      Write-Host "[FAIL] $Msg" -ForegroundColor Red     }
function Write-Fixed ([string]$Msg) { $script:IssuesFixed++
                                      Write-Host "[FIX]  $Msg" -ForegroundColor Magenta }
function Write-Warn  ([string]$Msg) { $script:Warnings.Add($Msg)
                                      Write-Host "[WARN] $Msg" -ForegroundColor Yellow  }

# ── fix helper ───────────────────────────────────────────────────────────────
# Uses $script: scope variables to avoid PowerShell scriptblock scoping issues.

function Invoke-Fix ([string]$Description, [scriptblock]$Action) {
    if (-not $Fix) {
        Write-Host "       (run with -Fix to remediate)" -ForegroundColor DarkGray
        return
    }
    try   { & $Action; Write-Fixed $Description }
    catch { Write-Warn "Could not fix '$Description': $($_.Exception.Message)" }
}

# ── admin check ──────────────────────────────────────────────────────────────

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]::new($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── registry helpers ─────────────────────────────────────────────────────────

function Get-RegValue ([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name
}

# ── port helper ───────────────────────────────────────────────────────────────

function Test-PortListening ([int]$TcpPort) {
    $c = Get-NetTCPConnection -LocalPort $TcpPort -State Listen -ErrorAction SilentlyContinue
    [bool]($c | Where-Object { $_.LocalAddress -in '0.0.0.0','::','[::]' })
}

# ── firewall helpers ──────────────────────────────────────────────────────────
# NOTE: DisplayGroup / DisplayName are localised on non-English Windows.
#       Rule Name values are never localised — always use those.

$script:RdpRuleNames = @(
    'RemoteDesktop-UserMode-In-TCP'
    'RemoteDesktop-UserMode-In-UDP'
    'RemoteDesktop-Shadow-In-TCP'
)

function Test-RuleAllowsTcpPort {
    param(
        [object]$Rule,
        [int]$TcpPort
    )

    $pf = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $Rule -ErrorAction SilentlyContinue
    if (-not $pf -or $pf.Protocol -ne 'TCP') { return $false }

    $ports = @($pf.LocalPort -split ',' | ForEach-Object { $_.Trim() })
    return ($ports -contains 'Any') -or ($ports -contains '*') -or ($ports -contains "$TcpPort")
}

function Get-RdpRules {
    param([int]$TcpPort = 3389)

    # Fetch all firewall rules once. Never use DisplayGroup — it is localised
    # (e.g. Hungarian "Távoli asztal" vs English "Remote Desktop").
    $all = @(Get-NetFirewallRule -ErrorAction SilentlyContinue)
    if ($all.Count -eq 0) { return @() }

    $byName = @($all | Where-Object { $_.Name -in $script:RdpRuleNames })
    if ($byName.Count -gt 0) { return $byName }

    # Fallback: any inbound allow rule that opens the RDP TCP port.
    @($all | Where-Object {
        $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' -and
        (Test-RuleAllowsTcpPort -Rule $_ -TcpPort $TcpPort)
    })
}

# ── user helper (locale-independent via well-known SID) ───────────────────────

function Get-RdpUsersGroup {
  <#
    Returns the local Remote Desktop Users group object.
    Uses the well-known SID so this works on Hungarian and other localised Windows
    where the display name differs (e.g. "Távoli asztal felhasználói").
  #>
    try {
        return Get-LocalGroup -SID $script:RdpUsersGroupSid -ErrorAction Stop
    }
    catch {
        Write-Warn "Could not resolve Remote Desktop Users group by SID: $($_.Exception.Message)"
        return $null
    }
}

function Test-InRdpGroup ([string]$AccountName) {
    try {
        $group = Get-RdpUsersGroup
        if (-not $group) { return $null }

        $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction Stop |
            ForEach-Object { $_.Name })

        $bare = $AccountName -replace '^.*\\', ''
        $memberBares = $members | ForEach-Object { $_ -replace '^.*\\', '' }
        return ($members -contains $AccountName) -or
               ($members -contains $bare) -or
               ($memberBares -contains $bare)
    }
    catch {
        Write-Warn "Could not read Remote Desktop Users membership: $($_.Exception.Message)"
        return $null
    }
}

# ── event log helper (locale-independent provider / log names) ────────────────
# EventLogException can bypass -ErrorAction; isolate queries and swallow misses.

function Get-RecentProviderEvents {
    param(
        [string]$LogName,
        [string]$ProviderName,
        [datetime]$Since,
        [int]$MaxEvents = 5
    )

    $events = @()

    # FilterXPath avoids FilterHashtable parameter issues on some localised builds.
    $utcSince = $Since.ToUniversalTime().ToString('o')
    $xpath = @"
*[System[
    Provider[@Name='$ProviderName']
    and (Level=2 or Level=3)
    and TimeCreated[@SystemTime>='$utcSince']
]]
"@

    try {
        $events = @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -MaxEvents $MaxEvents -ErrorAction Stop)
        if ($events.Count -gt 0) { return $events }
    }
    catch { <# XPath or provider not available — try fallback #> }

    # Fallback: direct provider query then filter in PowerShell.
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $events = @(Get-WinEvent -LogName $LogName -ProviderName $ProviderName -MaxEvents 200 -ErrorAction SilentlyContinue |
            Where-Object { $_.Level -in 2, 3 -and $_.TimeCreated -ge $Since } |
            Select-Object -First $MaxEvents)
        if ($events.Count -gt 0) { return $events }
    }
    catch { <# no events or provider missing #> }
    finally { $ErrorActionPreference = $prevEap }

    # Last resort: legacy Get-EventLog API (often works when Get-WinEvent fails).
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $events = @(Get-EventLog -LogName $LogName -Source $ProviderName -After $Since `
            -EntryType Error, Warning -Newest $MaxEvents -ErrorAction SilentlyContinue)
    }
    catch { <# source not registered in classic log #> }
    finally { $ErrorActionPreference = $prevEap }

    return $events
}

# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

Write-Section "RDP Health Check"
Write-Host "Version  : $($script:ScriptVersion) (locale-safe; no DisplayGroup / FilterHashtable)"
Write-Host "Mode     : $(if ($Fix) {'CHECK + FIX'} else {'CHECK ONLY'})"
Write-Host "Computer : $env:COMPUTERNAME"
Write-Host "OS       : $((Get-CimInstance Win32_OperatingSystem).Caption)"

$isAdmin = Test-IsAdmin
if ($Fix -and -not $isAdmin) {
    Write-Error "The -Fix switch requires an elevated (Administrator) PowerShell session."
    exit 1
}
if (-not $isAdmin) {
    Write-Warn "Not running as Administrator — some checks may be incomplete."
}

# ── 1. Remote Desktop enabled ─────────────────────────────────────────────

Write-Section "Remote Desktop Setting"

$tsPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$deny    = Get-RegValue $tsPath 'fDenyTSConnections'

if ($null -eq $deny) {
    Write-Warn "Could not read fDenyTSConnections."
}
elseif ($deny -eq 1) {
    Write-Issue "Remote Desktop is disabled (fDenyTSConnections = 1)."
    Invoke-Fix "Enabled Remote Desktop in registry." {
        Set-ItemProperty -LiteralPath $tsPath -Name 'fDenyTSConnections' -Value 0 -Type DWord -Force
    }
}
else {
    Write-Ok "Remote Desktop is enabled."
}

# ── 2. TermService ────────────────────────────────────────────────────────

Write-Section "Remote Desktop Services (TermService)"

$svc = Get-Service -Name TermService -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Issue "TermService is not installed."
}
else {
    $startMode = (Get-CimInstance Win32_Service -Filter "Name='TermService'" `
                    -ErrorAction SilentlyContinue).StartMode

    if ($svc.Status -ne 'Running') {
        Write-Issue "TermService is $($svc.Status) (startup: $startMode)."
        Invoke-Fix "Started TermService and set startup to Automatic." {
            Set-Service   -Name TermService -StartupType Automatic
            Start-Service -Name TermService
        }
    }
    else {
        Write-Ok "TermService is running."
    }

    if ($startMode -and $startMode -ne 'Auto') {
        Write-Warn "TermService startup type is '$startMode' (recommended: Automatic)."
        Invoke-Fix "Set TermService startup type to Automatic." {
            Set-Service -Name TermService -StartupType Automatic
        }
    }

    $um = Get-Service -Name UmRdpService -ErrorAction SilentlyContinue
    if ($um -and $um.Status -ne 'Running') {
        Write-Issue "UmRdpService is $($um.Status)."
        Invoke-Fix "Started UmRdpService." {
            Set-Service   -Name UmRdpService -StartupType Manual
            Start-Service -Name UmRdpService
        }
    }
    elseif ($um) {
        Write-Ok "UmRdpService is running."
    }
}

# ── 3. Firewall ────────────────────────────────────────────────────────────
# Rule names are used exclusively — DisplayGroup is locale-dependent.

Write-Section "Windows Firewall"

foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
    if ($p.Enabled) { Write-Ok  "Firewall profile '$($p.Name)' is enabled." }
    else            { Write-Warn "Firewall profile '$($p.Name)' is disabled." }
}

# Resolve configured RDP port early so firewall checks use the same port.
$rdpTcpPathEarly = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$configuredPortEarly = Get-RegValue $rdpTcpPathEarly 'PortNumber'
if ($null -ne $configuredPortEarly) { $Port = [int]$configuredPortEarly }

$script:RdpRules = Get-RdpRules -TcpPort $Port

if ($script:RdpRules.Count -eq 0) {
    Write-Issue "No Remote Desktop firewall rules found (by rule Name or TCP port $Port)."
    Invoke-Fix "Enabled or created inbound Remote Desktop firewall rule for port $Port." {
        # Try to enable the canonical rules first — they may exist but be disabled.
        $anyEnabled = $false
        foreach ($n in $script:RdpRuleNames) {
            $r = Get-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
            if ($r) {
                Enable-NetFirewallRule -Name $n -ErrorAction Stop
                $anyEnabled = $true
            }
        }
        # If none of the canonical rules exist at all, create a custom one.
        if (-not $anyEnabled) {
            $customName = 'RemoteDesktop-UserMode-In-TCP-Custom'
            if (-not (Get-NetFirewallRule -Name $customName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule `
                    -Name        $customName `
                    -DisplayName "Remote Desktop - TCP In ($Port)" `
                    -Direction   Inbound `
                    -Protocol    TCP `
                    -LocalPort   $Port `
                    -Action      Allow `
                    -Profile     Any `
                    -Enabled     True | Out-Null
            }
            else {
                Enable-NetFirewallRule -Name $customName -ErrorAction Stop
            }
        }
    }
}
else {
    $script:DisabledRdpRules = @($script:RdpRules | Where-Object { "$($_.Enabled)" -ne 'True' })

    if ($script:DisabledRdpRules.Count -gt 0) {
        Write-Issue "$($script:DisabledRdpRules.Count) Remote Desktop firewall rule(s) are disabled."
        Invoke-Fix "Enabled disabled Remote Desktop firewall rules." {
            foreach ($r in $script:DisabledRdpRules) {
                Enable-NetFirewallRule -Name $r.Name -ErrorAction Stop
            }
        }
    }
    else {
        Write-Ok "Remote Desktop firewall rules are enabled ($($script:RdpRules.Count) rule(s))."
    }
}

# ── 4. Port listener ───────────────────────────────────────────────────────

Write-Section "RDP Port Listener"

$rdpTcpPath = $rdpTcpPathEarly

if (Test-PortListening $Port) {
    Write-Ok "Port $Port is listening."
}
else {
    Write-Issue "Port $Port is not listening."
    Invoke-Fix "Restarted TermService to restore RDP listener." {
        Restart-Service -Name TermService -Force
        Start-Sleep -Seconds 3
        if (-not (Test-PortListening $Port)) {
            throw "Port $Port still not listening after service restart."
        }
    }
}

# ── 5. RDP-Tcp registry ────────────────────────────────────────────────────

Write-Section "RDP-Tcp Configuration"

if (-not (Test-Path -LiteralPath $rdpTcpPath)) {
    Write-Issue "RDP-Tcp registry key is missing."
    Write-Warn  "A missing key may require 'sfc /scannow' or an in-place repair."
}
else {
    Write-Ok "RDP-Tcp registry key exists."
    $nla = Get-RegValue $rdpTcpPath 'UserAuthentication'
    if ($null -ne $nla) {
        if ($nla -eq 1) { Write-Ok   "Network Level Authentication (NLA) is enabled." }
        else            { Write-Warn "Network Level Authentication (NLA) is disabled (UserAuthentication = 0)." }
    }
}

# ── 6. Group Policy override ───────────────────────────────────────────────

Write-Section "Policy Overrides"

$gpoPath  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$gpoDeny  = Get-RegValue $gpoPath 'fDenyTSConnections'

if ($gpoDeny -eq 1) {
    Write-Issue "Group Policy is blocking Remote Desktop (Policies fDenyTSConnections = 1)."
    Write-Warn  "Registry fixes may be overridden until policy is updated (gpupdate /force)."
}
else {
    Write-Ok "No Group Policy block detected."
}

# ── 7. User permission ─────────────────────────────────────────────────────

if ($User) {
    Write-Section "User Permission Check"
    $rdpGroup = Get-RdpUsersGroup
    if (-not $rdpGroup) {
        Write-Warn "Skipped membership check for '$User' (group not found)."
    }
    else {
        $inGroup = Test-InRdpGroup -AccountName $User
        if ($null -eq $inGroup) {
            Write-Warn "Skipped membership check for '$User'."
        }
        elseif (-not $inGroup) {
            Write-Issue "User '$User' is not in $($rdpGroup.Name) (Remote Desktop Users)."
            Invoke-Fix "Added '$User' to $($rdpGroup.Name)." {
                Add-LocalGroupMember -Group $rdpGroup.Name -Member $User -ErrorAction Stop
            }
        }
        else {
            Write-Ok "User '$User' is in $($rdpGroup.Name) (Remote Desktop Users)."
        }
    }
}

# ── 8. Recent event log errors ─────────────────────────────────────────────

Write-Section "Recent Event Log Errors (last 24 h)"

$since      = (Get-Date).AddHours(-24)
$logSources = @(
    'TermService'
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager'
)
$anyEvents = $false

try {
    foreach ($src in $logSources) {
        $evts = Get-RecentProviderEvents -LogName 'System' -ProviderName $src -Since $since -MaxEvents 5

        if ($evts -and $evts.Count -gt 0) {
            $anyEvents = $true
            Write-Warn "Recent $src events:"
            foreach ($e in $evts) {
                $line = ($e.Message -split "`n")[0]
                $when = if ($e.TimeGenerated) { $e.TimeGenerated } else { $e.TimeCreated }
                $id   = if ($e.EventID) { $e.EventID } else { $e.Id }
                Write-Host "       $($when.ToString('yyyy-MM-dd HH:mm'))  Id=$id  $line" `
                    -ForegroundColor DarkYellow
            }
        }
    }
}
catch {
    Write-Warn "Event log check skipped: $($_.Exception.Message)"
}

if (-not $anyEvents) {
    Write-Ok "No recent TermService / RemoteConnectionManager errors in the System log."
}

# ── summary ────────────────────────────────────────────────────────────────

Write-Section "Summary"
Write-Host "Issues found : $script:IssuesFound"
if ($Fix)                          { Write-Host "Issues fixed : $script:IssuesFixed" }
if ($script:Warnings.Count -gt 0)  { Write-Host "Warnings     : $($script:Warnings.Count)" }

if ($script:IssuesFound -eq 0) {
    Write-Host "`nNo RDP configuration issues detected." -ForegroundColor Green
    exit 0
}

if (-not $Fix) {
    Write-Host "`nRe-run as Administrator with -Fix to apply remediations:" -ForegroundColor Yellow
    Write-Host "  .\Fix-RdpErrors.ps1 -Fix" -ForegroundColor Yellow
    exit 2
}

if ($script:IssuesFixed -lt $script:IssuesFound) {
    Write-Host "`nSome issues could not be fixed automatically. Review warnings above." -ForegroundColor Yellow
    exit 3
}

Write-Host "`nRDP checks completed and fixes applied. Try connecting again." -ForegroundColor Green
exit 0
