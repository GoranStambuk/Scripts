<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Script to detect and mitigate web servers, screen overlays, keyloggers, suspicious DLLs, remote thread execution, and unauthorized audio.
                 Runs invisibly without disrupting the calling batch file. While it is not designed to be antivirus replacement, it aims to be 2nd layer of defense for high profile targets.
                 It is a part of larger script suite, called GShield with other scripts offering gaming tweaks and additional tweaks and policies for hardening.
    Version: 5.3
    License: Free for personal use
#>

# Constants
$logonGroup = "Console Logon"
$validGroups = @($logonGroup)
$consoleUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName

# Log function to log messages to a file in the Documents folder
function Write-Log {
    param (
        [string]$message
    )
    $logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\GShield_Log.txt")
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logMessage = "$timestamp - $message"
    try {
    Add-Content -Path $logPath -Value $logMessage
} catch {
    Write-Output "Error writing to log: $_"
   }
}

function Get-ProcessDetailsAndTerminate {
    param (
        [int]$ProcessId
    )

    try {
        # Get process details using the ProcessId
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        $processName = $process.Name
        $processOwner = (Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId").GetOwner().User

        # Log process details before termination
        Write-Log "Detected process to terminate: $processName (PID: $ProcessId), Owner: $processOwner"

        # Optionally, perform additional checks on the process (e.g., if it's not a system process)
        if ($processName -notin @("System", "svchost")) {
            Write-Log "Terminating process: $processName (PID: $ProcessId)"
            Stop-Process -Id $ProcessId -Force
        } else {
            Write-Log "System process detected, skipping termination: $processName (PID: $ProcessId)"
        }
    } catch {
        Write-Log ("Error retrieving details for process ID " + $ProcessId + ": " + $($_.Exception.Message))
    }
}

# Function to check if the process is owned by the Console Logon group (SID: S-1-2-1)
function Is-ProcessFromConsoleLogonGroup {
    $consoleLogonSID = "S-1-2-1"  # Console Logon SID

    # Get all running processes
    $processes = Get-WmiObject Win32_Process

    foreach ($process in $processes) {
        try {
            # Get the SID of the process owner
            $owner = (Get-CimInstance Win32_Process -Filter "ProcessId = '$($process.ProcessId)'").GetOwner()
            $processOwnerSID = (New-Object System.Security.Principal.NTAccount($owner.User)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            # Compare the SID of the process owner with the Console Logon SID
            if ($processOwnerSID -ne $consoleLogonSID) {
                # If the process is not from Console Logon group, terminate it
                Write-Log "Blocking non-console logon process: $($process.Name)"
                Stop-Process -Id $process.ProcessId -Force
            }
        } catch {
            Write-Log "Error retrieving owner for process $($process.ProcessId)."
        }
    }
}

# Function to check and block network connections that aren't from Console Logon group
function Block-NonConsoleLogonGroupNetwork {
    $consoleLogonSID = "S-1-2-1"  # Console Logon SID

    $networkProcesses = Get-NetTCPConnection
    foreach ($connection in $networkProcesses) {
        try {
            # Get the process owner SID
            $process = Get-Process -Id $connection.OwningProcess
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId = '$($process.Id)'").GetOwner()
            $processOwnerSID = (New-Object System.Security.Principal.NTAccount($owner.User)).Translate([System.Security.Principal.SecurityIdentifier]).Value

            if ($processOwnerSID -ne $consoleLogonSID) {
                # Block network connection if process is not from Console Logon group
                Write-Log "Blocking network connection from non-console logon process: $($process.Name) on port $($connection.LocalPort)"
                Stop-Process -Id $process.Id -Force
            }
        } catch {
            Write-Log "Error retrieving network connection owner for process $($connection.OwningProcess)."
        }
    }
}

# Ensure WMI and SharedAccess services are running
function Ensure-ServicesRunning {
    # Ensure WMI service is running
    $wmiService = Get-Service -Name "winmgmt" -ErrorAction SilentlyContinue
    if ($wmiService -and $wmiService.Status -ne "Running") {
        Start-Service -Name "winmgmt" -ErrorAction SilentlyContinue
        Write-Log "WMI service started."
    } elseif (-not $wmiService) {
        Write-Log "WMI service not found. Check system integrity."
    } else {
        Write-Log "WMI service is running."
    }

    # Ensure SharedAccess (Windows Firewall) service is running
    $sharedAccessService = Get-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
    if ($sharedAccessService -and $sharedAccessService.Status -ne "Running") {
        Start-Service -Name "sharedaccess" -ErrorAction SilentlyContinue
        Write-Log "SharedAccess (Windows Firewall) service started."
    } elseif (-not $sharedAccessService) {
        Write-Log "SharedAccess service not found. Check system integrity."
    } else {
        Write-Log "SharedAccess service is running."
    }
}

# Remove suspicious dll's
function Monitor-LoadedDLLs {
    function Write-Log {
        param ($Message)
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Add-Content -Path "C:\Temp\DLLMonitor.log" -Value "$Timestamp - $Message"
    }

    Write-Log "Monitoring all loaded DLLs system-wide."

    $processes = Get-Process | Where-Object { $_.ProcessName -ne "Idle" }

    foreach ($process in $processes) {
        try {
            $modules = $process.Modules
            foreach ($module in $modules) {
                try {
                    $cert = Get-AuthenticodeSignature $module.FileName
                    if ($cert.Status -ne "Valid") {
                        Write-Log "Removing suspicious DLL: $($module.FileName)"
                        Remove-Item -Path $module.FileName -Force -ErrorAction Stop
                    }
                } catch {
                    Write-Log "Error checking DLL $($module.FileName): $_"
                }
            }
        } catch {
            Write-Log "Skipping process $($process.ProcessName): $_"
        }
    }
}


# Function to monitor for suspicious screen overlays and trace their sources
function Monitor-Overlays {
    # Get a list of processes with visible windows, excluding whitelisted processes
    $windows = Get-Process | Where-Object {
        $_.MainWindowTitle -ne ""
    }

    foreach ($window in $windows) {
        Write-Log "Potential screen overlay or UI hijacker detected: $($window.ProcessName)"
        # Call the new function to get process details and terminate the process and parent
        Get-ProcessDetailsAndTerminate -ProcessId $window.Id
    }
}

# Function to detect potential keyloggers by monitoring keyboard hooks
function Detect-Keyloggers {
    Write-Log "Checking for keylogger behavior."
    $suspiciousProcesses = Get-WmiObject Win32_Process | Where-Object {
        ($_.CommandLine -match "SetWindowsHookEx" -or $_.CommandLine -match "GetAsyncKeyState")
    }
    foreach ($proc in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($proc.Name) - $($proc.CommandLine)"
    }
}

# Enhanced keylogger detection
function Monitor-Keyloggers {
    # Get processes that might be keyloggers based on behavior
    $suspiciousProcesses = Get-Process | Where-Object {
        ($_.Modules.ModuleName -match "hook|key|log|capture|sniff") -or
        ($_.Path -match "keylogger|hook|log|capture|sniff") -or
        (Get-Process -Id $_.Id -Module | Where-Object { $_.ModuleName -match "keylogger|hook|log|capture|sniff" })
    }

    foreach ($process in $suspiciousProcesses) {
        Write-Log "Potential keylogger detected: $($process.ProcessName)"
        Get-ProcessDetailsAndTerminate -ProcessId $process.Id
    }
}

# Function to detect and terminate unauthorized web servers
function Detect-And-Terminate-WebServers {
    $webServerPorts = @(80, 443) # Common web server ports

    # Get active network connections on web server ports
    $connections = Get-NetTCPConnection | Where-Object {
        $_.LocalPort -in $webServerPorts -and $_.State -eq "Listen"
    }

    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Log "Unauthorized web server detected: $($process.Name) on Port $($connection.LocalPort)"
            # Call the new function to get process details and terminate the process and parent
            Get-ProcessDetailsAndTerminate -ProcessId $process.Id
        }
    }
}

# Function to prevent remote thread execution
function Prevent-RemoteThreadExecution {
    $remoteThreads = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match "remote" }
    foreach ($thread in $remoteThreads) {
        Write-Log "Preventing remote thread execution for Process: $($thread.ProcessId)"
        Stop-Process -Id $thread.ProcessId -Force
    }
}

# Function to detect and block remote logins
function Block-RemoteLogins {
    $remoteSessions = Get-CimInstance -Class Win32_ComputerSystem | Select-Object UserName
    if ($remoteSessions.UserName) {
        Write-Log "Remote login detected, logging off the user."
        Shutdown.exe /l
    }
}

# Function to detect and terminate rootkit-like behaviors
function Monitor-Rootkit {
    # Look for hidden processes, modules, or files
    $hiddenProcesses = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $null }

    foreach ($process in $hiddenProcesses) {
        Write-Log "Suspicious hidden process detected: $($process.ProcessName). Terminating process."
        Stop-Process -Name $process.ProcessName -Force
    }

    $hiddenFiles = Get-ChildItem -Path "C:\Windows\System32" -Recurse | Where-Object { $_.Attributes -match "Hidden" }
    foreach ($file in $hiddenFiles) {
        Write-Log "Hidden file detected: $($file.FullName). Quarantining file."
        Move-Item -Path $file.FullName -Destination "C:\Backup\Quarantined" -Force
    }
}

# Function to scan memory for suspicious activity and terminate related processes
function Scan-MemoryForMalware {
    $suspiciousPatterns = @("malware", "inject", "hook")
    $memoryDump = Get-CimInstance -Query "SELECT * FROM Win32_Process"

    foreach ($process in $memoryDump) {
        $processName = $process.Name
        foreach ($pattern in $suspiciousPatterns) {
            if ($processName -match $pattern) {
                Write-Log "Suspicious memory pattern detected in process: $processName. Terminating process."
                Stop-Process -Name $processName -Force
            }
        }
    }
}

# Function to monitor audio processes
function Monitor-AudioProcesses {
    Write-Output "Starting audio process monitoring..."

    # Function to check if a process belongs to the allowed user
    function Is-AllowedUser {
        param (
            [string]$ProcessId
        )
        try {
            $owner = (Get-WmiObject Win32_Process -Filter "ProcessId = $ProcessId").GetOwner().User
            return $owner -eq $consoleUser
        } catch {
            return $false
        }
    }

    # Function to mute unauthorized audio processes
    function Mute-UnallowedProcesses {
        $audioProcesses = Get-Process | Where-Object { $_.ProcessName -match ".*audio.*" }
        foreach ($process in $audioProcesses) {
            if (-not (Is-AllowedUser -ProcessId $process.Id)) {
                Write-Output "Muting unauthorized process: $($process.ProcessName)"
                # Set system volume to mute (example for system-wide control)
                [AudioControl]::waveOutSetVolume([IntPtr]::Zero, 0x00000000) | Out-Null
            }
        }
    }
}

# Function to corrupt telemetry data
function Corrupt-Telemetry {
    $TargetFiles = @(
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener_1.etl",
        "$env:ProgramData\Microsoft\Diagnosis\ETLLogs\ShutdownLogger.etl",
        "$env:LocalAppData\Microsoft\Windows\WebCache\WebCacheV01.dat"
    )

    Function Overwrite-File {
        param ($FilePath)
        if (Test-Path $FilePath) {
            $Size = (Get-Item $FilePath).length
            $Junk = [byte[]]::new($Size)
            (New-Object Random).NextBytes($Junk)
            [System.IO.File]::WriteAllBytes($FilePath, $Junk)
        }
    }

    While ($true) {
        foreach ($File in $TargetFiles) {
            Overwrite-File -FilePath $File
        }
   }
}

# Paths to cookie files for popular browsers
$BrowserPaths = @{
    "Chrome"    = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies";
    "Edge"      = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies";
    "Firefox"   = "$env:APPDATA\Mozilla\Firefox\Profiles\*\cookies.sqlite";
    "Opera"     = "$env:APPDATA\Opera Software\Opera Stable\Cookies";
    "Brave"     = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cookies";
    "Vivaldi"   = "$env:LOCALAPPDATA\Vivaldi\User Data\Default\Cookies";
}

# Backup directory for cookies
$BackupDir = "$env:USERPROFILE\CookieBackups"
if (!(Test-Path $BackupDir)) {
    try {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    } catch {
        Write-Log "Error creating backup directory: $_"
    }
}

# Backup and monitor cookie files
function BackupAndMonitorCookies {
    foreach ($Browser in $BrowserPaths.Keys) {
        $CookiePath = $BrowserPaths[$Browser]

        # Expand wildcard for Firefox profiles
        if ($CookiePath -like "*\*") {
            $CookiePath = Get-ChildItem -Path $CookiePath -File -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (Test-Path $CookiePath) {
            $BackupPath = Join-Path -Path $BackupDir -ChildPath "$Browser-Cookies.bak"

            # Copy cookie file to backup location
            Copy-Item -Path $CookiePath -Destination $BackupPath -Force
            Write-Output "Backed up and protected cookies for $Browser."
        } else {
            Write-Output "Cookie file for $Browser not found."
        }
    }

    # Monitor for unauthorized changes
    Monitor-CookieFiles
}

# Monitor cookie files for changes
function Monitor-CookieFiles {
    $FileSystemWatcher = New-Object System.IO.FileSystemWatcher
    $FileSystemWatcher.Path = $BackupDir
    $FileSystemWatcher.Filter = "*.bak"
    $FileSystemWatcher.IncludeSubdirectories = $false
    $FileSystemWatcher.EnableRaisingEvents = $true

    $FileSystemWatcher.Changed += {
        Write-Output "Detected unauthorized changes to $($_.FullPath). Restoring backup..."
        RestoreCookies
    }

    $FileSystemWatcher.Deleted += {
        Write-Output "Backup deleted: $($_.FullPath). Recreating backup..."
        BackupAndMonitorCookies
    }

    Write-Output "Monitoring cookie files for changes..."
}

# Restore cookies from backup
function RestoreCookies {
    foreach ($Backup in Get-ChildItem -Path $BackupDir -Filter "*.bak") {
        $Browser = ($Backup.Name -split "-")[0]
        $OriginalPath = $BrowserPaths[$Browser]

        if ($OriginalPath -like "*\*") {
            $OriginalPath = Get-ChildItem -Path $OriginalPath -File -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if (Test-Path $OriginalPath) {
            Copy-Item -Path $Backup.FullName -Destination $OriginalPath -Force
            Write-Output "Restored cookies for $Browser."
        }
    }
}

# Kill VM's
function StopVirtualMachines {
    param (
        [scriptblock]$Action = {
            $vmProcesses = "vmware", "VirtualBox", "qemu", "hyperv", "vboxheadless"

            Get-Process | Where-Object { $_.ProcessName -match ($vmProcesses -join "|") } | ForEach-Object {
                Write-Output "Stopping VM process: $($_.ProcessName)"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }
    )

    Invoke-Command -ScriptBlock $Action
}

# Define regex patterns for ad domains
$adRegexPatterns = @(
    # From BlockAds.pac
    "^(.+[-_.])?(ads?|banners?|track(er|ing)?|doubleclick|adservice|adnxs|adtech|googleads|partner|sponsor|clicks|pop(up|under)|promo|marketing|affiliates?|metrics|statcounter|analytics|pixel)",

    # Additional patterns
    "(.*\.|^)((think)?with)?google($|((adservices|apis|mail|static|syndication|tagmanager|tagservices|usercontent|zip|-analytics)($|\..+))",
    "(.*\.|^)g(gpht|mail|static|v(t[12])?)($|\..+)",
    "(.*\.|^)chrom(e(experiments)?|ium)($|\..+)",
    "(.*\.|^)ampproject($|\..+)",
    "(.*\.|^)doubleclick($|\..+)",
    "(.*\.|^)firebaseio($|\..+)",
    "(.*\.|^)googlevideo($|\..+)",
    "(.*\.|^)waze($|\..+)",
    "(.*\.|^)y(outube|timg)($|\..+)",
    "^r[0123456789]+((-{3})|(.))sn-.{8}.googlevideo.com$",
    ".*[`^.`]googlevideo.com$",
    ".*[`^.`]l.google.com$"
)

# Combine all regex patterns into a single regex
$combinedRegex = $adRegexPatterns -join "|"

# Function to check if a domain matches any of the regex patterns
function IsAdDomain($domain) {
    return $domain -match $combinedRegex
}

# Function to block ad domains in real-time
function BlockAds {
    while ($true) {
        # Get active network connections
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }

        foreach ($connection in $connections) {
            $remoteAddress = $connection.RemoteAddress
            $remotePort = $connection.RemotePort

            # Resolve the remote address to a domain name
            try {
                $domain = [System.Net.Dns]::GetHostEntry($remoteAddress).HostName
            } catch {
                continue
            }

            # Check if the domain matches any ad-related regex
            if (IsAdDomain $domain) {
                # Block the connection by terminating it
                Write-Host "Blocking ad domain: $domain"
                Stop-Process -Id $connection.OwningProcess -Force
            }
        }
    }
}

# Infinite loop to run the functions
function Run-Monitoring {
    Ensure-ServicesRunning
    Monitor-LoadedDLLs
    Monitor-AudioProcesses
    Monitor-Keyloggers
    Monitor-Overlays
    Monitor-Rootkit
    Detect-Keyloggers
    Detect-And-Terminate-WebServers
    Prevent-RemoteThreadExecution
    Block-RemoteLogins
    Scan-MemoryForMalware
    BackupAndMonitorCookies
    Block-NonConsoleLogonGroupNetwork
    CorruptTelemetry
    StopVirtualMachines
    BlockAds
}

# Continuously run the script
Start-Job -ScriptBlock {
    Run-Monitoring
}
