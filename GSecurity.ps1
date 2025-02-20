<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Enhanced version of GSecurity script with optimized performance, improved logging, and stronger threat detection.
    Version: 6.1
    License: Free for personal use
#>

# Constants
$activeSessionUser = (Get-CimInstance -Class Win32_ComputerSystem).UserName
$consoleUser = New-Object System.Security.Principal.SecurityIdentifier("S-1-2-1")
$logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\GShield_Log.txt")

# Log function with timestamp and log rotation
function Write-Log {
    param ([string]$message)
    $timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    $logEntry = "[$timestamp] $message"
    Add-Content -Path $logPath -Value $logEntry
    
    # Rotate log if size exceeds 5MB
    if ((Get-Item $logPath).Length -gt 5MB) {
        Move-Item -Path $logPath -Destination "$logPath.bak" -Force
    }
}

function CheckAndQuarantineUnsignedModules {
    # Path to quarantine folder (ensure this folder exists)
    $quarantinePath = "C:\Quarantine"

    # Create quarantine folder if it doesn't exist
    if (-not (Test-Path $quarantinePath)) {
        New-Item -Path $quarantinePath -ItemType Directory
    }

    # Get all processes running on the system
    $processes = Get-Process -IncludeUserName

    foreach ($process in $processes) {
        try {
            # Skip processes without modules (e.g., system processes)
            if ($process.Modules.Count -eq 0) { continue }

            # Iterate over all modules of the current process
            foreach ($module in $process.Modules) {
                try {
                    # Check if the module has a valid certificate
                    $cert = Get-AuthenticodeSignature $module.FileName

                    # If the certificate is not valid or signed, handle it
                    if ($cert.Status -ne 'Valid') {
                        Write-Host "Module $($module.FileName) is unsigned or invalid."

                        # Forcefully unload the module (this can be tricky and might need more sophisticated handling)
                        Stop-Process -Id $process.Id -Force

                        # Move module to quarantine
                        $destinationPath = Join-Path $quarantinePath $(Split-Path $module.FileName -Leaf)
                        Move-Item -Path $module.FileName -Destination $destinationPath -Force
                        Write-Host "Moved $($module.FileName) to quarantine."

                        # Optionally, you could also add logging here.
                    }
                } catch {
                    Write-Host "Error checking module $($module.FileName): $_"
                }
            }
        } catch {
            Write-Host "Error processing process $($process.Id): $_"
        }
    }
}

# Monitor for unauthorized remote access
function Monitor-RemoteAccess {
    $remoteProcesses = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1" }
    foreach ($conn in $remoteProcesses) {
        Write-Log "Remote connection detected: $($conn.RemoteAddress):$($conn.RemotePort)"
        Stop-Process -Id (Get-Process -Id $conn.OwningProcess).Id -Force
    }
}

# Monitor LSASS memory access for credential theft
function Protect-LSASS {
    $lsass = Get-Process -Name lsass -ErrorAction SilentlyContinue
    if ($lsass) {
        Set-ProcessMitigation -Name lsass -Enable DEP, ASLR, CFG
        Write-Log "LSASS protection enabled."
    }
}

# Monitor for screen overlays
function Detect-Overlays {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class OverlayDetect {
        [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] public static extern IntPtr FindWindowEx(IntPtr parent, IntPtr child, string className, string windowName);
    }
"@
    $window = [OverlayDetect]::GetForegroundWindow()
    $overlay = [OverlayDetect]::FindWindowEx($window, [IntPtr]::Zero, "#32770", $null)
    if ($overlay -ne [IntPtr]::Zero) {
        Write-Log "Potential screen overlay detected."
    }
}

# Key scrambling function to disrupt keyloggers
function Scramble-Keys {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    public class KeyScramble {
        [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
        public static void Scramble() {
            Random rand = new Random();
            for (int i = 0; i < 255; i++) {
                if (GetAsyncKeyState(i) != 0) {
                    System.Threading.Thread.Sleep(rand.Next(1, 5));
                }
            }
        }
    }
"@
    [KeyScramble]::Scramble()
    Write-Log "Key scrambling executed."
}

# Detect and terminate keyloggers
function Monitor-Keyloggers {
    $suspiciousProcesses = Get-WmiObject Win32_Process | Where-Object {
        $_.CommandLine -match "GetAsyncKeyState|SetWindowsHookEx|keylog"
    }
    foreach ($proc in $suspiciousProcesses) {
        Write-Log "Keylogger detected and terminated: $($proc.Name) (PID: $($proc.ProcessId))"
        Stop-Process -Id $proc.ProcessId -Force
    }
}

# Ensure the RunAsPPL registry setting is enabled for LSASS
function Enable-RunAsPPL {
    $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
    $regValue = "RunAsPPL"
    $value = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
    if ($value -eq $null -or $value.$regValue -ne 1) {
        Set-ItemProperty -Path $regPath -Name $regValue -Value 1
        Write-Log "RunAsPPL enabled for LSASS to prevent memory dumping."
    }
}

# Function to disable all audio devices for non-console users
function Disable-AudioForNonConsoleUsers {
    # Check if the active session user is not the console user
    if ($activeSessionUser -ne $consoleUser) {
        # Get all audio devices (input and output)
        $audioDevices = Get-WmiObject -Class Win32_SoundDevice

        # Disable all audio devices
        foreach ($device in $audioDevices) {
            try {
                Write-Log "Disabling audio device: $($device.DeviceID) due to non-console user: $activeSessionUser"
                $device.Disable()
            } catch {
                Write-Log "Failed to disable audio device $($device.DeviceID): $_"
            }
        }
    } else {
        Write-Log "Console user detected, audio remains enabled."
    }
}

# Define the path to the setup scripts directory
$setupScriptsPath = Join-Path $env:windir "setup\scripts"

# List of common web server processes (including parental control apps)
$webServerNames = @(
    "iis", "httpd", "nginx", "tomcat", "apache", 
    "XAMPP", "lighttpd", "node.exe", "python.exe", 
    "openresty", "jetty", "caddy", "uwsgi", "php", 
    "mscorsvw.exe", "vpnagent.exe", "parentalcontrol", 
    "norton", "mcafee", "kaspersky", "bitdefender", 
    "openvpn", "pfsense", "pfctl", "webroot", "trendmicro", 
    "avast", "comodo", "sophos", "fortigate", "webshield"
)

# Function to list web servers running on ports 80, 8080, and 443
function List-WebServers {
    Write-Host "Listing Web Servers running on ports 80, 8080, and 443..."

    # Get the netstat output for all processes and filter for ports 80, 8080, and 443
    $netstatOutput = netstat -ano | Select-String "(\d+\.\d+\.\d+\.\d+:\d+|\[::\])" 

    # Process each line of netstat output
    $webServers = @()
    foreach ($line in $netstatOutput) {
        # Check if the line contains the desired ports (80, 8080, or 443)
        if ($line.Line -match ":(80|8080|443)\s+") {
            # Extract PID from the netstat output
            $pid = ($line -split "\s+")[4]

            # Get process information using the PID
            $process = Get-WmiObject Win32_Process | Where-Object { $_.ProcessId -eq $pid }

            if ($process) {
                # Get the executable path of the process
                $exePath = $process.ExecutablePath
                $webServers += [PSCustomObject]@{
                    PID           = $process.ProcessId
                    Name          = $process.Name
                    ExecutablePath = $exePath
                    ListeningPort = ($line -split "\s+")[1]
                }
            }
        }
    }

    # Output the list of web servers
    if ($webServers.Count -gt 0) {
        $webServers | Format-Table -Property PID, Name, ExecutablePath, ListeningPort
    } else {
        Write-Host "No web servers found running on ports 80, 8080, or 443."
    }

    return $webServers
}

# Function to check and terminate web servers not executing from the setup scripts directory
function CheckAndTerminate-WebServers {
    # Get the list of all web server processes
    $webServers = List-WebServers

    # Iterate through each server and terminate those not running from the setup folder
    foreach ($webServer in $webServers) {
        if ($webServer.ExecutablePath -notlike "$setupScriptsPath*") {
            Write-Host "Terminating process: $($webServer.Name) with PID $($webServer.PID), running from $($webServer.ExecutablePath)"
            # Terminate the process
            Stop-Process -Id $webServer.PID -Force
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

# Function to detect and block remote logins
function Block-RemoteLogins {
    $remoteSessions = Get-CimInstance -Class Win32_ComputerSystem | Select-Object UserName
    if ($remoteSessions.UserName) {
        Write-Log "Remote login detected, logging off the user."
        Shutdown.exe /l
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

# Main execution loop (event-driven)
function Run-Monitoring {
    while ($true) {
        Block-RemoteLogins
	BackupAndMonitorCookies
	Monitor-RemoteAccess
        Ensure-ServicesRunning
	Protect-LSASS
        Detect-Overlays
        Scramble-Keys
        Monitor-Keyloggers
        CheckAndTerminate-WebServers
        StopVirtualMachines
	Start-Sleep -Seconds 60
    }
}

# Run the function
function Run-Monitor {
    while ($true) {
        Monitor-Rootkit
	Scan-MemoryForMalware
	CheckAndQuarantineUnsignedModules
	Disable-AudioForNonConsoleUsers
    }
}

# Start the monitoring script as a background job
Start-Job -ScriptBlock {
    Run-Monitoring
    Run-Monitor
}
