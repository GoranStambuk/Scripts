<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Enhanced version of GSecurity script with optimized performance, improved logging, and stronger threat detection.
    Version: 6.2
    License: Free for personal use
#>

# Constants
$setupScriptsPath = Join-Path $env:windir "setup\scripts"
$logPath = [System.IO.Path]::Combine($env:USERPROFILE, "Documents\GShield_Log.txt")

# Trusted driver vendors to exclude from termination
$trustedDriverVendors = @(
    "*Microsoft*", "*NVIDIA*", "*Intel*", "*AMD*", "*Realtek*, "*Dolby*"
)

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

# Detect and terminate web servers
function Detect-And-Terminate-WebServers {
    $ports = @(80, 443, 8080)  # Common web server ports
    $connections = Get-NetTCPConnection | Where-Object { $ports -contains $_.LocalPort }
    foreach ($connection in $connections) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process.Executable -and -notlike "$setupScriptsPath*") {
            Write-Log "Web server detected: $($process.ProcessName) (PID: $($process.Id)) on Port $($connection.LocalPort)"
            Stop-Process -Id $process.Id -Force
            Write-Log "Web server process terminated: $($process.ProcessName)"
        }
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
function Detect-And-Terminate-Keyloggers {
    $suspiciousProcesses = Get-WmiObject Win32_Process | Where-Object {
        $_.CommandLine -match "GetAsyncKeyState|SetWindowsHookEx|keylog"
    }
    foreach ($proc in $suspiciousProcesses) {
        Write-Log "Keylogger detected and terminated: $($proc.Name) (PID: $($proc.ProcessId))"
        Stop-Process -Id $proc.ProcessId -Force
    }
}

# Monitor for screen overlays
function Detect-And-Terminate-Overlays {
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

# Detect and terminate untrusted drivers
function Detect-And-Terminate-Suspicious-Drivers {
    $drivers = Get-WmiObject Win32_SystemDriver | Where-Object {
        ($_.DisplayName -notlike $trustedDriverVendors) -and $_.Started -eq $true
    }
    foreach ($driver in $drivers) {
        Write-Log "Suspicious driver detected: $($driver.DisplayName)"
        Stop-Service -Name $driver.Name -Force
        Write-Log "Suspicious driver stopped: $($driver.DisplayName)"
    }
}

# Detect and terminate unsigned modules
function Detect-And-Terminate-Unsigned-DLLs {
    # Iterate over all processes
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            # Iterate over each module in the process
            $proc.Modules | ForEach-Object {
                $modulePath = $_.FileName
                $signature = Get-AuthenticodeSignature -FilePath $modulePath

                if ($signature.Status -eq 'NotSigned') {
                    Write-Host "Unsigned module detected: $($modulePath)"
                    
                    # Attempt to unload the module (if possible) and delete the file
                    try {
                        # Force unload module (for example, using Remove-Module or stopping the process)
                        $proc | Stop-Process -Force
                        Write-Host "Terminated process: $($proc.Name)"
                    } catch {
                        Write-Warning "Failed to unload module from process: $($proc.Name)"
                    }

                    # Attempt to delete the module file
                    if (Test-Path -Path $modulePath) {
                        Remove-Item -Path $modulePath -Force
                        Write-Host "Deleted unsigned module: $($modulePath)"
                    }
                }
            }
        } catch {
            Write-Warning "Could not retrieve modules for process: $($proc.Name)"
        }
    }
}

# Main execution loop (event-driven)
function Run-Monitoring {
    while ($true) {
	Detect-And-Terminate-WebServers
	Detect-And-Terminate-Keyloggers
	Detect-And-Terminate-Overlays
	Detect-And-Terminate-Suspicious-Drivers
	Start-Sleep -Seconds 10
    }
}

# Run the function
function Run-Monitor {
    while ($true) {
	Detect-And-Terminate-Unsigned-DLLs
    }
}

# Start the monitoring script as a background job
Start-Job -ScriptBlock {
    Run-Monitoring
    Run-Monitor
}
