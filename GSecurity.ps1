<#
    Script Name: GSecurity
    Author: Gorstak
    Description: Enhanced version of GSecurity script with optimized performance, improved logging, and stronger threat detection.
    Version: 8.0
    License: Free for personal use
#>

# Constants
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

function Stop-ProcessesOnPortsNotInSetupScripts {
    # Define the allowed directory
    $allowedDirectory = Join-Path -Path $env:windir -ChildPath "Setup\Scripts"

    # Define the ports to monitor
    $portsToMonitor = @(80, 8080, 443)

    # Get processes using the specified ports
    $portProcesses = @()
    foreach ($port in $portsToMonitor) {
        # Use netstat to find processes listening on the specified ports
        $netstatOutput = netstat -ano | Select-String ":$port\s"
        foreach ($line in $netstatOutput) {
            $pid = ($line -split '\s+')[-1]  # Extract the PID from the netstat output
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                $portProcesses += $process
            }
        }
    }

    # Terminate processes not in the allowed directory
    foreach ($process in $portProcesses) {
        # Get the full path of the executable (if available)
        $processPath = $process.Path

        # Check if the process is not in the allowed directory
        if ($processPath -and -not ($processPath -like "$allowedDirectory\*")) {
            Write-Host "Terminating process: $($process.ProcessName) (PID: $($process.Id)) - Executable: $processPath"
            Stop-Process -Id $process.Id -Force
        }
    }
}

function Remove-UnsignedDlls {
    # Define the quarantine folder path
    $quarantineFolder = "C:\Quarantine"

    # Create the quarantine folder if it doesn't exist
    if (-not (Test-Path -Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder | Out-Null
        Write-Host "Quarantine folder created at: $quarantineFolder"
    }

    # Get the current process
    $process = Get-Process -Id $pid

    # Get all loaded modules (DLLs) in the current process
    $loadedDlls = $process.Modules

    foreach ($dll in $loadedDlls) {
        $dllPath = $dll.FileName

        # Check if the DLL has a valid digital signature
        $signature = Get-AuthenticodeSignature -FilePath $dllPath

        if ($signature.Status -ne "Valid") {
            Write-Host "Unsigned DLL found: $dllPath"
            
            # Attempt to unload the DLL (this is risky and may not always work)
            try {
                $moduleHandle = $dll.BaseAddress
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($moduleHandle)
                Write-Host "Successfully unloaded: $dllPath"

                # Move the DLL to the quarantine folder
                $dllFileName = Split-Path -Leaf $dllPath
                $quarantinePath = Join-Path -Path $quarantineFolder -ChildPath $dllFileName
                Move-Item -Path $dllPath -Destination $quarantinePath -Force
                Write-Host "Moved to quarantine: $quarantinePath"
            } catch {
                Write-Host "Failed to unload: $dllPath"
            }
        } else {
            Write-Host "Signed DLL: $dllPath"
        }
    }
}

# Delete known bad files
function Block-FileByMD5 {
    param (
        [string[]]$BlockedMD5s,
        [switch]$Delete,  # If specified, delete matching files
        [switch]$Quarantine  # If specified, move to quarantine folder
    )
    
    # Ensure at least one action is chosen
    if (-not ($Delete -or $Quarantine)) {
        Write-Host "Specify either -Delete or -Quarantine to take action." -ForegroundColor Red
        return
    }
    
    $QuarantinePath = "C:\Quarantine"
    if ($Quarantine -and -not (Test-Path $QuarantinePath)) {
        New-Item -ItemType Directory -Path $QuarantinePath | Out-Null
    }
    
    # Get all local, removable, and network drives
    $Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -match "^[A-Z]:\\$" }
    
    foreach ($Drive in $Drives) {
        Get-ChildItem -Path $Drive.Root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $file = $_.FullName
            try {
                $md5 = (Get-FileHash -Path $file -Algorithm MD5).Hash.ToLower()
                if ($BlockedMD5s -contains $md5) {
                    if ($Delete) {
                        Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                        Write-Host "Deleted: $file" -ForegroundColor Yellow
                    } elseif ($Quarantine) {
                        $dest = Join-Path -Path $QuarantinePath -ChildPath $_.Name
                        Move-Item -Path $file -Destination $dest -Force -ErrorAction SilentlyContinue
                        Write-Host "Quarantined: $file" -ForegroundColor Cyan
                    }
                }
            } catch {
                Write-Host "Error scanning $file: $_" -ForegroundColor Red
            }
        }
    }
}

# Example usage
Block-FileByMD5 -BlockedMD5s @("2131f5b6da23b52cb4bbca834fa0b0a1") -Delete
Block-FileByMD5 -BlockedMD5s @("2c1657253a1808551d38b3ec272771d9") -Delete
Block-FileByMD5 -BlockedMD5s @("55c8e69dab59e56951d31350d7a94011") -Delete
Block-FileByMD5 -BlockedMD5s @("448b345bcac7ec3729f291229c942060") -Delete
Block-FileByMD5 -BlockedMD5s @("245d37b8e3ca1ffdcc215cde242217de") -Delete


# Import necessary .NET assemblies
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class KeyScrambler {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    public static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
        if (nCode >= 0 && wParam == (IntPtr)0x100) { // WM_KEYDOWN
            int vkCode = Marshal.ReadInt32(lParam);
            Console.WriteLine("Key pressed: " + (Keys)vkCode);
            // Scramble keypress by sending a random key
            Random rand = new Random();
            int randomKey = rand.Next(65, 90); // Random uppercase letter
            SendKeys.SendWait(((char)randomKey).ToString());
            return (IntPtr)1; // Block the original keypress
        }
        return CallNextHookEx(IntPtr.Zero, nCode, wParam, lParam);
    }

    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;

    public static void Start() {
        _hookID = SetHook(_proc);
    }

    public static void Stop() {
        UnhookWindowsHookEx(_hookID);
    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc) {
        using (var curProcess = System.Diagnostics.Process.GetCurrentProcess())
        using (var curModule = curProcess.MainModule) {
            return SetWindowsHookEx(13, proc, GetModuleHandle(curModule.ModuleName), 0);
        }
    }
}
"@

# Function to detect suspicious processes
function Detect-SuspiciousProcesses {
    $suspiciousProcesses = @()

    # Get all running processes
    $processes = Get-Process

    foreach ($process in $processes) {
        # Heuristic 1: Processes with no visible window and high CPU usage
        if ($process.MainWindowHandle -eq 0 -and $process.CPU -gt 10) {
            $suspiciousProcesses += $process
        }

        # Heuristic 2: Processes with unusual parent processes
        $parentProcess = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $($process.Id)" | Select-Object -ExpandProperty ParentProcessId
        if ($parentProcess -ne $null -and $parentProcess -ne 0) {
            $parentName = (Get-Process -Id $parentProcess).ProcessName
            if ($parentName -notin @("explorer.exe", "svchost.exe", "wininit.exe")) {
                $suspiciousProcesses += $process
            }
        }
    }

    return $suspiciousProcesses
}

# Function to terminate suspicious processes
function Terminate-SuspiciousProcesses {
    $suspiciousProcesses = Detect-SuspiciousProcesses

    foreach ($process in $suspiciousProcesses) {
        Write-Host "Detected suspicious process: $($process.ProcessName) (PID: $($process.Id))"
        try {
            Stop-Process -Id $process.Id -Force
            Write-Host "Successfully terminated suspicious process: $($process.ProcessName) (PID: $($process.Id))"
        } catch {
            Write-Host "Failed to terminate suspicious process: $($process.ProcessName) (PID: $($process.Id))"
        }
    }
}

# Function to scramble keypresses
function Start-KeyScrambler {
    [KeyScrambler]::Start()
    Write-Host "Key scrambler started. Press any key to stop..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    [KeyScrambler]::Stop()
    Write-Host "Key scrambler stopped."
}

# Run the function
function Run-Monitor {
    while ($true) {
	Terminate-SuspiciousProcesses
	Start-KeyScrambler
	Remove-UnsignedDlls
    }
}

# Start the monitoring script as a background job
Start-Job -ScriptBlock {
    Run-Monitor
}
