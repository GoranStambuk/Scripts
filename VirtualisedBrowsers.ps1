#Requires -RunAsAdministrator

# Function to check if the specified process is already running in a virtualized environment
function IsVirtualizedProcess([string]$processName) {
    $virtualizedProcesses = Get-AppvClientPackage | Get-AppvClientProcess
    return $virtualizedProcesses.Name -contains $processName
}

# Function to launch a process in a virtualized environment using App-V
function LaunchVirtualizedProcess([string]$executablePath) {
    if (Test-Path $executablePath) {
        Write-Host "Launching virtualized process: $executablePath"
        Start-AppvVirtualProcess -AppvClientObject Get-AppvClientPackage -AppvVirtualPath $executablePath
    } else {
        Write-Host "Error: Virtualized browser executable not found at $executablePath"
    }
}

# Function to enable App-V feature
function EnableAppV {
    $enableAppVScript = ".\EnableAppV.ps1"

    # Check if the execution policy allows running scripts
    $currentExecutionPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentExecutionPolicy -ne "Unrestricted") {
        Write-Host "Execution policy prevents running scripts. Changing execution policy..."
        Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
    }

    # Run the script with administrative privileges to enable App-V
    Write-Host "Enabling App-V feature..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$enableAppVScript`"" -Verb RunAs -Wait

    # Restore the original execution policy
    Set-ExecutionPolicy -ExecutionPolicy $currentExecutionPolicy -Scope Process -Force
}

# Function to add the script to Windows startup folder
function AddToStartup {
    $scriptPath = $MyInvocation.MyCommand.Definition
    $startupFolderPath = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupFolderPath "VirtualisedBrowsers.lnk"

    if (-Not (Test-Path $shortcutPath)) {
        Write-Host "Adding script to startup..."
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        
        # Correct syntax for the TargetPath property
        $shortcut.TargetPath = "powershell.exe"
        $shortcut.Arguments = "-File `"$scriptPath`""
        
        $shortcut.Save()
    }
}

# Function to check if the script is already added to startup
function IsInStartup {
    $shortcutPath = Join-Path ([Environment]::GetFolderPath("Startup")) "VirtualisedBrowsers.lnk"
    return Test-Path $shortcutPath
}

# Check if the script is already added to startup
if (-Not (IsInStartup)) {
    AddToStartup
}

# Detect installed browsers and virtualize them
$installedBrowsers = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                     Where-Object { $_.DisplayName -match "chrome|firefox|msedge|opera|waterfox|chromium|ur|vivaldi" } |
                     Select-Object -ExpandProperty DisplayName

foreach ($browser in $installedBrowsers) {
    if (-Not (IsVirtualizedProcess "$browser.exe")) {
        # Check if App-V is enabled, and enable it if necessary
        $hyperVAppVMLegacyState = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppVMLegacy".State
        $hyperVAppVState = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-AppV".State

        if ($hyperVAppVMLegacyState -ne "Enabled" -or $hyperVAppVState -ne "Enabled") {
            EnableAppV
        }

        # Set the path to the virtualized browser executable
        $virtualizedBrowserPath = "C:\Program Files\AppVirt\VirtualizedBrowsers\$($browser).exe"
        LaunchVirtualizedProcess $virtualizedBrowserPath
    }
}

Write-Host "Virtualized browsers check complete."
