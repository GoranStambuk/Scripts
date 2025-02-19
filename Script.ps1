# Unified PowerShell Script: Combining all four scripts

### Script 1: Enable Acoustic Echo Cancellation (AEC) and Noise Suppression ###
function Enable-AECAndNoiseSuppression {
    $renderDevicesKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"

    $audioDevices = Get-ChildItem -Path $renderDevicesKey
    foreach ($device in $audioDevices) {
        $fxPropertiesKey = "$($device.PSPath)\FxProperties"

        if (!(Test-Path $fxPropertiesKey)) {
            New-Item -Path $fxPropertiesKey -Force
            Write-Host "Created FxProperties key for device: $($device.PSChildName)" -ForegroundColor Green
        }

        $aecKey = "{1c7b1faf-caa2-451b-b0a4-87b19a93556a},6"
        $noiseSuppressionKey = "{e0f158e1-cb04-43d5-b6cc-3eb27e4db2a1},3"
        $enableValue = 1

        $currentAECValue = Get-ItemProperty -Path $fxPropertiesKey -Name $aecKey -ErrorAction SilentlyContinue
        if ($currentAECValue.$aecKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $aecKey -Value $enableValue
            Write-Host "Acoustic Echo Cancellation enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
        }

        $currentNoiseSuppressionValue = Get-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -ErrorAction SilentlyContinue
        if ($currentNoiseSuppressionValue.$noiseSuppressionKey -ne $enableValue) {
            Set-ItemProperty -Path $fxPropertiesKey -Name $noiseSuppressionKey -Value $enableValue
            Write-Host "Noise Suppression enabled for device: $($device.PSChildName)" -ForegroundColor Yellow
        }
    }
}

Enable-AECAndNoiseSuppression

### Script 2: Browser WebRTC and Remote Desktop Settings ###
function Check-And-Apply-Settings {
    param (
        [string]$browserName,
        [string]$prefsPath
    )
    $desiredSettings = @{ "media_stream" = 2; "webrtc" = 2; "remote" = @{ "enabled" = $false; "support" = $false } }

    if (Test-Path $prefsPath) {
        $prefsContent = Get-Content -Path $prefsPath -Raw | ConvertFrom-Json
        $settingsChanged = $false

        if ($prefsContent.profile -and $prefsContent.profile["default_content_setting_values"]) {
            foreach ($key in $desiredSettings.Keys) {
                if ($prefsContent.profile["default_content_setting_values"][$key] -ne $desiredSettings[$key]) {
                    $prefsContent.profile["default_content_setting_values"][$key] = $desiredSettings[$key]
                    $settingsChanged = $true
                }
            }
        }

        if ($prefsContent.remote) {
            foreach ($key in $desiredSettings["remote"].Keys) {
                if ($prefsContent.remote[$key] -ne $desiredSettings["remote"][$key]) {
                    $prefsContent.remote[$key] = $desiredSettings["remote"][$key]
                    $settingsChanged = $true
                }
            }
        }

        if ($settingsChanged) {
            $prefsContent | ConvertTo-Json -Compress | Set-Content -Path $prefsPath
            Write-Output "${browserName}: Settings updated."
        } else {
            Write-Output "${browserName}: No changes detected."
        }
    } else {
        Write-Output "${browserName}: Preferences file not found."
    }
}

function Configure-Firefox {
    $firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfilePath) {
        $firefoxProfiles = Get-ChildItem -Path $firefoxProfilePath -Directory
        foreach ($profile in $firefoxProfiles) {
            $prefsJsPath = "$($profile.FullName)\prefs.js"
            if (Test-Path $prefsJsPath) {
                if (-not (Select-String -Path $prefsJsPath -Pattern 'media.peerconnection.enabled')) {
                    Add-Content -Path $prefsJsPath 'user_pref("media.peerconnection.enabled", false);'
                }
            }
        }
    }
}

Configure-Firefox

### Script 3: Prevent Remote Connections and Enforce Firewall Rules ###
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
Stop-Service -Name "TermService" -Force
Set-Service -Name "TermService" -StartupType Disabled
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0
Disable-PSRemoting -Force
Stop-Service -Name "WinRM" -Force
Set-Service -Name "WinRM" -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart

# Disable SMB
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force

# Disable Wake-on-LAN
Get-NetAdapter | ForEach-Object {
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Disabled"
    Set-NetAdapterAdvancedProperty -Name $_.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Disabled"
}

New-NetFirewallRule -DisplayName "Block RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SMB TCP 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block

### Script 4: Disable gpsvc and Null Access ###
$serviceName = "gpsvc"
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"

$acl = Get-Acl -Path $serviceRegistryPath
$acl.SetOwner([System.Security.Principal.NTAccount]$currentUser)
Set-Acl -Path $serviceRegistryPath -AclObject $acl

$permission = "$currentUser", "FullControl", "Allow"
$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl -Path $serviceRegistryPath -AclObject $acl

Stop-Service -Name $serviceName -Force
Set-Service -Name $serviceName -StartupType Disabled

Write-Host "Unified script executed successfully."
