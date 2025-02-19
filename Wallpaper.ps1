$wallpaperSource = "$PSScriptRoot\wall.jpg"
$wallpaperDest = "$env:WINDIR\Setup\Scripts\wall.jpg"

# Ensure destination directory exists
if (!(Test-Path "$env:WINDIR\Setup\Scripts")) {
    New-Item -ItemType Directory -Path "$env:WINDIR\Setup\Scripts" -Force
}

# Copy wallpaper
Copy-Item -Path $wallpaperSource -Destination $wallpaperDest -Force

# Set as default wallpaper (current user and default profile)
$regPath = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $regPath -Name Wallpaper -Value $wallpaperDest

# Refresh wallpaper
rundll32.exe user32.dll, UpdatePerUserSystemParameters
