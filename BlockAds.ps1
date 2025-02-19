# Set the system region to Albania (GeoID 191)
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name "GeoID" -Value 191

# Set AdvertisingInfo Country to Albania ("AL")
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Country" -Value "AL" -Type String

# Prevent network-based region detection using Cloudflare DNS (1.1.1.1)
$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
foreach ($adapter in $networkAdapters) {
    Set-DnsClientServerAddress -InterfaceAlias $adapter.InterfaceAlias -ServerAddresses ("1.1.1.1","1.0.0.1")
}

# Refresh settings without restarting
Stop-Process -Name "explorer" -Force
Start-Process "explorer"
Write-Host "Region changed to Albania (No-Ad Country). Ads may be reduced."