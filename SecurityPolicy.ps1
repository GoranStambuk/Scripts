# Export the current security policy
secedit /export /cfg C:\secpol.cfg

# Define the privilege rights settings
$privilegeSettings = @'
[Privilege Rights]
SeChangeNotifyPrivilege = *S-1-1-0
SeInteractiveLogonRight = *S-1-5-32-544 
SeDenyNetworkLogonRight = *S-1-5-11
SeDenyInteractiveLogonRight = Guest
SeDenyRemoteInteractiveLogonRight = *S-1-5-11
SeDenyServiceLogonRight = *S-1-5-32-545
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeAssignPrimaryTokenPrivilege= 
SeBackupPrivilege= 
SeCreateTokenPrivilege= 
SeDebugPrivilege= 
SeImpersonatePrivilege= 
SeLoadDriverPrivilege= 
SeRemoteInteractiveLogonRight= 
SeServiceLogonRight= 
SeTakeOwnershipPrivilege= 
'@

# Apply the new privilege settings
$privilegeSettings | Out-File -Append C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg C:\secpol.cfg /areas USER_RIGHTS

# Clean up temporary file
Remove-Item C:\secpol.cfg
