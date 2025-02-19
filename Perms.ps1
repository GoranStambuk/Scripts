# Get all drives on the system
$drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID

# Loop through each drive and modify permissions
foreach ($drive in $drives) {
    Write-Host "Processing drive $drive"

    # Get all files and folders in the drive
    $items = Get-ChildItem -Path $drive\ -Recurse -Force -ErrorAction SilentlyContinue

    foreach ($item in $items) {
        # Get the ACL (Access Control List) for the item
        $acl = Get-Acl $item.FullName

        # Find the "Authenticated Users" access rule and remove the Write permission
        $authUsersRule = $acl.Access | Where-Object { $_.IdentityReference -eq "BUILTIN\Authenticated Users" }

        if ($authUsersRule) {
            # Remove the Write permission (if it exists)
            $newAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Authenticated Users", 
                "Write", 
                "Allow"
            )
            $acl.RemoveAccessRule($newAccessRule)
            # Set the new ACL
            Set-Acl -Path $item.FullName -AclObject $acl
        }
    }
}

Write-Host "Write permissions for 'Authenticated Users' have been removed."
