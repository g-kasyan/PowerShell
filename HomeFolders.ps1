function HomeFolders {
    param (
        # Path to share
        [Parameter(Mandatory = $true)]
        [string]
        $SmbShare,

        # Path to organisation unit of AD users
        [Parameter(Mandatory = $true)]
        [string]
        $UsersOU
    )

    $ADUsers = Get-ADUser -Filter {Enabled -eq $true} -SearchBase $UsersOU

    if ($ADUsers) {
        # Section creating users home folders
        foreach ($ADUser in $ADUsers) {
            $UserHomeFolder = Join-Path -Path $SmbShare -ChildPath $ADUser.SamAccountName
            if (!(Test-Path -Path $UserHomeFolder)) {
                New-Item -Path $SmbShare -Name $ADUser.SamAccountName -ItemType Directory | Out-Null

                $UserSmbShareACL = Get-Acl -Path $UserHomeFolder
                $UserHomeFolderACL = $ADUser.SamAccountName, 'Read,Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
                $ACLRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $UserHomeFolderACL
                $UserSmbShareACL.SetAccessRule($ACLRule)
                Set-Acl -Path $UserHomeFolder -AclObject $UserSmbShareACL
            }
        }
        
        # Section removing users home folders
        $SubFolders = Get-ChildItem -Path $SmbShare -Directory
        foreach ($SubFolder in $SubFolders) {
            if ($SubFolder.Name -notin $ADUsers.SamAccountName) {
                Remove-Item -Path $SubFolder.FullName -Force
            }
        }
    }
}
