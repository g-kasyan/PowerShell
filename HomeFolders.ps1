function HomeFolders {
    <#
    .SYNOPSIS
    The script manages home folders for Active Directory user accounts.
    
    .DESCRIPTION
    The script looks for enabled user accounts in a specific organization unit in Active Directory. 
    If there is no folder with the Username in the network folder, then the script creates it, 
    copies the ACL of the parent folder and adds users home folder permissions. 

    If the users account in a specific organization unit in Active Directory is disabled or absent, 
    then the user folder is removed. 
    
    .PARAMETER SmbShare
    Path to folder containing users home folders.

    .PARAMETER UsersOU
    Search for users accounts in the selected organization unit in Active Directory.

    .EXAMPLE
    HomeFolders -SMBShare "C:\Public\HomeFolders" -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB"
    Description
    -----------
    This command creates users home folders in parent folder "C:\Public\HomeFolders" for all enabled 
    users account located in organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB".

    .EXAMPLE
    HomeFolders -SMBShare "\\ServerName\Path\to\HomeFolders" -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB"
    Description
    -----------
    This command creates users home folders in parent folder "\\ServerName\Path\to\HomeFolders" for all enabled 
    users account located in organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB".
    #>

    param (
        # Path to network share
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
                # Set ACL user's home folder
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
