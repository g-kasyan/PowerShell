<#
.Synopsis
Disable user account that have not signed in for a specified numbers of days.

.Description
Use this script to disable users accounts that have not signed in for an extended period
of time. Review the output to ensure that no unintened accounts were disabled.

.Parameter <Days>
The number of days for which users have not signed in.

.Example
Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB"
This command searches for inactive users who have not signed in the last 60 days 
in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB", disables them

.Example
Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -Days 10
This command searches for inactive users who have not signed in the last 10 days 
in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB", disables them.

.Example
Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -DisabledUsersOU "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB"
This command searches for inactive users who have not signed in the last 60 days 
in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB", disables and moves 
them to the organizational unit "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB".
#>

Function Disable-InactiveADUsers{
    param(
        [parameter(Mandatory=$true)]
        [string]
        $UsersOU,

        [parameter(Mandatory=$false)]
        [int]
        $Days = 60,

        [parameter(Mandatory=$false)]
        [string]
        $DisabledUsersOU
    )
    Try{
        $CutOffDate = (Get-Date).AddDays(-1 * $Days)
        $ADUsers = Get-ADUser -Filter * -SearchBase $UsersOU -Properties LastLogon, whenCreated -ErrorAction Stop
        
        foreach ($ADUser in $ADUsers) {
            $LastLogon = [datetime]::FromFileTime($ADUser.LastLogon)

            If ((($ADUser.LastLogon -eq 0) -and ($ADUser.whenCreated -le $CutOffDate)) -or `
                 ($LastLogon -lt $CutOffDate)) {
                    Write-Host ("User {0} will blocked!" -f $ADUser.Name)
                    #$TimeStamp = Get-Date -Format "dd.MM.yyyy HH:mm"
                    #Set-ADUser -Identity $ADUser -Enabled $false -Description ("Account was blocked by sript at {0}" -f $TimeStamp)
                    If ($DisabledUsersOU -ne "") {
                        Write-Host ("User {0} will moved to {1} OU!" -f $ADUser.Name, $DisabledUsersOU)
                        #Move-ADObject -Identity $ADUser -TargetPath $DisabledUsersOU
                    }
            }
        }
    }
    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Host ("Organizational Unit '{0}' not found" -f $UsersOU) -ForegroundColor RED
        #$PSItem.Exception | Get-Member
    }
    Catch [Microsoft.ActiveDirectory.Management.ADException]{
        Write-Host ("Organizational Unit '{0}' not found" -f $DisabledUsersOU) -ForegroundColor RED
        #$PSItem.Exception | Get-Member
    }
    Catch {
        Write-Host ("An unknown error occurred") -ForegroundColor RED
    }
}

Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -DisabledUsersOU "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB"
