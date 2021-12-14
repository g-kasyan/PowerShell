<#
.Synopsis
Disable user account that have not signed in for a specified numbers of days.

.Description
Use this script to disable users accounts that have not signed in for an extended period
of time. Review the output to ensure that no unintened accounts were disabled.

.Parameter <Days>
The number of days for which users have not signed in.

.Example
.\Disable-InactiveADUsers.ps1 -Days 60
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

    #$UsersOU = "OU=Users,OU=Test,DC=TEST,DC=LAB"
    #$DisabledUsersOU = "OU=Disabled,OU=Test,DC=TEST,DC=LAB"
    
    Write-Host ("UserOU = {0}, Days = {1}, DisabledUsersOU = {2}" -f $UsersOU, $Days, $DisabledUsersOU)


    # Section search and disable users accounts
    $CutOffDate = (Get-Date).AddDays(-1 * $Days)
    $ADUsers = Get-ADUser -Filter * -SearchBase $UsersOU -Properties LastLogon, whenCreated

    foreach ($ADUser in $ADUsers) {
        $LastLogon = [datetime]::FromFileTime($ADUser.LastLogon)
    
        If ((($ADUser.LastLogon -eq 0) -and ($ADUser.whenCreated -le $CutOffDate)) -or `
             ($LastLogon -lt $CutOffDate)) {
                Write-Host ("User {0} will blocked!" -f $ADUser.Name)
                #$TimeStamp = Get-Date -Format "dd.MM.yyyy HH:mm"
                #Set-ADUser -Identity $ADUser -Enabled $false -Description ("Account was blocked by sript at {0}" -f $TimeStamp) 
                #Move-ADObject -Identity $ADUser -TargetPath $DisabledUsersOU
        }
    }
}

Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -Days 10 -DisabledUsersOU "OU=Disabled,OU=Test,DC=TEST,DC=LAB"
