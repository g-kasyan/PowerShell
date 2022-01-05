function Write-Log {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("INFO","WARNING","ERROR","FATAL","DEBUG")]
    [string]
    $Level = "INFO",
    
    [Parameter(Mandatory=$true)]
    [string]
    $Message,
    
    [Parameter(Mandatory=$false)]
    [string]
    $Logfile
    )
    
    $TimeStamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $Delimiter = "`t"
    $LogLine = "$TimeStamp$Delimiter$Level$Delimiter$Message"
    
    if($Logfile) {
        $LogDirecotry = Split-Path -Path $Logfile
        
        if (-not (Test-Path -Path $LogDirecotry)) {
           New-Item -ItemType Directory -Force -Path $LogDirecotry -ErrorAction Stop | Out-Null
        }
        Add-Content $Logfile -Value $LogLine
    }
    else {
        Write-Output $LogLine
    }
}


function Remove-InactiveADAccounts {
    <#
    .SYNOPSIS
    Script removes disabled users or computers accounts in Active Directory that have not signed in for a  
    specified numbers of days.

    .DESCRIPTION
    Use this script to removes disabled users or computers accounts in Active Directory that have not signed in 
    for an extended period of time. Review the output to ensure that no required accounts were removed.

    .PARAMETER UsersOnly
    Searchs for only users accounts in Active Directory. The parameter is enabled by default.
        
    .PARAMETER ComputersOnly
    Searchs for only computers accounts in Active Directory.

    .PARAMETER Days
    The number of days for which account have not signed in. The default number of days is 730.
    
    For searching computer accounts, the Days parameter cannot be less than twice the maximum 
    age of the computer password. The maximum age of a password is determined from a registry entry.
    
    .PARAMETER AccountsOU
    Searchs for users or computers accounts in the selected organizational unit.

    .PARAMETER Logfile
    The Logfile parameter sends logging messages of what script does during runtime to a file.
    
    .EXAMPLE
    Remove-InactiveADAccounts -AccountsOU "OU=DisabledUsers,OU=Test,DC=test,DC=lab"
    Description
    -----------
    This command searches for disabled inactive users accounts who have not signed in the last 730 days 
    at the organizational unit "OU=DisabledUsers,OU=Test,DC=test,DC=lab" and removes them.

    .EXAMPLE
    Remove-InactiveADAccounts -UsersOnly -AccountsOU "OU=DisabledUsers,OU=Test,DC=test,DC=lab"
    Description
    -----------
    This command searches for disabled inactive users accounts who have not signed in the last 730 days 
    at the organizational unit "OU=DisabledUsers,OU=Test,DC=test,DC=lab" and removes them.
    
    .EXAMPLE
    Remove-InactiveADAccounts -AccountsOU "OU=DisabledUsers,OU=Test,DC=test,DC=lab" -Days 365 -Logfile C:\Logs\RemoveAccount.log
    Description
    -----------
    This command searches for disabled inactive users accounts who have not signed in the last 365 days 
    at the organizational unit "OU=DisabledUsers,OU=Test,DC=test,DC=lab" and removes them. All actions 
    are recorded in a log file.

    .EXAMPLE
    Remove-InactiveADAccounts -ComputersOnly -AccountsOU OU=DisabledComputers,OU=Hardware,DC=test,DC=lab
    Description
    -----------
    This command searches for disabled computers accounts in Active Direcotry who have not changet password 
    in the last 730 days at the organizational unit OU=DisabledComputers,OU=Hardware,DC=test,DC=lab 
    and removed them.
    #>

    [CmdletBinding(SupportsShouldProcess=$True, DefaultParameterSetName="User")]
    param(
        [parameter(Mandatory = $false, ParameterSetName = "User")]
        [switch]
        $UsersOnly,
        
        [parameter(Mandatory = $false, ParameterSetName = "Computer")]
        [switch]
        $ComputersOnly,
        
        [parameter(Mandatory = $false)]
        [int]
        $Days = 730,
        
        [parameter(Mandatory = $true)]
        [string]
        $AccountsOU,
        
        [parameter(Mandatory = $false)]
        [string]
        $Logfile
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'User' {
                $ADAccounts = Get-ADUser -Filter 'Enabled -eq $false' -SearchBase $AccountsOU -Properties LastLogon -ErrorAction Stop

                $CutOffDate = (Get-Date).AddDays(-$Days)
                
                foreach ($ADAccount in $ADAccounts) {
                    
                    $LastLogon = [datetime]::FromFileTime($ADAccount.LastLogon)
                    $isNeedToRemove = ($LastLogon -lt $CutOffDate)
                    
                    switch($true) {
                        ($isNeedToRemove) {
                            Remove-ADObject -Identity $ADAccount -Confirm:$false
                        }
                        ($isNeedToRemove -and $Logfile) {
                            Write-Log -Message ("User account '{0}' removed. Reason: user not active for {1} days." -f $ADAccount.distinguishedName, $Days) -Logfile $Logfile
                        }                        
                    }
                }
                break
            }
            
            'Computer' {
                $ADAccounts = Get-ADComputer -Filter 'Enabled -eq $false' -SearchBase $AccountsOU -Properties pwdLastSet, lastLogon -ErrorAction Stop
                
                $DisablePasswordChangeReg = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Name DisablePasswordChange
                $MaximumPasswordAgeReg = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Name MaximumPasswordAge
                $MaximumPasswordAge = 2 * $MaximumPasswordAgeReg
                
                $IsDayIncorrect = ($Days -le $MaximumPasswordAge)
                $IsIncorrect = ($IsDayIncorrect -and (-not $DisablePasswordChangeReg))
                
                if ($IsIncorrect) {
                    $Days = $MaximumPasswordAge
                }
                
                $CutOffDate = (Get-Date).AddDays(-$Days)
                
                foreach ($ADAccount in $ADAccounts) {
                    
                    $pwdLastSet = [datetime]::FromFileTime($ADAccount.pwdLastSet)
                    $lastLogon = [datetime]::FromFileTime($ADAccount.lastLogon)
                    
                    $isNeedToRemove = (($pwdLastSet -lt $CutOffDate) -and ($lastLogon -lt $CutOffDate))
                    
                    switch($true) {
                        ($isNeedToRemove) {
                            Remove-ADObject -Identity $ADAccount -Confirm:$false
                        }
                        ($isNeedToRemove -and $Logfile) {
                            Write-Log -Message ("Computer account '{0}' removed. Reason: The password for the computer account has not been changed for last {1} days and last logon was less then {1} days." -f $ADAccount.distinguishedName, $Days) -Logfile $Logfile
                        }
                    }
                }
                break
            }
        }
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Log -Level ERROR -Message ("Organizational Unit '{0}' not found." -f $AccountsOU) -Logfile $Logfile
    }
    catch [System.InvalidOperationException] {
        Write-Log -Level ERROR -Message ("Required permissions are missing") -Logfile $Logfile
    }
    catch {
        Write-Log -Level ERROR -Message ("An unknown error occurred.") -Logfile $Logfile
        #$PSItem.Exception | Get-Member
    }
}
