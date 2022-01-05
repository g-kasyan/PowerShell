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

function Disable-InactiveADAccounts
{
    <#
    .SYNOPSIS
    Script disables users or computers Active Directory accounts that have not signed in for a specified 
    numbers of days.
    
    .DESCRIPTION
    Use this script to disables users or computers Active Directory accounts that have not signed in 
    for an extended period of time. Review the output to ensure that no unintened accounts were disabled.
    
    .PARAMETER UsersOnly
    Searchs for only users accounts in Active Directory. The parameter is enabled by default.
        
    .PARAMETER ComputersOnly
    Searchs for only computers accounts in Active Directory.
    
    .PARAMETER Days
    The number of days for which account have not signed in.
    The default number of days is 90.
    
    For searching computer accounts, the Days parameter cannot be less than twice the maximum 
    age of the computer password. The maximum age of a password is determined from a registry entry.
        
    .PARAMETER AccountsOU
    Searchs for users or computers accounts in the selected OU.
        
    .PARAMETER DisabledAccountsOU
    Moves locked users or computers accounts into a selected OU.
    
    .PARAMETER Logfile
    The Logfile parameter sends logging messages of what script does during runtime to a file.
    
    .EXAMPLE
    Disable-InactiveADAccounts
    Description
    -----------
    This command searches for inactive users accounts who have not signed in the last 90 days 
    and disables them.
        
    .EXAMPLE
    Disable-InactiveADAccounts -UsersOnly -AccountsOU "OU=Users,OU=Test,DC=TEST,DC=LAB"
    Description
    -----------
    This command searches for inactive users accounts who have not signed in the last 90 days at the 
    organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB" and disables them.
        
    .EXAMPLE
    Disable-InactiveADAccounts -AccountsOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -Days 10 -Logfile C:\Logs\DisableAccount.log
    Description
    -----------
    This command searches for inactive users accounts who have not signed in the last 10 days at the 
    organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB" and disables them. All actions are recorded in a log file.
    
    .EXAMPLE
    Disable-InactiveADAccounts -AccountsOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -DisabledAccountsOU "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB"
    Description
    -----------
    This command searches for inactive users accounts who have not signed in the last 90 days at the 
    organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB", disables and moves them to the organizational 
    unit "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB".
    
    .EXAMPLE
    Disable-InactiveADAccounts -ComputersOnly -AccountsOU "OU=Computers,OU=Hardware,DC=TEST,DC=LAB" -DisabledAccountsOU "OU=DisabledComputers,OU=Hardware,DC=TEST,DC=LAB"
    Description
    -----------
    This command searches for computers accounts who have not changet password in the last 
    90 days at the organizational unit "OU=Computers,OU=Hardware,DC=TEST,DC=LAB", disables and moves them 
    to the organizational unit "OU=DisabledComputers,OU=Hardware,DC=TEST,DC=LAB".
    
    .FUNCTIONALITY
    Active Directory
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
        $Days = 90,
        
        [parameter(Mandatory = $false)]
        [string]
        $AccountsOU,
        
        [parameter(Mandatory = $false)]
        [string]
        $DisabledAccountsOU,
        
        [parameter(Mandatory = $false)]
        [string]
        $Logfile
    )
    
    $ADUsersException = 'krbtgt', 'Guest', 'Administrator', 'Администратор', 'Гость'
        
    try {
        switch ($PSCmdlet.ParameterSetName)
        {
            'User'
            {
                if ($AccountsOU) {
                    $ADAccounts = Get-ADUser -Filter 'Enabled -eq $true' -SearchBase $AccountsOU -Properties LastLogon, whenCreated -ErrorAction Stop
                }
                else {
                    $ADAccounts = Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogon, whenCreated -ErrorAction Stop | `
                    Where-Object {$PSItem.Name -notin $ADUsersException}
                }
                
                $CutOffDate = (Get-Date).AddDays(-$Days)
                
                foreach ($ADAccount in $ADAccounts) {
                    
                    $LastLogon = [datetime]::FromFileTime($ADAccount.LastLogon)
                    $isPeriodOver = ($ADAccount.LastLogon -ne 0) -and ($LastLogon -lt $CutOffDate)
                    $isNeverLogon = ($ADAccount.LastLogon -eq 0) -and ($ADAccount.whenCreated -le $CutOffDate)
                    $isNeedToDisable = ($isPeriodOver -or $isNeverLogon)
                    
                    switch($true) {
                        ($isNeedToDisable) {
                            Set-ADUser -Identity $ADAccount -Enabled $false
                        }
                        ($isPeriodOver -and $Logfile) {
                            Write-Log -Message ("User account '{0}' disabled. Reason: user not active for {1} days." -f $ADAccount.distinguishedName, $Days) -Logfile $Logfile
                        }
                        ($isNeverLogon -and $Logfile) {
                            Write-Log -Message ("User account '{0}' disabled. Reason: user has never logged in." -f $ADAccount.distinguishedName) -Logfile $Logfile
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU) {
                            Move-ADObject -Identity $ADAccount -TargetPath $DisabledAccountsOU
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU -and $Logfile) {
                            Write-Log -Message ("User account '{0}' moved to '{1}'." -f $ADAccount.distinguishedName, $DisabledAccountsOU) -Logfile $Logfile
                        }
                    }
                }
                
                break
            }
            
            'Computer'
            {
                if ($AccountsOU) {
                    $ADAccounts = Get-ADComputer -Filter 'Enabled -eq $true' -SearchBase $AccountsOU -Properties pwdLastSet -ErrorAction Stop
                }
                else {
                    $ADAccounts = Get-ADComputer -Filter 'Enabled -eq $true' -Properties pwdLastSet -ErrorAction Stop
                }
                
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
                    
                    $isNeedToDisable = ($pwdLastSet -lt $CutOffDate)
                    
                    switch($true) {
                        ($isNeedToDisable) {
                            Set-ADComputer -Identity $ADAccount -Enabled $false
                        }
                        ($isNeedToDisable -and $Logfile) {
                            Write-Log -Message ("Computer account '{0}' disabled. Reason: The password for the computer account has not been changed for last {1} days." -f $ADAccount.distinguishedName, $Days) -Logfile $Logfile
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU) {
                            Write-Host ("Move-ADObject -Identity $ADAccount -TargetPath $DisabledAccountsOU")
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU -and $Logfile) {
                            Write-Log -Message ("Computer account '{0}' moved to '{1}'." -f $ADAccount.distinguishedName, $DisabledAccountsOU) -Logfile $Logfile
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
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Log -Level ERROR -Message ("Organizational unit not found or required permissions are missing.") -Logfile $Logfile
    }
    catch [System.UnauthorizedAccessException] {
        Write-Log -Level ERROR -Message ("Required permissions are missing.") -Logfile $Logfile
    }
    catch {
        Write-Log -Level ERROR -Message ("An unknown error occurred.") -Logfile $Logfile
        #$PSItem.Exception | Get-Member
    }
}
