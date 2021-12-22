function Write-Log {
    [CmdletBinding()]
    param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("INFO","WARNING","ERROR","FATAL","DEBUG")]
    [String]
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
    
    [Datetime]$CutOffDate = (Get-Date).AddDays(-$Days)
    
    try {
        switch ($PSCmdlet.ParameterSetName)
        {
            'User'
            {
                if ($AccountsOU) {
                    $ADAccounts = Get-ADUser -Filter * -SearchBase $AccountsOU -Properties LastLogon, whenCreated -ErrorAction Stop
                }
                else {
                    $ADAccounts = Get-ADUser -Filter * -Properties LastLogon, whenCreated -ErrorAction Stop | `
                    Where-Object {$PSItem.Name -notin $ADUsersException}
                }
                
                foreach ($ADAccount in $ADAccounts) {
                    
                    $LastLogon = [datetime]::FromFileTime($ADAccount.LastLogon)
                    $isPeriodOver = ($ADAccount.LastLogon -ne 0) -and ($LastLogon -lt $CutOffDate)
                    $isNeverLogon = ($ADAccount.LastLogon -eq 0) -and ($ADAccount.whenCreated -le $CutOffDate)
                    $isNeedToDisable = $isPeriodOver -or $isNeverLogon
                    
                    switch($true) {
                        ($isNeedToDisable) {
                            Set-ADUser -Identity $ADAccount -Enabled $false
                        }
                        ($isPeriodOver -and $Logfile) {
                            Write-Log -Message ("User account '{0}' disabled. Reason: user not active for {1} days." -f $ADAccount.SamAccountName, $Days) -Logfile $Logfile
                        }
                        ($isNeverLogon -and $Logfile) {
                            Write-Log -Message ("User account '{0}' disabled. Reason: user has never logged in." -f $ADAccount.SamAccountName) -Logfile $Logfile
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU) {
                            Move-ADObject -Identity $ADAccount -TargetPath $DisabledAccountsOU
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU -and $Logfile) {
                            Write-Log -Message ("User account '{0}' moved to '{1}'." -f $ADAccount.SamAccountName, $DisabledAccountsOU) -Logfile $Logfile
                        }
                    }
                }
                
                break
            }
            
            'Computer'
            {
                if ($AccountsOU) {
                    $ADAccounts = Get-ADComputer -Filter * -SearchBase $AccountsOU -Properties pwdLastSet -ErrorAction Stop
                }
                else {
                    $ADAccounts = Get-ADComputer -Filter * -Properties pwdLastSet -ErrorAction Stop
                }
                
                $MaximumPasswordAgeReg = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Name MaximumPasswordAge
                $MaximumPasswordAge = 2 * $MaximumPasswordAgeReg + 1
                
                $IsIncorrect = $Days -lt $MaximumPasswordAge
                
                if ($IsIncorrect) {
                    $Days = $MaximumPasswordAge
                    $CutOffDate = (Get-Date).AddDays(-$Days)
                }
                
                foreach ($ADAccount in $ADAccounts) {
                    
                    $pwdLastSet = [datetime]::FromFileTime($ADAccount.pwdLastSet)
                    
                    $isNeedToDisable = $pwdLastSet -lt $CutOffDate
                    
                    switch($true) {
                        ($isNeedToDisable) {
                            Set-ADComputer -Identity $ADAccount -Enabled $false
                        }
                        ($isNeedToDisable -and $Logfile) {
                            Write-Log -Message ("Computer account '{0}' disabled. Reason: The password for the computer account has not been changed for last {1} days." -f $ADAccount.Name, $Days) -Logfile $Logfile
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU) {
                            Write-Host ("Move-ADObject -Identity $ADAccount -TargetPath $DisabledAccountsOU")
                        }
                        ($isNeedToDisable -and $DisabledAccountsOU -and $Logfile) {
                            Write-Log -Message ("Computer account '{0}' moved to '{1}'." -f $ADAccount.Name, $DisabledAccountsOU) -Logfile $Logfile
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
        Write-Log -Level ERROR -Message ("Organizational required permissions are missing.") -Logfile $Logfile
    }
    catch {
        Write-Log -Level ERROR -Message ("An unknown error occurred.") -Logfile $Logfile
        #$PSItem.Exception | Get-Member
    }
    
    
    <#
        .SYNOPSIS
        Disable user account that have not signed in for a specified numbers of days.
        
        .DESCRIPTION
        Use this script to disable AD accounts that have not signed in for an extended period
        of time. Review the output to ensure that no unintened accounts were disabled.
        
        .PARAMETER UsersOU
        Search for user accounts in the selected OU.
        
        .Parameter Days
        The number of days for which users have not signed in.
        
        .Parameter DisabledUsersOU
        Moves locked user accounts into a selected OU.
        
        .EXAMPLE
        Disable-InactiveADUsers
        Description
        -----------
        This command searches for inactive users who have not signed in the last 60 days 
        and disables them.

        .EXAMPLE
        Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB"
        Description
        -----------
        This command searches for inactive users who have not signed in the last 60 days 
        in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB" and disables them.
        
        .EXAMPLE
        Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -Days 10
        Description
        -----------
        This command searches for inactive users who have not signed in the last 10 days 
        in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB" and disables them.
        
        .EXAMPLE
        Disable-InactiveADUsers -UsersOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -DisabledUsersOU "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB"
        Description
        -----------
        This command searches for inactive users who have not signed in the last 60 days 
        in the organizational unit "OU=Users,OU=Test,DC=TEST,DC=LAB", disables and moves 
        them to the organizational unit "OU=DisabledUsers,OU=Test,DC=TEST,DC=LAB".

        .EXAMPLE
        Disable-InactiveADUsers -ComputersOnly -AccountsOU "OU=Computers,OU=Hardware,DC=TEST,DC=LAB" -DisabledAccountsOU "OU=DisabledComputers,OU=Hardware,DC=TEST,DC=LAB"
    #>
}
