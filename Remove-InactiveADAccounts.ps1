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


function Remove-InactiveADAccounts {
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
