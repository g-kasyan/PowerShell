#PowerShell

Various PowerShell functions and scripts.

# Instructions

These files contain functions.  For example, Disable-InactiveADAccounts.ps1 contains the Disable-InactiveADAccounts function. Each file contains help block and examples of how to use the function.

    #Download and unblock the file(s).
    #Dot source the file(s) as appropriate.
    .\Path\To\File\Disable-InactiveADAccounts.ps1
    
    #Use the functions
    Get-Help Disable-InactiveADAccounts -Full
    Disable-InactiveADAccounts -AccountsOU "OU=Users,OU=Test,DC=TEST,DC=LAB" -Days 10 -Logfile C:\Logs\DisableAccounts.log
    
