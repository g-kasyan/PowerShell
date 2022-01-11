Function Format-Bytes {
    <#
    .SYNOPSIS
    The script converts the number to string using kilobytes, megabytes, gigabytes or terabytes.

    .DESCRIPTION
    Use a script to convert the number to human-readable format. This script was found on the 
    Internet at https://theposhwolf.com/howtos/Format-Bytes/ and saved so as not to lose it.

    But keep in mind that this is simple a string format of the number. If you took that number 
    and tried any comparison or arithmetic operators, they would treat it as a string.

    .PARAMETER Size
    Number to be converted.

    .EXAMPLE
    Format-Bytes 1234567890
    1.15 GB

    Description
    -----------
    You can pass a number to functions.

    .EXAMPLE
    9876543210 | Format-Bytes
    9.20 GB
    
    Description
    -----------
    Or puss the number through the pipeline.

    .EXAMPLE
    Get-ChildItem -File | Select-Object Name,@{Name = 'Size';Expression = {Format-Bytes $_.Length}}
    Name           Size
    ----           ----
    .gitattributes 66 B
    LICENSE        1.04 KB
    README.md      1.07 KB

    You can integrate it into some output like Get-ChildItem.

    .LINK
    https://theposhwolf.com/howtos/Format-Bytes/
    #>
    param (
        [Parameter(ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [float]$Size
    )
	
    if ($Size -lt 1KB) {
        return "$Size B"
    }
    elseif ($Size -lt 1MB) {
        $Size = $Size / 1KB
        $Size = "{0:N2}" -f $Size
        return "$Size KB"
    }
    elseif ($Size -lt 1GB) {
        $Size = $Size / 1MB
        $Size = "{0:N2}" -f $Size
        return "$Size MB"
    }
    elseif ($Size -lt 1TB) {
        $Size = $Size / 1GB
        $Size = "{0:N2}" -f $Size
        return "$Size GB"
    }
    elseif ($Size -lt 1PB) {
        $Size = $Size / 1TB
        $Size = "{0:N2}" -f $Size
        return "$Size TB"
    }
    else {
        $Size = $Size / 1PB
        $Size = "{0:N2}" -f $Size
        return "$Size PB"
    }
}
