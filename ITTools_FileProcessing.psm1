function Limit-FileSize {
    <#
    .SYNOPSIS
        Limit log (or not) file size.
    .DESCRIPTION
        If file size is greater than specified (64KB default), file will be renamed
    .EXAMPLE
        PS C:\> Limit-FileSize -FilePath C:\Some.log -MaxSizeKB 32
        Rename C:\Some.log to C:\Some_yyyy-MM-dd_HH-mm-ss.log (if it's size is greater than 32KB)
    .INPUTS
        FilePath as [string] and MaxSize as [long]
    .OUTPUTS
        No output.
    .NOTES
    #>
    [OutputType([void])]
    [CmdletBinding()]
    param (
        # Path to file
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$FilePath,

        # Size limit (KB)
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [long]$MaxSizeKB = 64
    )
    

    [long]$MaxLength = $MaxSizeKB * 1024
    Write-Verbose "Max size is $MaxLength"
    if (Test-Path $FilePath) {
        try {
            $FileItem = Get-Item -Path $FilePath -ErrorAction Stop
            if ($FileItem.GetType() -ne [System.IO.FileInfo]) {
                throw "$FilePath is not file. Check the path."
            }
        }
        catch {
            throw "Cannot get item of $FilePath. Unknown error."
        }    
    }
    else {
        throw "Cannot get file $FilePath. Check file path and permissions."
    }
    

    Write-Verbose "File size is $($FileItem.Length)"
    

    if ($FileItem.Length -ge $MaxLength) {
        $NewNameString = (
            $FileItem.BaseName +
            '_' +
            (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss') +
            $FileItem.Extension
        )
        Write-Verbose "Renaming $FileItem to $NewNameString"
        $i = 0
        while (Test-Path (Join-Path -Path $FileItem.Directory -ChildPath $NewNameString)) {
            $NewNameString = (
                $FileItem.BaseName +
                '_' +
                (Get-Date).ToString('yyyy-MM-dd_HH-mm-ss') +
                '_' + 
                $i +
                $FileItem.Extension 
            )
            $i++
        } 
        Rename-Item $FileItem -NewName $NewNameString 
    }        
}


function Remove-OldFiles {
    <#
    .SYNOPSIS
        Remove files older than specified.
    .DESCRIPTION
    .EXAMPLE
    .INPUTS
        FileName or RegEx as [string], Directory as [string], MaxDays as [int]
    .OUTPUTS
        [void]
    .NOTES
    #>
    [OutputType([void])]
    [CmdletBinding(DefaultParameterSetName = 'WildCard')]
    param (
        # For wildcard
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'WildCard'
        )]
        [string]$FileName,

        # For regex
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'RegEx'
        )]
        [string]$RegEx,

        # Search in
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string]$Directory = $PSScriptRoot,

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [int]$MaxDays = 180
    )


    if (Test-Path $Directory) {
        try {
            $DirectoryItem = Get-Item -Path $Directory -ErrorAction Stop
            if ($DirectoryItem.GetType() -ne [System.IO.DirectoryInfo]) {
                throw "$Directory is not directory. Check the path."
            }
        }
        catch {
            throw "Cannot get item of $Directory. Unknown error."
        }    
    }
    else {
        throw "Cannot get directory $Directory. Check file path and permissions."
    }

    $DirectoryContent = Get-ChildItem -Path $DirectoryItem.FullName -File 
    if ($FileName) {
        $DirectoryContent | Where-Object {
            ($PSItem.Name -like $FileName) -and `
            ($PSItem.LastAccessTime -lt (Get-Date).AddDays(-$MaxDays))`
        } | ForEach-Object {
            Remove-Item $PSItem.FullName -Force
        }
    }

    if ($RegEx) {
        $DirectoryContent | Where-Object {
            ($PSItem.Name -match $RegEx) -and `
            ($PSItem.LastAccessTime -lt (Get-Date).AddDays(-$MaxDays))`
        } | ForEach-Object {
            Remove-Item $PSItem.FullName -Force
        }
    }
}

function New-TestFile {
    <#
    .SYNOPSIS
        Create file of specified size
    .DESCRIPTION

    .EXAMPLE

    .INPUTS
        Inputs (if any)
    .OUTPUTS
        [void]
    .NOTES

    #>
    [OutputType([void])]
    [CmdletBinding()]
    param (
        # Test file path
        [Parameter(
            Mandatory,
            Position = 0
        )]
        [string]$InFolder,

        # Test file lenght
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            Position = 1
        )]
        [double[]]$Size,

        # Parameter help description
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateSet(
            'Byte',
            'KB',
            'MB',
            'GB'
        )]
        [string]$Units = 'MB'
    )
    
    begin {
        # $Path is a folder
        if (!(Test-Path -Path $InFolder)) {
            New-Item -Path $InFolder -ItemType Directory
        }
        switch ($Units) {
            'Byte' {$Factor = 1}
            'KB' {$Factor = 1024}
            'MB' {$Factor = 1048576}
            'GB' {$Factor = 1073741824}
            Default {}
        }
    }
    
    process {
        foreach ($Lenght in $Size) {
            $File = New-Object -TypeName System.IO.FileStream -ArgumentList `
                (Join-Path -Path $InFolder -ChildPath "test$($Lenght.ToString().Replace('.','').Replace(',',''))$Units.dat"),
                Create,
                ReadWrite
            
            $File.SetLength($Lenght * $Factor)
            $File.Close()
        }
    }
    
    end {
        
    }
}