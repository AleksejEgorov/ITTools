function Limit-FileSize {
    <#
    .SYNOPSIS
        Limit file size.
    .DESCRIPTION
        If file size is greater than specified (64KB default), file will be renamed
        to <FileName>_<datetime>(_<i>).<FileExtension> where <FileName> is original
        file name without extension, <datetime> is current date and time in format
        yyyy-MM-dd_HH_mm, <i> is an iterator (if file name conflict occured), and
        <FileExtension> is orifinal file extension
    .EXAMPLE
        PS> Limit-FileSize -FilePath C:\Some.log -MaxSizeKB 32
        Rename C:\Some.log to C:\Some_yyyy-MM-dd_HH-mm.log (if it's size is greater than 32KB)
    .PARAMETER FilePath
        Path to prosessed file as System.String
    .PARAMETER MaxSizeKB
        Maximum file size (in KB) as System.Int64
    .INPUTS
        None. You cannot pipe objects to Limit-FileSize
    .OUTPUTS
        None. Limit-FileSize don't return anything
    .NOTES
    #>
    [OutputType([void])]
    [CmdletBinding()]
    param (
        # Path to target file.
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$FilePath,

        # Size limit (KB).
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
            (Get-Date).ToString('yyyy-MM-dd_HH-mm') +
            $FileItem.Extension
        )
        Write-Verbose "Renaming $FileItem to $NewNameString"
        $i = 0
        while (Test-Path (Join-Path -Path $FileItem.Directory -ChildPath $NewNameString)) {
            $NewNameString = (
                $FileItem.BaseName +
                '_' +
                (Get-Date).ToString('yyyy-MM-dd_HH-mm') +
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
        Remove files with last access time older than N days before.
        File names can be specified by wildcard string or regular expression.
    .PARAMETER FileName
        File name sample as System.String. Wildcard spported.
    .PARAMETER RegEx
        Full-powered regular expression to specify file names as System.String.
    .PARAMETER Directory
        Path to directory, where files will be searched as System.String. Default is script root directory.
    .PARAMETER MaxDays
        Nubmer of days before today, to define file as too old. As System.Int32
    .INPUTS
        None. You cannot pipe objects to Remove-OldFiles
    .OUTPUTS
        None. Remove-OldFiles don't return anything
    .EXAMPLE
        PS> Remove-OldFiles -FileName "MyLog_*.log" -Directory C:\Application\Logs -MaxDays 90
        Delete files like MyLog_(anything else).log, older than 90 days in C:\Application\Logs
    .EXAMPLE
        PS> Remove-OldFiles -RegEx "^MyLog_\d{1,}.log$" -Directory C:\Application\Logs -MaxDays 120
        Delete files like MyLog_(one or more digits).log, older than 120 days in C:\Application\Logs
    #>
    [OutputType([void])]
    [CmdletBinding(DefaultParameterSetName = 'WildCard')]
    param (
        # Specify wildcard string.
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'WildCard'
        )]
        [string]$FileName,

        # Specify regular expression.
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ParameterSetName = 'RegEx'
        )]
        [string]$RegEx,

        # Where files will be searched?
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string]$DirectoryPath = $PSScriptRoot,

        # How many days before today, are 'file is too old'?
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [int]$MaxDays = 180
    )


    if (Test-Path $DirectoryPath) {
        try {
            $DirectoryItem = Get-Item -Path $DirectoryPath -ErrorAction Stop
            if ($DirectoryItem.GetType() -ne [System.IO.DirectoryInfo]) {
                throw "$DirectoryPath is not directory. Check the path."
            }
        }
        catch {
            throw "Cannot get item of $DirectoryPath . Unknown error."
        }
    }
    else {
        throw "Cannot get directory $DirectoryPath . Check file path and permissions."
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
        Create file of specified size.
    .DESCRIPTION
        Create file test<Size><Units>.dat of specified size in specified folder.
    .PARAMETER DirectoryPath
        Path to directory, where to create files, as System.String
    .PARAMETER Size
        Sizes of required files as array of System.Double.
    .PARAMETER Units
        Units of size as System.String from fixed set (Byte, KB, MB, GB). MB is default.
    .INPUTS
        Size as System.Double[]
    .OUTPUTS
        None. New-TestFile don't return anything
    .EXAMPLE
        PS> New-TestFile -InDirectory C:\Test -Size 1 -Units MB
        Create file test1MB.dat size of 1MB in C:\Test
    .EXAMPLE
        PS> New-TestFile C:\Test 0.5 KB
        Create file test05KB.dat size of 512 bytes (0.5KB) in C:\Test
    .EXAMPLE
        New-TestFile . 5
        Create file test5MB.dat size of 5MB in current directory
    .EXAMPLE
        PS> New-TestFile . @(5,10,20)
        Create files test5MB.dat (size of 5MB), test10MB.dat (size of 10MB) and test20MB.dat (size of 20MB) in current directory
    .EXAMPLE
        PS> 1..3 | New-TestFile -DirectoryPath C:\TestFiles -Units GB
        Create files test1GB.dat (size of 1GB), test2GB.dat (size of 2GB) and test3GB.dat (size of 3GB) in directory C:\TestFiles
    #>
    [OutputType([void])]
    [CmdletBinding()]
    param (
        # Test file path
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$DirectoryPath,

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
        if (!(Test-Path -Path $DirectoryPath)) {
            New-Item -Path $DirectoryPath -ItemType Directory
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
                (Join-Path -Path $DirectoryPath -ChildPath "test$($Lenght.ToString().Replace('.','').Replace(',',''))$Units.dat"),
                Create,
                ReadWrite

            $File.SetLength($Lenght * $Factor)
            $File.Close()
        }
    }

    end {

    }
}


function Get-FolderSize {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('FullName')]
        [string[]]$FolderPath,

        [Parameter()]
        [Alias('h')]
        [switch]$HumanFriendly
    )

    begin {}

    process {
        foreach ($Path in $FolderPath) {
            if ((Test-Path $Path) -and (Get-Item $Path).PSIsContainer) {
                $Measure = Get-ChildItem $Path -Recurse -Force -File | Measure-Object -Property Length -Sum
                if ($Measure) {
                    $Result = @{
                        'Path' = $Path
                    }

                    if ($HumanFriendly) {
                        $Result.Add('Size (GB)',('{0:N2}' -f ($Measure.Sum / 1Gb)))
                    }
                    else {
                        $Result.Add('Size',$Measure.Sum)
                    }
                }
                [PSCustomObject]$Result
            }
        }
    }
    end {}
}


function Import-JsonSettings {
    [CmdletBinding()]
    param (
        # Json config path
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$JsonPath,

        # Properties list
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline
        )]
        [string[]]$Properties,

        # Json config path
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [string]$DefaultJsonPath
    )

    begin {
        if (!$DefaultJsonPath -and $MyInvocation.ScriptName) {
            $DefaultJsonPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($MyInvocation.ScriptName),'Defaults.json')
        }
        elseif (!$DefaultJsonPath -and !$MyInvocation.ScriptName) {
            $DefaultJsonPath = [System.IO.Path]::Combine($(Get-Location).Path,'Defaults.json')
        }

        Write-Verbose "Default json path is $DefaultJsonPath."
        Write-Verbose "Json path is $JsonPath."
        $SettingsHashTable = [hashtable]::new()
        if ((Test-Path $DefaultJsonPath)) {
            try {
                # https://stackoverflow.com/questions/51066978/convert-to-json-with-comments-from-powershell
                $global:DefaultSettings = (Get-Content -Path $DefaultJsonPath -Encoding UTF8 -Raw -ErrorAction Stop)`
                    -replace '(?m)(?<=^([^"]|"[^"]*")*)//.*' `
                    -replace '(?ms)/\*.*?\*/' | ConvertFrom-JSON -ErrorAction Stop
            }
            catch {
                throw $Error[0]
            }

            foreach ($NoteProperty in $DefaultSettings.psobject.Properties.name) {
                $SettingsHashTable.$NoteProperty = $DefaultSettings.$NoteProperty
            }
        }


        try {
            # https://stackoverflow.com/questions/51066978/convert-to-json-with-comments-from-powershell
            $global:OwnSettings = (Get-Content -Path $JsonPath -Encoding UTF8 -Raw -ErrorAction Stop) `
                -replace '(?m)(?<=^([^"]|"[^"]*")*)//.*' `
                -replace '(?ms)/\*.*?\*/' | ConvertFrom-JSON -ErrorAction Stop
        }
        catch {
            throw $Error[0]
        }

        foreach ($NoteProperty in $OwnSettings.psobject.Properties.name) {
            $SettingsHashTable.$NoteProperty = $OwnSettings.$NoteProperty
        }

        $global:Settings = [PSCustomObject]$SettingsHashTable



        if (!$Properties) {
            $Properties = $Settings.psobject.Properties.Name
        }
        $VerboseObject = @()
    }

    process {
        foreach ($Property in $Properties) {
            $Value = $Settings.$Property
            # Requested propery must be defined.
            if ($null -eq $Value) {
                throw "Property $Property is not defined in json file $JsonPath. Invocation stopped."
            }

            # PSCustomObject to hashtable
            if ($Value.GetType() -eq [System.Management.Automation.PSCustomObject]) {
                $ValueObject = $Value

                $Value = [hashtable]::new()
                foreach ($NoteProperty in $ValueObject.psobject.Properties.name) {
                    $Value.Add($NoteProperty,$ValueObject.$NoteProperty)
                }
            }

            try {
                New-Variable -Name $Property `
                    -Value $Value `
                    -Scope Global `
                    -ErrorAction Stop
            }
            catch [System.Management.Automation.SessionStateException] {
                $global:Error.RemoveAt(0)
                Set-Variable -Name $Property `
                    -Value $Value `
                    -Scope Global
            }

            $VerboseObject += [PSCustomObject]@{
                Variable = "Variable $Property is "
                Value = $Value
            }
        }
    }

    end {
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            $VarWidth = ($VerboseObject.Variable | ForEach-Object {$PSItem.Length} | Measure-Object -Maximum).Maximum + 1

            foreach ($Row in $VerboseObject) {
                Write-Verbose -Message (
                    ($Row.Variable).PadRight($VarWidth,' ') +
                    ': ' +
                    $Row.Value
                )
            }
        }
        return
    }
}


function Remove-EmptyFolders {
        <#
    .SYNOPSIS
        Recursively remove empty folders
    .DESCRIPTION
        Recursively remove empty folders, include or exclude root
    .PARAMETER Path
        Pathes to directories, where to remove.
    .INPUTS
        Path as System.String[]
    .OUTPUTS
        None. Remove-EmptyFolders don't return anything
    .EXAMPLE
        PS> Remove-EmptyFolders -Path C:\Test
        Recursively remove empty folders in C:\Test include C:\Test.
    .EXAMPLE
        PS> Remove-EmptyFolders -Path C:\Test -SaveRoot
        Recursively remove empty folders in C:\Test exclude C:\Test.
    .EXAMPLE
        PS> Remove-EmptyFolders -Path C:\Test -LogFilePath C:\Logs\RemovingEmpty.log
        Recursively remove empty folders in C:\Test with logging to C:\Logs\RemovingEmpty.log.
    .EXAMPLE
        PS> Get-ChildItem C:\Test | Remove-EmptyFolders -SaveRoot
        Recursively remove empty folders in subdirectories of C:\Test, but not subdirectories themselves.
    #>
    param (
        # Path to search
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('FullName','PSPath')]
        [string[]]$Path,

        # Dont remove root folder
        [switch]$SaveRoot,

        # Path to log file
        [Parameter(
            Mandatory = $false
        )]
        [string]$LogFilePath

    )

    begin {}

    process {
        foreach ($Item in $Path) {
            foreach ($ChildFolder in (Get-ChildItem -Force -LiteralPath $Item -Directory)) {
                Remove-EmptyFolders -Path $ChildFolder.FullName
            }

            if (!(Get-ChildItem -Force -LiteralPath $Item) -and !$SaveRoot) {
                Write-Verbose "Removing empty folder at path '$Item'."
                try {
                    Remove-Item -Force -LiteralPath $Item
                    Write-CMLog -LogFilePath $LogFilePath -Level Info -Message "Empty folder $($Item.FullName) removed."
                }
                catch {
                    Write-CMLog -LogFilePath $LogFilePath -Level Info -Message "Cannot remove empty folder $($Item.FullName). $($Error[0].Exception.Message)"
                    throw
                }
            }
        }
    }

    end {
        return
    }
}


function ConvertFrom-Ini {
    <#
    .SYNOPSIS
        Convert ini-file text to powershell object.
    .DESCRIPTION
        Convert ini-file text to powershell object. You can pass content as string or string array. 
        Pipelines supported. With -Verbose you can see line numbers. Comments and empty lines will be ignored. 
    .INPUTS
        Content as System.String[]
    .OUTPUTS
        Ini object as Dictionary[[string],[Dictionary[[string],[string]]]]
    .EXAMPLE
        PS> ConvertFrom-Ini -Content (Get-Content C:\Settings.ini)
        Convert content of C:\Settings.ini to powershell object
    .EXAMPLE
        PS> ConvertFrom-Ini (Get-Content C:\Settings.ini -Raw)
        Convert raw content of C:\Settings.ini to powershell object using positional parameter.
    .EXAMPLE
        Get-Content C:\Settings.ini | ConvertFrom-Ini 
        Convert content of C:\Settings.ini to powershell object using pipeline.
    #>
    [CmdletBinding()]
    param (
        # Input string
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true            
        )]
        [AllowEmptyString()]
        [string[]]$Content
    )
    
    begin {
        $MultilineContent = @()
        $Ini = [Dictionary[[string],[Dictionary[[string],[string]]]]]::new()
    }
    
    process {
        # Reformat content to multiline mode.
        foreach($Row in $Content) {
            if ($Row -match "`n") {
                $Row.Split("`n") | Where-Object {$PSItem} | ForEach-Object {$MultilineContent += $PSItem}
            }
            elseif ($Row) {
                $MultilineContent += $Row
            }
            else {
                continue
            }
        }
    }
    
    end {
        $i = 0

        foreach ($Line in $MultilineContent) {
            # Maybe line numbers will be usefull for comments
            Write-Verbose "$($i.ToString().PadLeft(($MultilineContent.Count.ToString().Length),'0')) | $Line"
            $i++

            switch -regex ($Line) {
                # Section
                "^\[(.+)\]" {
                    $SectionName = $Matches[1]
                    $Ini.Add($SectionName,([Dictionary[[string],[string]]]::new()))
                }
                # Key-Value
                "(.+?)\s*=(.*)" {
                    $KeyName,$Value = $matches[1..2]
                    $Ini.$SectionName.Add($KeyName,$Value)
                }
            }
        }

        return $Ini
    }
}

function ConvertTo-Ini {
    <#
    .SYNOPSIS
        Convert ini object to string array.
    .DESCRIPTION
       Convert ini object (i.e created with ConvertFrom-Ini) to ini content string array. 
       You can pass object as [Dictionary[[string],[Dictionary[[string],[string]]]]] or [hashtable] (not recommended).
       Pipelines supported.
    .INPUTS
        InputObject as [Dictionary[[string],[Dictionary[[string],[string]]]]] or System.Collections.Hashtable
    .OUTPUTS
        Content as String[]
    .EXAMPLE
        PS> ConvertTo-Ini -InputObject $IniObject
        Convert ini dictionary object to string array.
    .EXAMPLE
        PS> ConvertTo-Ini $HashTable
        Convert hashtable object to string array using positional parameter. Warning will be displayed.
    .EXAMPLE
        PS> $IniObject | ConvertTo-Ini | Out-File C:\Settings.ini -Encoding ASCII
         Convert ini dictionary object to string array and write it to ini-file C:\Settings.ini using pipelines.
    #>
    [CmdletBinding()]
    param (
        # Input object as [Dictionary[[string],[Dictionary[[string],[string]]]]]
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [ValidateScript(
            {
                switch ($PSItem.GetType()) {
                    ([Dictionary[[string],[Dictionary[[string],[string]]]]]) {
                        return $true
                    }
                    ([hashtable]) {
                        Write-Warning "Recommended input object type is [Dictionary[[string],[Dictionary[[string],[string]]]]] instead [Hashtable], but we will try."
                        return $true
                    }
                    Default {
                        throw "Input object must have type [Dictionary[[string],[Dictionary[[string],[string]]]]]"
                    }
                }
            }
        )]
        [psobject]$InputObject
    )
    
    begin {
        $Content = @()        
    }
    
    process {
        foreach ($Ini in $InputObject) {
            foreach ($SectionName in $Ini.Keys) {
                $Content += "[$SectionName]"
                foreach ($KeyName in $Ini.$SectionName.Keys) {
                    $Content += "$($KeyName)=$($Ini.$SectionName.$KeyName)"
                }
            }

        }        
    }
    
    end {
        return $Content
    }
}