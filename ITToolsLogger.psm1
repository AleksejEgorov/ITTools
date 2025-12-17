class ITToolsLogger {
    #Region Properties
    hidden                                          [string] $_filePath
    hidden [ValidateRange(0,3)]                     [int] $_level
    hidden [ValidateSet('Host','PS','File','CM')]   [string] $_type
                                                    [string] $StdLogLine = "{0:dd.MM.yyyy HH.mm.ss.fff} [{1}] {2}"

    static [hashtable[]] $MemberDefinitions = @(
        @{
            MemberType = 'ScriptProperty'
            MemberName = 'Level'
            Value = {$this._level}
            SecondValue = {
                $LevelMap = @{
                    'Debug' = 0
                    'Info' = 1
                    'Warning' = 2
                    'Error' = 3
                }
                $NewLevel = $args[0]

                if ($NewLevel -is [string]) {
                    if ($NewLevel -notin @('Debug', 'Info', 'Warning', 'Error')) {
                        throw "Level $NewLevel is unsupported. Valid are: Debug (0), Info (1), Warning (2), Error (3)"
                    }
                    $this._level = $LevelMap[$NewLevel]
                }
                elseif ($NewLevel -is [int]) {
                    if ($NewLevel -notin @(0..3)) {
                        throw "Level $NewLevel is unsupported. Valid are: 0 (Debug), 1 (Info), 2 (Warning), 3 (Error)"
                    }
                    $this._level = $NewLevel
                }
                else {
                    throw "Level must be of type [int] or [string]."
                }

                if ($this._level -eq 0 -and $this._type -eq 'CM') {
                    $this.Info('Level "Debug" is unsupported for CM type. Debug messages will be written like Info messages.')
                }
                if ($this.Type -eq 'PS') {
                    $InformationPreference = 'SilentlyContinue'
                    $DebugPreference = 'SilentlyContinue'
                    if ($this.Level -le 1) {
                        $InformationPreference = 'Continue'
                    }
                    if ($this.Level -eq 0) {
                        $DebugPreference = 'Continue'
                    }
                }
            }
        }
        @{
            MemberType = 'ScriptProperty'
            MemberName = 'Type'
            Value = {$this._type}
            SecondValue = {
                $Type = $args[0]

                if ($this._type) {
                    $this.Warning('Changing log type on the place is dangerous.')
                }

                switch -Regex ($Type) {
                    '^(File|CM)$' {
                        if (!$this.FilePath) {
                            throw "$($Type) format requires file path. Usage: [ITToolsLogger]::new('$($Type)', '$($this.Level)', `$FilePath)."
                        }
                        $this._type = $Type
                    }
                    '^(Host|PS)' {
                        $this._type = $Type
                        if ($this.FilePath) {
                            $this.Warning("File path is not using for $($Type). It will be ignored.")
                        }
                    }
                    default {
                        $this._type = $null
                        throw "Unsupported log type: $Type. Supported types: CM (configuration manager style), Host (Print to console), PS (PowerShell style) or File (plain text file)."
                    }
                }
            }
        }
        @{
            MemberType = 'ScriptProperty'
            MemberName = 'FilePath'
            Value = {$this._filePath}
            SecondValue = {$this._filePath = $args[0]}
        }
    )

    static ITToolsLogger() {
        $TypeName = [ITToolsLogger].Name
        foreach ($Definition in [ITToolsLogger]::MemberDefinitions) {
            Update-TypeData -Force -TypeName $TypeName @Definition
        }
    }
    #endregion


    #region Constructors

    ITToolsLogger() {}

    ITToolsLogger([hashtable]$LogConfig) {
        $this.FilePath = $LogConfig.FilePath
        $this.Level = $LogConfig.Level
        $this.Type = $LogConfig.Type
    }

    ITToolsLogger([PSCustomObject]$LogConfig) {
        $this.FilePath = $LogConfig.FilePath
        $this.Level = $LogConfig.Level
        $this.Type = $LogConfig.Type
    }

    ITToolsLogger([string]$Type) {
        $this.FilePath = $null
        $this.Level = 1
        $this.Type = $Type
    }

    ITToolsLogger([string]$Type, [int]$Level) {
        $this.FilePath = $null
        $this.Level = $Level
        $this.Type = $Type
    }

    ITToolsLogger([string]$Type, [string]$Level) {
        $this.FilePath = $null
        $this.Level = $Level
        $this.Type = $Type
    }

    ITToolsLogger([string]$Type, [int]$Level, [string]$FilePath) {
        $this.FilePath = $FilePath
        $this.Level = $Level


        $this.Type = $Type
    }

    ITToolsLogger([string]$Type, [string]$Level, [string]$FilePath) {
        $this.FilePath = $FilePath
        $this.Level = $Level
        $this.Type = $Type
    }
    #endregion

    #region Public methods
    [void] Debug ([string]$Message) {
        if ($this._level -gt 0) {
            break
        }
        $Line = [string]::Format($this.StdLogLine, [DateTime]::Now, 'DEBUG', $Message)

        if ($this.Type -eq 'CM') {
            $this.WriteLineToFile($this.NewCMLogEntry($Message, 1))
        }
        elseif ($this.Type -eq 'PS') {
            $InformationPreference = 'Continue'
            Write-Information -MessageData $Message
        }
        elseif ($this.Type -eq 'Host') {
            $this.PrintHostLine($Line, 0)
        }
        elseif ($this.Type -eq 'File') {
            $this.WriteLineToFile($Line)
        }
    }

    [void] Info([string]$Message) {
        if ($this._level -gt 1) {
            break
        }
        $Line = [string]::Format($this.StdLogLine, [DateTime]::Now, 'INFO', $Message)

        if ($this.Type -eq 'CM') {
            $this.WriteLineToFile($this.NewCMLogEntry($Message, 1))
        }
        elseif ($this.Type -eq 'PS') {
            $InformationPreference = 'Continue'
            Write-Information -MessageData $Message
        }
        elseif ($this.Type -eq 'Host') {
            $this.PrintHostLine($Line, 1)
        }
        elseif ($this.Type -eq 'File') {
            $this.WriteLineToFile($Line)
        }
    }

    [void] Warning([string]$Message) {
        if ($this.Level -gt 2) {
            break
        }
        $Line = [string]::Format($this.StdLogLine, [DateTime]::Now, 'WARN', $Message)

        if ($this.Type -eq 'CM') {
            $this.WriteLineToFile($this.NewCMLogEntry($Message, 2))
        }
        elseif ($this.Type -eq 'PS') {
            $WarningPreference = 'Continue'
            Write-Warning -Message $Message
        }
        elseif ($this.Type -eq 'Host') {
            $this.PrintHostLine($Line, 2)
        }
        elseif ($this.Type -eq 'File') {
            $this.WriteLineToFile($Line)
        }
    }

    [void] Error([string]$Message) {
        # For errors get info about last error
        $LastError = $Global:Error[0]
        $Message = "$Message $($LastError.Exception.Message)"
        $Line = [string]::Format($this.StdLogLine, [DateTime]::Now, 'ERROR', "$Message ($($this.GetComponent()) $($LastError.InvocationInfo.ScriptLineNumber):$($LastError.InvocationInfo.OffsetInLine))")

        if ($this.Type -eq 'CM') {
            $this.WriteLineToFile($this.NewCMLogEntry($Message, 3))
        }
        elseif ($this.Type -eq 'PS') {
            $ErrorActionPreference = 'Continue'
            Write-Error -Message $Message
        }
        elseif ($this.Type -eq 'Host') {
            $this.PrintHostLine($Line, 3)
        }
        elseif ($this.Type -eq 'File') {
            $this.WriteLineToFile($Line)
        }
    }
    #endregion

    #region Hidden methods
    hidden [void] PrintHostLine ([string]$Line, [int]$RecordType) {
        $LvlText = 'INFO'
        $DefaultColor = [System.Console]::ForegroundColor
        $Color = $DefaultColor
        switch ($RecordType) {
            0 {$Color = 'DarkGray'; $LvlText = 'DEBUG'}
            1 {$Color = 'Gray'; $LvlText = 'INFO'}
            2 {$Color = 'Yellow'; $LvlText = 'WARN'}
            3 {$Color = 'Red'; $LvlText = 'ERROR'}
            Default {
                throw "Record type $RecordType is invalid"
            }
        }

        $Parts = $Line.Replace($LvlText,"`n").Split("`n")
        [System.Console]::Write($Parts[0])
        [System.Console]::ForegroundColor = $Color
        [System.Console]::Write($LvlText)
        [System.Console]::ForegroundColor = $DefaultColor
        [System.Console]::Write($Parts[1])
        [System.Console]::Write("`n")
    }

    hidden [string] NewCMLogEntry([string]$Message, [int]$Level) {

        # Define record type
        switch ($Level) {
            "Info" {[int]$RecType = 1}
            "Warning" {[int]$RecType = 2}
            "Error" {[int]$RecType = 3}
        }

        # Create a log entry
        $Line = "<![LOG[$Message]LOG]!>" +`
            "<time=`"$([datetime]::Now.ToString("HH:mm:ss.ffffff"))`" " +`
            "date=`"$([datetime]::Now.ToString("M-d-yyyy"))`" " +`
            "component=`"$($this.GetComponent())`" " +`
            "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
            "type=`"$Level`" " +`
            "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
            "file=`"`">"
        return $Line
    }

    hidden [void] WriteLineToFile([string]$Line) {
        if (!(Test-Path $this.FilePath)) {
            [void](New-Item -Path $this.FilePath -ItemType File -Force)
            $this.Info("Log file $($this.FilePath) created.")
        }

        # Write the line to the log file
        [bool]$LogSuccess = $false
        $AttemptsLeft = 30
        if ($global:PSVersionTable.PSVersion -ge ([version]'6.0.0')) {
            $Encoding = 'utf8bom'
        }
        else {
            $Encoding = 'utf8'
        }

        while (!$LogSuccess -and ($AttemptsLeft -gt 0)) {
            try {
                Add-Content -Path $this.FilePath -Value $Line -Encoding $Encoding -ErrorAction Stop
                $LogSuccess = $true
            }
            catch {
                $AttemptsLeft--
                if ($AttemptsLeft -gt 0) {
                    $global:Error.RemoveAt(0)
                    Start-Sleep -Milliseconds (Get-Random (500..3000))
                }
            }
        }
        if (!$LogSuccess) {
            throw $($Error[0].Exception.Message)
        }
    }

    hidden [string] GetComponent() {
        $Component = $MyInvocation.MyCommand.Name
        if (!$Component) {
            $Component = $global:MyInvocation.MyCommand.Name
        }
        if (!$Component) {
            $Component = "PSConsole"
        }
        return $Component
    }
}