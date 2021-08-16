$Global:ITToolsPath = $PSScriptRoot

class DiskInfo {
    [string]$Status
    [int]$Index
    [string]$Model
    [string]$Type
    [string]$Bus
    [UInt64]$TotalSize

    DiskInfo() {
        $this.Status = $null
        $this.Index = $null
        $this.Model = $null
        $this.Bus = $null
        $this.Type = $null

        $this.TotalSize = $null
    }

    DiskInfo(
        [string]$stat,
        [int]$id,
        [string]$mod,
        [string]$tp,
        [string]$bs,
        [UInt64]$sz
    ) {
        $this.Status = $stat
        $this.Index = $id
        $this.Model = $mod
        $this.Type = $tp
        $this.Bus = $bs
        $this.TotalSize = $sz
    }

    [string[]]ToJson() {
        return $this | ConvertTo-Json
    } 

}

class MonitorInfo {
    [bool]$Active
    [string]$Manufacturer
    [string]$Model
    [string]$SerialNumber

    MonitorInfo() {
        $this.Active = $null
        $this.Manufacturer = $null
        $this.Model = $null
        $this.SerialNumber = $null
    }

    MonitorInfo(
        [bool]$act,
        [string]$man,
        [string]$mod,
        [string]$sn
    ) {
        $this.Active = $act
        $this.Manufacturer = $man
        $this.Model = $mod
        $this.SerialNumber = $sn
    }

    [string[]]ToJson() {
        return $this | ConvertTo-Json
    } 

}

class InventoryInfo {
    [string]$Status
    [string]$HostName
    [string[]]$IPAddress
    [string[]]$MACAddress
    [string]$SerialNumber
    [string]$Model
    [string]$CPU
    [string]$RAM
    [DiskInfo[]]$Disks
    [MonitorInfo[]]$Monitors
    [string[]]$UPSs
    [string]$LastUser

    InventoryInfo() {
        $this.Status = $null
        $this.HostName = $null
        $this.IPAddress = $null
        $this.MACAddress = $null
        $this.SerialNumber = $null
        $this.Model = $null
        $this.CPU = $null
        $this.RAM = $null
        $this.Disks = $null
        $this.Monitors = $null
        $this.UPSs = $null
        $this.LastUser = $null
    }

    InventoryInfo(
        [string]$stat,
        [string]$hstnm,
        [string[]]$ip,
        [string[]]$mac,
        [string]$sn,
        [string]$mod,
        [string]$cp,
        [string]$mem,
        [DiskInfo]$dsk,
        [MonitorInfo[]]$mon,
        [string[]]$ups,
        [string]$user
    ) {
        $this.Status = $stat
        $this.HostName = $hstnm
        $this.IPAddress = $ip
        $this.MACAddress = $mac
        $this.SerialNumber = $sn
        $this.Model = $mod
        $this.CPU = $cp
        $this.RAM = $mem
        $this.Disks = $dsk
        $this.Monitors = $mon
        $this.UPSs = $ups
        $this.LastUser = $user
    }

    [string[]]ToJson() {
        return $this | ConvertTo-Json -Depth 5
    }
    [PSCustomObject]ToTableObject() {
        return [PSCustomObject]@{
            Status = $this.Status
            HostName = $this.HostName

            IPAddress = & {
                if ($this.IPAddress) {
                    return [string]::Join(',',$this.IPAddress)
                }
                else {
                    return $null
                }
            }

            MACAddress = & {
                if ($this.MACAddress) {
                    return [string]::Join(',',$this.MACAddress)
                }
                else {
                    return $null
                }
            }

            SerialNumber = $this.SerialNumber
            Model = $this.Model
            CPU = $this.CPU
            RAM = $this.RAM
            
            Disks = & {
                if ($this.Disks) {
                    return [string]::Join(
                        ',',
                        (
                            $this.Disks | ForEach-Object {
                                [string]::Concat(
                                    $PSItem.Model,
                                    ' (',
                                    $PSItem.TotalSize,
                                    'GB: ',
                                    $PSItem.Status,
                                    ' ',
                                    $PSItem.Bus,
                                    ' ',
                                    $PSItem.Type,
                                    ')'
                                )
                            }
                        )
                    )
                }
                else {
                    return $null
                }
            }

            Monitors = & {
                if ($this.Monitors) {
                    return [string]::Join(
                        ',',
                        (
                            $this.Monitors | ForEach-Object {
                                [string]::Concat(
                                    $PSItem.Model,
                                    ' (',
                                    $PSItem.SerialNumber,
                                    ')'
                                )
                            }
                        )
                    )
                }
                else {
                    return $null
                }
                
            }

            UPSs = & {
                if ($this.UPSs) {
                    return [string]::Join(',',$this.UPSs)
                }
                else {
                    return $null
                }
            }

            LastUser = $this.LastUser
        }
    }
}


##############################################################
####                  Convert string to HEX               ####
##############################################################

function Get-Hex {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$String
    )

    foreach ($Char in $String.ToCharArray()) {
        $Result = $Result + [System.String]::Format("{0:X}",[System.Convert]::ToUInt32($Char))
    }

    return $Result
}



##############################################################
####                Validate e-mail address               ####
##############################################################
function Test-EmailValidation {
    param (
        [Parameter(
            Mandatory = $true
        )]
        [AllowEmptyString()]
        [string]$EmailAddress
    )

    $MailRegex = "^[a-zA-Z0-9\-\._]*@[a-zA-Z0-9\-_.]*\.[a-zA-Z]{2,5}$"
    # If real e-mail
    if ($EmailAddress -match $MailRegex) {
        return $EmailAddress
    }

    else {
        # Replace 'me' to current user SamAccountName
        if ($EmailAddress -eq 'me') {
            $EmailAddress = $env:USERNAME
        }
        try {
            # Find user in AD. Valid if has EmailAddress
            $ADMail = ([adsisearcher]"(&(objectClass=user)(objectCategory=person)(sAMAccountName=$EmailAddress))").FindOne().GetDirectoryEntry().mail
        }
        catch {
            Write-Host "No user $EmailAddress in domain $($Env:USERDNSDOMAIN.ToLower())!" -ForegroundColor Red -BackgroundColor Black
            return $null
        }
        if ($ADMail -and ($ADMail -match $MailRegex)) {
            return $ADMail
        }
        else {
            Write-Host "User $EmailAddress has no valid mail!" -ForegroundColor Red -BackgroundColor Black
            return $null
        }
    }
}



##############################################################
####  Show logon server for current user on specified PC  ####
##############################################################

function Get-LogonServer {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true

        )]
        [string[]]$ComputerName = @(".")
    )

    Import-Module ActiveDirectory
    # Create result object
    $Result = @() 
    foreach ($Computer in $ComputerName) {
        # Get current loged in user. If no — all fields are empty
        try {
            $UserName = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ErrorAction Stop).UserName.Split('\')[1]
        }
        catch {
            $Result += [PSCustomObject]@{
                ComputerName = $Computer
                LogonServer = ''
                UserName = ''
                Domain = ''
            }
        }
        

        # Get current loged in user's SID from AD. If no — it's local user.
        try {
            $ADUser = ([adsisearcher]"(&(objectClass=user)(objectCategory=person)(sAMAccountName=$UserName))").FindOne().GetDirectoryEntry()
            $SID = ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$ADUser.objectSid.Value,0)).Value
        }
        catch {
            $Result += [PSCustomObject]@{
                ComputerName = $Computer
                LogonServer = $Computer
                UserName = $UserName
                Domain = $Computer
            }
            continue
        }

        # Get logon server for domain user.
        $RegBranch = Invoke-Command -ComputerName $Computer -ScriptBlock {
            $null = New-PSDrive HKU Registry HKEY_USERS
            Get-ItemProperty "HKU:\$using:SID\Volatile Environment"
        }
        $Result += [PSCustomObject]@{
            ComputerName = $Computer
            LogonServer = $RegBranch.LogonServer.replace('\\','')
            UserName = $RegBranch.UserName
            Domain = $RegBranch.UserDNSDomain.ToLower()
        }
    }
    return $Result
}



##############################################################
####                 Connection using DW MRC              ####
##############################################################

function Connect-DWClient {
    [CmdletBinding()]
    param (
        [Parameter(mandatory=$True)][string]$Target,
        [Parameter(mandatory=$false)][Switch]$Force,
        [Parameter(mandatory=$false)][Switch]$Polite
    )


    # Test target PC availability
    try {
        Test-Connection $Target -Count 1 -ErrorAction Stop
    } 
    catch {
        Write-Host "Host is unavaliable." -ForegroundColor Red -BackgroundColor Black
        return
    }

    # Change remote registry service start mode to auto and run it 
    cmd /c "sc \\$Target config remoteregistry start=auto"
    cmd /c "sc \\$Target start remoteregistry"

    # Change registry: 
    # allowing dameware service to start in safe mode
    reg add "\\$Target\HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\dwmrcs" /t REG_SZ /d Service /f

    if ($Polite) {
        # Enable request to user before connection
        reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 1 /f
    }
    if ($Force) {
        # Disable request to user before connection
        reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 0 /f
    }

    # Run the connection. Close the application when disconnected
    Start-Sleep -Seconds 1
    Start-Process "${env:ProgramFiles(x86)}\SolarWinds\DameWare Remote Support\DWRCC.exe" -ArgumentList "-h -c -x -m:$Target"

    # Return registry value.
    if ($Force) {
        Start-Job -ScriptBlock {
            Start-Sleep -Seconds 30
            reg add "\\$Target\HKLM\SOFTWARE\DameWare Development\Mini Remote Control Service\Settings" /v "Permission Required" /t REG_DWORD /d 1 /f
        }
    }
}



##############################################################
####           Connection using UltraVNC Viewer           ####
##############################################################

function Connect-VNCClient {
    param (
        # Parameter help description
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$Computername
    )
    
    Start-Process "$env:ProgramFiles\UltraVNC\vncviewer.exe" -ArgumentList "-connect $using:Computername -autoscaling -user $env:USERNAME"
}



##############################################################
####             Calc best practice staging quota         ####
##############################################################

function Get-BPStagingQuota {
    [CmdletBinding()]
    param (
        # Define path to measute
        [Parameter(Mandatory = $true)]
        [string]$Path,

        # Define number of files
        [Parameter(Mandatory = $false)]
        [int]$Flows = 32
    )
    
    $i = 1
    # Get all files.
    $Content = @()
    Get-ChildItem $Path -File -Recurse | `
        ForEach-Object {
            $Content += $PSItem
            Write-Progress -Activity "Counting file $($PSItem.name)" -Status "Total files: $i"
            $i++
        } 
        
    # Select biggest and measure average size
    $MaxSizeFiles = $Content | 
        Sort-Object Length -Descending |
        Select-Object -First $Flows |
        ForEach-Object {$PSItem.Length / 1MB}
    $Measured = $MaxSizeFiles | Measure-Object -Average
    $Result = $Measured.Average * $Flows
    return [System.Math]::Round($Result,0)
}


##############################################################
####                 Define server by site                ####
##############################################################
function Get-ADSiteServer {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("Name")]
        [string[]]$Sites,
        
        [Parameter(Mandatory = $false)]
        [string]$Forest = $env:USERDNSDOMAIN
    ) 
    
    foreach ($Site in $Sites) {
        $ForestObject = New-object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", "$Forest")
        $SiteObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestObject).Sites | Where-Object {$PSItem.Name -eq $Site}
        $SiteObject.Servers | Select-Object SiteName,Name,IPAddress
    }
}


##############################################################
####                    Reboot with result                ####
##############################################################
function Wait-Reboot {
    param (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^[a-zA-Z0-9\-\.]*$")]
        [string[]]
        $ComputerName,

        # Waiting timeout in seconds. 5 minutes as default.
        [Parameter(Mandatory = $false)]
        [int]
        $WaitSeconds = 300,

        [Parameter(Mandatory = $false)]
        [switch]
        $MonitorOnly
    )
    
    $Rebooted = @()
    $AttemptsRemaining = [System.Math]::Round(($WaitSeconds / 2),0)

    $NotRebooted = Test-Connection -ComputerName $ComputerName -Count 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Address
    $Unavaliable = Compare-Object -ReferenceObject $ComputerName -DifferenceObject $NotRebooted | Select-Object -ExpandProperty InputObject
    if ($Unavaliable) {
        foreach ($Computer in $Unavaliable) {
            Write-Host "$($Computer): " -NoNewline
            Write-Host "OFFLINE" -ForegroundColor Gray
        }
    }   

    $StartTime = Get-Date
    if (!$MonitorOnly) {
        Write-Host "Reboot started..." -ForegroundColor Gray
        Restart-Computer $NotRebooted -Force
    }
    
    do {
        $Rebooted += Invoke-Command -ComputerName $NotRebooted -ScriptBlock {
            $TimeStamp = Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
            $RebootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($TimeStamp)
            if ($RebootTime -gt $using:StartTime) {
                Write-Host "$($Env:COMPUTERNAME): " -NoNewline
                Write-Host "OK" -ForegroundColor Green
                return $Env:COMPUTERNAME
            }
        } -ErrorAction SilentlyContinue -ErrorVariable ConErr

        $NotRebooted = Compare-Object -ReferenceObject $NotRebooted -DifferenceObject $Rebooted | Select-Object -ExpandProperty InputObject
        Start-Sleep -Seconds 2
        $AttemptsRemaining--
    } until ((!$NotRebooted) -or ($AttemptsRemaining -eq 0))

    if ($NotRebooted) {
        foreach ($Computer in $NotRebooted) {
            Write-Host "$($Computer): " -NoNewline
            Write-Host "FAIL!" -ForegroundColor Red
        }
    }        
}



##############################################################
####          Check, open & allow RDP connections         ####
##############################################################

function Unblock-RDP {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('Name','HostName')]
        [string]$ComputerName
    )

    begin {}
    process {
        foreach ($Computer in $ComputerName) {
            try {
                # Handle to terminal service settings
                $TermServ = Get-WmiObject -ComputerName $Computer Win32_TerminalServiceSetting -Namespace root\cimv2\TerminalServices
            }
            catch {
                Write-Host "Host is unavaliable." -ForegroundColor Red -BackgroundColor Black
                break
            }
        
            # Enable remote desktop
            $TermServ.SetAllowTSConnections(1,1)
            
            # Allow connections from all computers
            # $TermServ.SetUserAuthenticationRequired(0)
        }
    }
    end {}
}



##############################################################
####              Export PSObject to Excel file           ####
##############################################################
function Export-Excel {
    <#
    .SYNOPSIS
    Export powershell object to Excel file
    .DESCRIPTION
    Export powershell object (or object array) to Excel file 
    .NOTES
    Author: Egorov.Aleksej.v@gmail.com
    .INPUTS
    PSObject. You can pipe any object to Export-Excel.
    .OUTPUTS
    None. Export-Excel returns nothing.
    .PARAMETER Properties
    Selected property list 
    .PARAMETER InputObject
    Any PSObject or ovject array to export.
    .PARAMETER Name
    Friendly name for file and worksheet. 
    Default: PowerShell.
    .PARAMETER AddColumns
    Additional columns — not existion properties 
    .PARAMETER Show
    Оpen and show you file
    .PARAMETER ExportTo
    Path for export. 
    Default: Desktop. Folder redirection is supported.
    .PARAMETER Passwd
    Make file password-protected. String parameter.
    .PARAMETER NotReplace
    Allow to add new file, if file with the same name are existing.
    

    .EXAMPLE
    Get-ChildItem C:\ | Export-Excel
    Export list of files and directories on C:\ to your desktop with filename PowerShell-PSReport-2020-04-19.xlsx
    .EXAMPLE
    Get-ChildItem C:\ | Export-Excel -Name 'Content_C'
    Export list of files and directories on C:\ to your desktop with filename Content_C-PSReport-2020-04-19.xlsx
    .EXAMPLE
    Get-ChildItem C:\ | Export-Excel -ExportTo D:
    Export list of files and directories on C:\ to the file D:\PowerShell-PSReport-2020-04-19.xlsx
    #>
    [CmdletBinding(PositionalBinding = $false)]
    param (
        # Define list of existing properties
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [string[]]$Propetries,

        # Input object
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [psobject[]]$InputObject,

        # Define list of adding properties
        [Parameter(Mandatory = $false)]
        [string[]]$AddColumns,
        
        # Only show file, without saving
        [Parameter(Mandatory = $false)]
        [switch]$Show,

        # Define file destination
        [Parameter(Mandatory = $false)]
        [string]$ExportTo,
        
        # Define file name
        [Parameter(Mandatory = $false)]
        [string]$Name,

        # Password-protected file
        [Parameter(Mandatory = $false)]
        [string]$Passwd,

        [Parameter(Mandatory = $false)]
        [switch]$NotReplace
    )


    begin {
        # Define default name
        if (!$Name) {
            $Name = 'PowerShell'
        }
         
        # Create excel file
        $Excel = New-Object -ComObject Excel.Application
        $Excel.Visible = $false

        $WorkBook = $Excel.Workbooks.Add()
        $Report = $WorkBook.Worksheets.Item(1)
        $Report.Name = "$Name report"
        $ProcessObject = @()
    }    
        
    process {
        foreach ($Object in $InputObject) {
            $ProcessObject += $Object
        }
    }
    
    end {
        # Define input object properties list
        if (!$ProcessObject) {
            Write-Error -Message 'Input object is null or empty' -Category InvalidOperation -Exception InvalidOperationException
            return
        }

        Write-Debug "Processing object is ready"
        
        $AllPropetries = $ProcessObject | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name

        $SelectedProperties = @()
        foreach ($Prop in $Propetries) {
            if ($AllPropetries -contains $Prop) {
                $SelectedProperties += $Prop
            }
        }

        if (!$SelectedProperties) {
            $SelectedProperties = $AllPropetries
        }

        if ($AddColumns) {
            foreach ($Field in $AddColumns) {
                $SelectedProperties += $Field
            }             
        }

        Write-Debug "Property list is ready"
        
        # Push content
        $Column = 0
        foreach ($Property in $SelectedProperties) {
            # Headers
            $Column++
            $Report.Cells.Item(1,$Column) = "$Property"

            # Data
            Set-StrictMode -Version Latest
            $Row = 1
            foreach ($Item in $ProcessObject) {
                $Row++
                try {
                    $Report.Cells.Item($Row,$Column) = $Item.$Property    
                }
                catch {
                    
                }
            }
            Set-StrictMode -Off
        }
        # Format table
        # Define last column number
        [string]$LastColumn = ''
        [int]$FirstLetter = [System.Math]::Truncate($Column / 26)
        [int]$SecondLetter = $Column - (26 * $FirstLetter)
        if ($FirstLetter -gt 0) {
            $OFS = ''
            $LastColumn += [char](64 + $FirstLetter)
        }
        $LastColumn += [char](64 + $SecondLetter)
        
        $Headers = $Report.Range("A1","$($LastColumn)1")
        $Headers.Font.Bold = $true
        $Headers.Interior.ColorIndex = 15
        $null = $Headers.EntireColumn.AutoFilter()
        $null = $Headers.EntireColumn.AutoFit()
        7..12 | ForEach-Object `
        {
            $Headers.Borders.Item($PSItem).LineStyle = 1
            $Headers.Borders.Item($PSItem).Weight = 2
        }

        Write-Debug "ExportTo is $ExportTo; Show is $Show"

        if ($Show -and !$ExportTo) {
            $Excel.Visible = $true
            break
        }

        $Desktop = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name Desktop).Desktop
        
        # Define export path
        if ($ExportTo -and ($ExportTo -ne "Default")) {
            try {
                Test-Path $ExportTo -ErrorAction Stop
                $SaveAsFolder = $ExportTo
            }
            catch {
                $SaveAsFolder = "$Desktop"
                Write-Warning "$ExportTo is not valid path! File will be saved in $SaveAsFolder"
            }
        }

        elseif ((!$ExportTo) -or ($ExportTo -eq "Default")) {
            $SaveAsFolder = "$Desktop"
        }
        
        # Define full path
        $FileName = "$Name-PSReport-" + (Get-Date -Format yyyy-MM-dd) + '.xlsx' 
        $SaveAsPath = Join-Path $SaveAsFolder -ChildPath $FileName

        # Prepare for saving
        $SaveAsPathNR = $SaveAsPath
        if ($NotReplace) {
            $i = 0
            while (Test-Path $SaveAsPathNR) {
                $i++
                $SaveAsPathNR = $SaveAsPath.Replace('.xlsx',"_$i.xlsx")
            }
            $SaveAsPath = $SaveAsPathNR
        }

        $Excel.DisplayAlerts = $false
        $missing = [System.Reflection.Missing]::Value

        $null = $WorkBook.SaveAs("$SaveAsPath",$missing,"$Passwd")
        

        $TimeOut = 10

        while (($TimeOut -gt 0) -and !(Test-Path $SaveAsPath)) {
            Start-Sleep -Seconds 1
            $TimeOut--
        }
        if ($TimeOut -eq 0) {
            Write-Error -Message "File was not saved in $SaveAsFolder" `
                -Category InvalidResult `
                -TargetObject $WorkBook `
                -RecommendedAction "Check if file is not busy and you have permissions to write file in this location."
            $Excel.Visible = $true
            break
        }
        else {
            Write-Host "Export done to: `n$SaveAsPath" -ForegroundColor Green 
        }

        if ($Show) {
            $Excel.Visible = $true
            
        }
        else {
            $Excel.Quit()
        }
    }
}


##############################################################
####          Test user if member of specific group       ####
##############################################################
function Test-GroupMembership {
    [CmdletBinding()]
    param (
        # Target group
        [parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$GroupName,

        # Users to check or add
        [parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$SamAccountName,

        # Define addition. If no — check only
        [Switch]$Add
        
    )
    begin {
        Import-Module ActiveDirectory
        try {
            $Group = Get-ADGroup $GroupName
        }
        catch {
            throw "Group $GroupName not found in domain $env:USERDOMAIN."
        }
    }
    process {
        foreach ($User in $SamAccountName) {
            $GroupList = @()
            try {
                $GroupList += (Get-ADUser $User -Properties MemberOf -ErrorAction Stop).MemberOf | ForEach-Object {
                    (Get-ADGroup $PSItem)
                }
            }

            catch {
                Write-Host "User not found!" -ForegroundColor red -BackgroundColor Black
                continue 
            }
            Write-Verbose "$User in $($GroupList.Count) groups : $($GroupList.Name)"
    
            Write-Host "$User is in $GroupName : " -NoNewline
            if ($GroupList.Name -contains $Group.Name) {
                Write-Host "TRUE" -ForegroundColor Green | Out-Host
            }
            else {
                if ($Add) {
                    Add-ADGroupMember -Identity $Group -Members $User
                    Write-Host "ADDED" -ForegroundColor Yellow | Out-Host
                }
                else {
                    Write-Host "FALSE" -ForegroundColor Red | Out-Host
                }
            }
        } 
    }
    end {}
}




##############################################################
####                Convert object encoding               ####
##############################################################
function ConvertTo-Encoding {
    param (
        # Source encoding
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$From,
        
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$To,

        [Parameter(
            Mandatory = $true,
            Position = 2,
            ValueFromPipeline = $true
        )]
        [string]$String
    )
    begin {
        $Error.Clear()
        $encFrom = [System.Text.Encoding]::GetEncoding($from)
        $encTo = [System.Text.Encoding]::GetEncoding($to)
        if ($Error) {
            break
        }
    }
    process {
        $bytes = $encTo.GetBytes($String)
        $bytes = [System.Text.Encoding]::Convert($encFrom, $encTo, $bytes)
        $encTo.GetString($bytes)
    }
}




##############################################################
####               QWinSta output ad object               ####
##############################################################
function Get-QWinSta {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [string[]]$Servers = @("localhost")
    )
    
    begin {
        $Result = @()
    }
    
    process {
        foreach ($Server in $Servers) {
            $QueryRes = qwinsta /server:$Server | ConvertTo-Encoding -From cp866 -To windows-1251 
            $QueryRes[0] = 'SessionName,UserName,ID,State,Type,Device,ComputerName'
            $ObjectRes = $QueryRes | ForEach-Object {
                $Row = $PSItem
                if (($PSItem -match "\d\s+Disc") -or ($PSItem -match "\d\s+Диск")) {
                    $Row = "none" + $Row
                }
                $Row.trim() -replace "\s+", "," 
            } | ConvertFrom-Csv -Delimiter ',' 
            $ObjectRes | Where-Object {!$PSItem.State} | ForEach-Object {
                $PSItem.State = $PSItem.ID
                $PSItem.ID = $PSItem.UserName
                $PSItem.UserName = ''
            }
            $ObjectRes | Where-Object {$PSItem.SessionName -eq  'none'} | ForEach-Object {
                $PSItem.SessionName = ''
            }
            $ObjectRes | ForEach-Object {$PSItem.ComputerName = [string]$Server}
            $Result += $ObjectRes
        }
    }
    
    end {
        return $Result
    }
}


##############################################################
####     Get info about loged in users from event log     ####
##############################################################

function Get-LoggedInUsers {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string[]]$Servers,

        [Parameter(
            Mandatory = $true
        )]
        [DateTime]$After
    )
    
    begin {
        $LoggedInUsers = @()
        $XmlDate = [Xml.XmlConvert]::ToString($After,[Xml.XmlDateTimeSerializationMode]::Utc)
        $XPath = "*[System[(EventID = 1149) and TimeCreated[(@SystemTime>'$XmlDate')]]]"
    }
    
    process {
        foreach ($Server in $Servers) {
            
            try {
                $Events = Get-WinEvent -ComputerName $Server `
                    -LogName "Microsoft-Windows-TerminalServices-*" `
                    -FilterXPath $XPath `
                    -ErrorAction Stop                
            }
            catch {
                continue
            }
            
            foreach ($Event in $Events) {
                $LoggedInUsers += ([xml]$Event.ToXml()).Event.UserData.EventXML.Param1.Split('@')[0]
            } 
        }
    }
    
    end {
        return ($LoggedInUsers | Select-Object -Unique)
    }
}


##############################################################
####           Get locked account source from PDC         ####
##############################################################
function Get-LockSource {
    #Requires -Modules ActiveDirectory
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true)]
        [string[]]
        $UserName
    )
    
    begin {
        $PDC = (Get-AdDomain).PDCEmulator
        $Result = @()
    }
    
    process {
        foreach ($User in $UserName) {
            try {
                $null = Get-ADUser "$User"
            }
            catch {
                Write-Host "$User not found!" -ForegroundColor Red -BackgroundColor Black
                continue
            }
            $ParamsEvent = @{
                Computername = $Pdc;
                LogName = 'Security';
                FilterXPath = "*[System[EventID=4740] and EventData[Data[@Name='TargetUserName']='$User']]";
            }
            try {
                $Events = Get-WinEvent @ParamsEvent -ErrorAction Stop
            }
            catch {
                continue
            }

            foreach ($Event in $Events) {
                $Result +=  [PSCustomObject]@{
                    Account = $Event.Properties[0].Value;
                    LockSource = $Event.Properties[1].Value.TrimStart('\');
                    EventTime = $Event.TimeCreated
                }
            }
        }
    }
    
    end {
        return $Result
    }
}




##############################################################
####     Shadow connection to Win10/Server2016+ hosts     ####
##############################################################
function New-ShadowConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName

    )
    $Sessions = @()
    Get-QWinSta $ComputerName | Where-Object {$PSItem.State -eq "Active"} | ForEach-Object {$Sessions += $PSItem}
    if ($Sessions.count -gt 1) {
        $Sessions | Select-Object ID,UserName | Out-Host  
        $SessionID = Read-Host "Type session ID"
    }
    else {
        $SessionID = $Sessions.ID
    }
    
    $ArgList = @(
        "/v:$ComputerName",
        "/shadow:$SessionID",
        "/Control",
        "/NoConsentPrompt"
    )
    Start-Process mstsc.exe -ArgumentList $ArgList
}




##############################################################
####               Send Wake-on-LAN package               ####
##############################################################
function Send-WOL {
    <#
        .SYNOPSIS 
            Send a WOL packet to a broadcast address
        .PARAMETER MAC
        The MAC address of the device that need to wake up
        .PARAMETER ComputerName
        Name of the compurer, that need to wake up. IPAddress defines automaticaly.
        .PARAMETER IP
        The IP address where the WOL packet will be sent to
        .EXAMPLE
        Send-WOL -mac 00:11:22:33:44:55 -ip 192.168.2.100
    #>
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    param(
        [Parameter(
            Mandatory=$True,
            Position = 1,
            ParameterSetName = 'MAC'
        )]
        [ValidatePattern(
            "(^[a-f0-9\*]{1,12}$)|(^[a-f0-9\-\*]{1,14}$)|(^[a-f0-9\:\*]{1,17}$)|(^[a-f0-9\-\*]{1,17}$)"
        )]
        [string]$MAC,
        
        [Parameter(
            Mandatory=$True,
            Position = 1,
            ParameterSetName = 'ComputerName'
        )]
        [string]$ComputerName,

        # Parameter help description
        [Parameter(
            Mandatory = $false
        )]
        [ValidateScript(
            {
                try {
                    [ipaddress]$PSItem
                    return $true
                }
                catch {
                    throw "$PSItem is not valid ip address"
                }
            }
        )]
        [string]$IPAddress,
        [int]$Port = 9
    )
    

    if (($Computername) -and ($ComputerName -notmatch "([0-9a-f]{2}[:\-]?){5}[0-9a-f]{2}")) {
        try {
            $IPAddressFromDNS = (Resolve-DnsName $ComputerName -ErrorAction Stop).IPAddress            
        }
        catch {
            Write-Error -Message "Can't resolve name to IP address. Please, try by MAC." -Category InvalidData -TargetObject "$ComputerName"
            break
        }
        $DHCPServerName = (Resolve-DnsName (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$PSItem.DnsDomain -eq $env:USERDNSDOMAIN}).DHCPServer).NameHost
        $ScopeID = $IPAddressFromDNS -replace "\.\d{1,3}$",'.0'
        if (!$IPAddress) {
            $IPAddress = $IPAddressFromDNS -replace "\.\d{1,3}$",'.255'
        }

        try {
            $MAC = (Get-DhcpServerv4Lease -ComputerName $DHCPServerName -ScopeId $ScopeID -ErrorAction Stop| Where-Object {$PSItem.IPAddress -eq $IPAddressFromDNS}).ClientId            
        }
        catch {
            Write-Error -Message "Can't find IP lease on $DHCPServerName. Please, try by MAC." -Category InvalidData -TargetObject "$IPAddressFromDNS"
            break
        }
    }

    else {
        if (!$IPAddress) {
            $IPAddress = "255.255.255.255"            
        }
    }
    
    $Broadcast = [Net.IPAddress]::Parse($IPAddress)
    
    $MAC=(($MAC.Replace(":","")).Replace("-","")).Replace(".","")
    $Target=0,2,4,6,8,10 | ForEach-Object {[convert]::ToByte($MAC.Substring($PSItem,2),16)}
    $Packet = (,[byte]255 * 6) + ($Target * 16)
    
    $UDPClient = New-Object System.Net.Sockets.UdpClient
    $UDPClient.Connect($Broadcast,$Port)
    [void]$UDPClient.Send($Packet, 102)
}



##############################################################
####                Translit string en → ru               ####
##############################################################
function Get-Translit {
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$String
    )

    if (!$String) {
        return
    }

    $CyrArr = @("а","б","в","г","д","е","ё", "ж", "з","и","й","к","л","м","н","о","п","р","с","т","у","ф","х","ц","ч", "ш", "щ",  "ъ","ы","ь","э","ю", "я",`
                "А","Б","В","Г","Д","Е","Ё", "Ж", "З","И","Й","К","Л","М","Н","О","П","Р","С","Т","У","Ф","Х","Ц","Ч", "Ш", "Щ",  "Ъ","Ы","Ь","Э","Ю", "Я",`
                "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",`
                "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z",`
                "_","0","1","2","3","4","5","6","7","8","9")
    
    $LatArr = @("a","b","v","g","d","e","jo","zh","z","i","y","k","l","m","n","o","p","r","s","t","u","f","h","c","ch","sh","sch","y","y","", "e","yu","ya",`
                "A","B","V","G","D","E","Jo","Zh","Z","I","Y","K","L","M","N","O","P","R","S","T","U","F","H","C","Ch","Sh","Sch","Y","Y","", "E","Yu","Ya",`
                "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",`
                "A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z",`
                "_","0","1","2","3","4","5","6","7","8","9")

    $TransVoc = @()
    $i=0
    for ($i = 0; $i -lt $CyrArr.Count; $i++) {
        $TransCharObj = New-Object psobject | Select-Object @{n="Cyr";e={$CyrArr[$i]}},@{n="Lat";e={$LatArr[$i]}}
        $TransVoc += $TransCharObj              
    }
    
    
    $AllChars=$String.ToCharArray()

    foreach ($Char in $AllChars) {
        if ($Char -match "\w") {
            $TransChar = ($TransVoc | Where-Object {$PSItem.Cyr -ceq $Char}).Lat
        }
        else {
            $TransChar = $Char
        }

        if (($Prevchar -notmatch "\w") -or ($Prevchar -match "_") -or ($Prevchar -match "\d")) {
            switch -CaseSensitive ($TransChar) {
                'h' {$TransChar = 'kh'}
                'H' {$TransChar = 'Kh'}
                Default {}
            }
        }
        $Prevchar = $TransChar
        $TransString += $TransChar
    }
    $TransString = $TransString -replace "yy$","y"

    return [string]$TransString
}





##############################################################
####                 Generate random password             ####
##############################################################
function New-Password {
    param (
        [Parameter()]
        [ValidateRange(7,[int]::MaxValue)]
        [int]$Length = 10,

        [ValidateRange(0,[int]::MaxValue)]
        [int]$SpecChar = 0,

        [ValidateRange(0,4)]
        [int]$Conditions = 4
    )
        
    $CharacterList = @()
    $Symbols = '!@#$%^&*()-_=+<>'.ToCharArray()
    
    $CharacterList += 65..90 | ForEach-Object {[char]$_}
    $CharacterList += 97..122 | ForEach-Object {[char]$_}
    $CharacterList += 0..9
    $CharacterList += $Symbols
    
    do {
        $Passwd = ""
        # for ($i = 0; $i -lt $Length; $i++) {
        #     $RandomIndex = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(0, $CharacterList.Length)
        #     $Passwd += $CharacterList[$RandomIndex]
        # }
        0..$Length | ForEach-Object {
            $Passwd += $CharacterList | Get-Random 
        }

        [int]$hasLowerChar = $Passwd -cmatch '[a-z]'
        [int]$hasUpperChar = $Passwd -cmatch '[A-Z]'
        [int]$hasDigit = $Passwd -match '[0-9]'
        [int]$hasSymbol = $Passwd.IndexOfAny($Symbols) -ne -1

    }
    until (($hasLowerChar + $hasUpperChar + $hasDigit + $hasSymbol) -ge $Conditions)

    return $Passwd
}



##############################################################
####            Resize pictire for AD intedration         ####
##############################################################
function Get-ResizedPicture {
        
    Param ( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$ImageSource,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$CanvasSize,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Quality 
    )

    # Check input
    if (!(Test-Path $ImageSource)) {
        Write-Error "File $ImageSource not found." -Category ObjectNotFound
    }

    if (($CanvasSize -lt 10) -or ($CanvasSize -gt 1000)) {
        Write-Error "CanvasSize is out of range. 10..1000 expected." -Category InvalidData
    }

    if (($Quality -lt 1) -or ($Quality -gt 100)) {
        "Quality is out of range. 1..100 expected."
    }

    # Import class 
    [void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

    $ImageBytes = [byte[]](Get-Content $ImageSource -Encoding byte)
    $ms = New-Object IO.MemoryStream($ImageBytes, 0, $ImageBytes.Length)
    $ms.Write($ImageBytes, 0, $ImageBytes.Length);

    $bmp = [System.Drawing.Image]::FromStream($ms, $true)

    # Resolution after convertation
    $CanvasWidth = $CanvasSize
    $CanvasHeight = $CanvasSize

    # Set quality
    $MyEncoder = [System.Drawing.Imaging.Encoder]::Quality
    $EncoderParams = New-Object System.Drawing.Imaging.EncoderParameters(1)
    $EncoderParams.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter($MyEncoder, $Quality)

    # Get pictute type
    $MyImageCodecInfo = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object {$PSItem.MimeType -eq 'image/jpeg'}

    # Calc ratio
    $RatioX = $CanvasWidth / $bmp.Width;
    $RatioY = $CanvasHeight / $bmp.Height;

    if($RatioX -le $RatioY){
        $Ratio = $RatioX
    }
    else {
        $Ratio = $RatioY
    }

    # Create empty pict file
    $NewWidth = [int]($bmp.Width * $Ratio)
    $NewHeight = [int]($bmp.Height * $Ratio)
    $BmpResized = New-Object System.Drawing.Bitmap($NewWidth, $NewHeight)
    $Graph = [System.Drawing.Graphics]::FromImage($BmpResized)

    $Graph.Clear([System.Drawing.Color]::White)
    $Graph.DrawImage($bmp,0,0 , $NewWidth, $NewHeight)

    # Create empty stream
    $ms = New-Object IO.MemoryStream
    $bmpResized.Save($ms,$myImageCodecInfo, $($encoderParams))

    # Cleanup
    $bmpResized.Dispose()
    $bmp.Dispose()

    return $ms.ToArray()
}




##############################################################
####                  Define user's groups                ####
##############################################################
function Get-UserGroups {
    param (
        [Parameter(
            Mandatory = $true, ValueFromPipeline = $true
        )]
        [Alias("SamAccountName")]
        [string]$UserName,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsObject
    )

    begin {}
    
    process {
        foreach ($User in $UserName) {
            try {
                $GroupList = (Get-ADUser $User -Properties memberof -ErrorAction Stop).MemberOf | 
                    ForEach-Object {Get-ADGroup -Identity $PSItem}
            }
            catch {
                Write-Warning "User $User not found in $env:USERDOMAIN."          
            }

            if ($AsObject) {
                return $GroupList
            }
            else {
                $GroupList | Select-Object Name
            }
        }
    }

    end {}
}




##############################################################
####             Create new scope on DHCP server          ####
##############################################################
function New-IPScope {
    [CmdletBinding()]
    param (
        [Parameter(mandatory=$true)][string]$Scope,
        [Parameter(mandatory=$true)][string]$Name,
        [Parameter(mandatory=$false)][string]$Description,
        [Parameter(mandatory=$false)][string]$DHCPServer,
        
        [Parameter(mandatory=$false)] 
        [ValidateRange(0,32)][int]$Mask = 24,

        [Parameter(mandatory=$false)] 
        [ValidateRange(2,254)][int]$Start = 10,

        [Parameter(mandatory=$false)]
        [ValidateRange(2,254)][int]$End = 250
    )

    if (!$DHCPServer) {
        $DHCPServer = = (Resolve-DnsName (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$PSItem.DnsDomain -eq $env:USERDNSDOMAIN}).DHCPServer).NameHost
    }

    if (($Scope -notmatch "^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)$") `
        -and ($Scope -notmatch "^(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}$")) {
        Write-Host "Wrong IP address format!" -BackgroundColor Black -ForegroundColor Red
        return
    }
    else {
        $IPOctets=$Scope.Split(".")
        $ScopeId="$($IPOctets[0]).$($IPOctets[1]).$($IPOctets[2]).0"
    }


    # Define range
    $StartRange = "$($Scope.Split(".")[0]).$($Scope.Split(".")[1]).$($Scope.Split(".")[2]).$Start"
    $EndRange = "$($Scope.Split(".")[0]).$($Scope.Split(".")[1]).$($Scope.Split(".")[2]).$End"
    $Router = "$($Scope.Split(".")[0]).$($Scope.Split(".")[1]).$($Scope.Split(".")[2]).1"
    $SubnetMask = (([string]'1'*$Mask + [string]'0'*(32-$Mask)) -split "(\d{8})" -match "\d" | ForEach-Object {[convert]::ToInt32($PSItem,2)}) -split "\D" -join "."
    $ScopeName = Get-Translit $Name


    # Create scope
    Add-DhcpServerv4Scope -ComputerName $DHCPServer `
        -StartRange $StartRange `
        -EndRange $EndRange `
        -SubnetMask $SubnetMask `
        -Name $ScopeName `
        -Description $Description `
        -Type Dhcp
    
    # Set regular options
    Set-DhcpServerv4OptionValue -ComputerName $DHCPServer -ScopeId $ScopeId -Router $Router
}




##############################################################
####                Limit string from the end              ####
##############################################################

function Limit-String {
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [int]$Limit,

        [Parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true
        )]
        [string]$String
    )
    
    if ($String.Length -gt $Limit) {
        return [string]::Join('',$String[($String.Length - $Limit)..($String.Length - 1)])
    }
    else {
        return [string]$String
    }   
}




##############################################################
####            Grabbing inventory information            ####
##############################################################
function Get-InventoryInfo {

    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('Name','HostName')]
        [string[]]$Computername,

        [Parameter(Mandatory=$false)]
        [string]$ExportPath = "$HOME\Documents",
        
        [Parameter()]
        [switch]$Csv,

        [Parameter()]
        [switch]$Json,
        
        [Parameter()]
        [switch]$Excel    
    )
    

    BEGIN {
        $InventoryTotal = @()
    }
    

    PROCESS {
        ForEach ($Computer in $Computername)  {
            Write-Progress -Activity "Grabbing inventory information." `
                -Status "Processing $($Computername.IndexOf($Computer) + 1) of $($Computername.Count): $Computer" `
                -PercentComplete (($Computername.IndexOf($Computer) / $Computername.Count) * 100)
            $MachineInfo = New-Object -TypeName InventoryInfo
            # Checking remote machine avaliabelty
            try {
                $CimSession = New-CimSession -ComputerName $Computer -Name $Computer  -ErrorAction Stop 
            }
            catch {
                $MachineInfo.Status = "Unavaliable"
                try {
                    $null = [ipaddress]$Computer
                    $MachineInfo.IPAddress = $Computer
                    try {
                        $MachineInfo.HostName = (Resolve-DnsName $Computer -ErrorAction Stop).NameHost
                    }
                    catch {}
                }
                catch {
                    try {
                        $DnsInfo = Resolve-DnsName $Computer -ErrorAction Stop
                        $MachineInfo.HostName = $DnsInfo.Name
                        $MachineInfo.IPAddress = $DnsInfo.IPAddress
                    }
                    catch {
                        $MachineInfo.HostName = $Computer
                    }
                    
                }
                $InventoryTotal += $MachineInfo
                $MachineInfo
                continue
            }
            $MachineInfo.Status = "Avaliable"

            # Grabbing data
            # Model
            $MachineInfo.Model = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).Model

            # CPU
            $MachineInfo.CPU = (Get-CimInstance -ClassName Win32_Processor -CimSession $CimSession).Name

            # RAM
            $MachineInfo.RAM = [Math]::Round(
                (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).TotalPhysicalMemory / 1GB
            )
            
            # Serial nunber
            $MachineInfo.SerialNumber = (Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession).SerialNumber

            # Disk drives
            $Disks = @()
            $MachineDisks = Get-PhysicalDisk -CimSession $CimSession

            foreach ($Disk in $MachineDisks) {
                $DiscInfoObject = New-Object -TypeName DiskInfo

                $DiscInfoObject.Status = $Disk.HealthStatus
                $DiscInfoObject.Index = $Disk.DeviceId
                $DiscInfoObject.Model = $Disk.FriendlyName
                $DiscInfoObject.Type = $Disk.MediaType
                $DiscInfoObject.Bus = $Disk.BusType
                $DiscInfoObject.TotalSize = [Math]::Round($Disk.Size / 1GB)
                $Disks += $DiscInfoObject
            }
            $MachineInfo.Disks = $Disks


            # Trying to get current user and searching in AD  
            $LastUserSid = (
                    Get-CimInstance Win32_UserProfile -CimSession $CimSession | `
                        Where-Object {!$PSItem.Special} | `
                        Sort-Object LastUseTime -Descending |
                        Select-Object -First 1
                ).SID


            # Find in AD
            try {
                $MachineInfo.LastUser = ([adsisearcher]"(objectSID=$LastUserSid)").FindOne().GetDirectoryEntry().userPrincipalName
            }
            catch {
                $MachineInfo.LastUser = (Get-CimInstance Win32_UserAccount -Filter "SID='$LastUserSid'" -CimSession $CimSession).Caption
            }
            if (!$MachineInfo.LastUser) {
                $MachineInfo.LastUser = 'NoData'
            }

            
            # Searching connected monitors
            $Monitors = @()
            $MonitorsFromWmi = @()
            try {
                $MonitorsFromWmi = Get-CimInstance -Namespace root/WMI `
                    -ClassName WmiMonitorID `
                    -CimSession $CimSession `
                    -ErrorAction Stop
            }
            catch {
                $MachineInfo.Monitors = $Monitors
            }
            foreach ($WmiMonitor in $MonitorsFromWmi) {
                $Monitors += [MonitorInfo]::new( 
                    $WmiMonitor.Active,
                    [string]::Join('',($WmiMonitor.ManufacturerName | `
                            Where-Object {$PSItem -ne 0} | `
                            ForEach-Object {[char]$PSItem}
                        )
                    ), 
                    [string]::Join('',($WmiMonitor.UserFriendlyName | `
                            Where-Object {$PSItem -ne 0} | `
                            ForEach-Object {[char]$PSItem}
                        )
                    ), 
                    [string]::Join('',($WmiMonitor.SerialNumberID | `
                            Where-Object {$PSItem -ne 0} | `
                            ForEach-Object {[char]$PSItem}
                        )
                    )
                )
            }
            $MachineInfo.Monitors = $Monitors
            

            # So UPS like monitors
            $UPSs = @()
            foreach ($Ups in (Get-CimInstance -ClassName Win32_Battery -CimSession $CimSession).DeviceID) {
                $UPSs += $Ups
            }
            $MachineInfo.UPSs = $UPSs

            # Define IPs and HostName

            # $DomainNics = @()
            # $DomainNics += (
            #     Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -CimSession $CimSession| `
            #         Where-Object {
            #             $PSItem.DNSdomain -eq "$(
            #                     (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).Domain
            #                 )"
            #         }
            # ).Index
            # $DomainNicIndex = $DomainNics[0]

            $MachineInfo.IPAddress = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -CimSession $CimSession | `
                Where-Object {
                    $PSItem.IPAddress # -and `
                    # ($PSItem.Index -eq $DomainNicIndex)
                } | ForEach-Object {$PSItem.IPAddress[0]}
            )

            $MachineInfo.MACAddress = (
                Get-CimInstance -ClassName Win32_NetworkAdapter -CimSession $CimSession | `
                    Where-Object {
                        $PSItem.DeviceID -and
                        $PSItem.NetEnabled -and
                        $PSItem.PhysicalAdapter # -and 
                        # $PSItem.DeviceID -eq $DomainNicIndex
                    }
            ).MACAddress

            $MachineInfo.HostName = (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).DNSHostName + 
                '.' +
                (Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession).Domain
        
            
            Remove-CimSession -CimSession $CimSession
            $InventoryTotal += $MachineInfo
            $MachineInfo       
        }
    }

    END {
        # Procesing export options...
        if ($Csv) {
            $Date = Get-Date -Format yyyy-MM-dd
            $FileName = "InventoryReport_$Date.csv"
            $CsvPath = Join-Path -Path $ExportPath -ChildPath $FileName
            $InventoryTotal.ToTableObject() | Export-Csv -Path "$CsvPath" -UseCulture -Encoding UTF8
            Write-Host "Csv export done: $CsvPath" -ForegroundColor Green
        }

        if ($Json) {
            $Date = Get-Date -Format yyyy-MM-dd
            $FileName = "InventoryReport_$Date.Json"
            $JsonPath = Join-Path -Path $ExportPath -ChildPath $FileName
            $InventoryTotal| ConvertTo-Json -Depth 5 | Out-File -FilePath $JsonPath -Encoding UTF8 
            Write-Host "Json export done: $JsonPath" -ForegroundColor Green   
        }

        if ($Excel) {
            $InventoryTotal.ToTableObject() | `
                Export-Excel -Propetries Status,
                    HostName,
                    IPAddress,
                    MACAddress,
                    SerialNumber,
                    Model,
                    CPU,
                    RAM,
                    Disks,
                    Monitors,
                    UPSs,
                    LastUser `
                -ExportTo $ExportPath -Name "InventoryReport" -NotReplace
        }
    }
}



##############################################################
####                 Parse IAS/NPS log file               ####
##############################################################
# Not mine function, but may the force be with the author.
function Get-IASLog {
        <# 
    .SYNOPSIS 
        Log parser/interpreter for MS NPS RADIUS Logs 
    .DESCRIPTION 
        Easy parse and interpret Data from MS NPS RADIUS log file. 
        !!! You must Have MS NPS/RADIUS Logs in "IAS (Legacy)" Format Created Daily !!! LogNames in format:
        "IN" + Last two numbers of current year + number of current month + number of current day + .log
        For Example: At 2015-10-23 You have: IN151023.log
        
        At this script in "Variables" section I Hard-Coded names of NPS/RADIUS Servers (RADIUS1 and RADIUS2) and Path to shared logs (Logs)
        You must change that variables corresponding to Your Enivornment

    .NOTES 
        Author         : Marcin Krzanowicz - mkrzanowicz@gmail.com 
        Author Website : http://mkrzanowicz.pl 
    .LINK 
        https://technet.microsoft.com/en-us/library/cc785145(v=ws.10).aspx
        https://technet.microsoft.com/en-us/library/cc771748%28v=ws.10%29.aspx
        http://www.iana.org/assignments/radius-types/radius-types.xhtml
    .EXAMPLE 
        NAP_Parser.ps1 -SearchData id12345
        Get RADIUS Events with 'id12345' Data in Log file (Last 2 days in Logs [Default] searched + Full Info about Events)
    .EXAMPLE 
        NAP_Parser.ps1 -SearchData id12345 -SearchDays 5
        Get RADIUS Events with 'id12345' Data in Log file (Last 5 days in Logs searched + Full Info about Events)
    .EXAMPLE 
        NAP_Parser.ps1 -SearchData id12345 -BaseInfo
        Get Base (only necessary info) RADIUS Events with 'id12345' Data in Log file (Last 2 days in Logs [Default] searched)
    .EXAMPLE 
        NAP_Parser.ps1 -SearchData id12345 -NotStreaming
        Get Base (only necessary info) RADIUS Events with 'id12345' Data in Log file in Formatted Table (Not streaming data on display)
    .EXAMPLE 
        NAP_Parser.ps1 -SearchData
        Get Full Info about All RADIUS Events (Default Last 2 days)
    .EXAMPLE 
        NAP_Parser.ps1 -filename D:\NAP\iaslog7.log -BaseInfo
        Interpret Logs from specified File Logs
    #>  

    
    param (
        $filename = $null,						#Analyze LogFile
        [int]$SearchDays = 2,					#Days to search Logs; Default = 2
        [string]$SearchData = $null,			#Search LogFile for specified data
        [switch]$BaseInfo,						#Display only base info about Events
        [switch]$NotStreaming					#Format All Data into Table (not Live Dispaly like default $BaseInfo). 
    ) 

    ##############################################
    # RADIUS/NPS Documented Parameters and meanings

    $PACKET_TYPES = @{ 
    1 = "Access-Request"; 
    2 = "Access-Accept"; 
    3 = "Access-Reject"; 
    4 = "Accounting-Request";
    5 = "Accounting-Response";
    6 = "Accounting-Status";
    7 = "Password-Request";
    8 = "Password-Ack";
    9 = "Password-Reject";
    10 = "Accounting-Message";
    11 = "Access-Challenge";
    21 = "Resource-Free-Request";
    22 = "Resource-Free-Response";
    23 = "Resource-Query-Request";
    24 = "Resource-Query-Response";
    25 = "Alternate-Resource-Reclaim-Request";
    26 = "NAS-Reboot-Request";
    27 = "NAS-Reboot-Response";	
    29 = "Next-Passcode";
    30 = "New-Pin";
    31 = "Terminate-Session";
    32 = "Password-Expired";
    33 = "Event-Request";
    34 = "Event-Response"; 	
    40 = "Disconnect-Request";
    41 = "Disconnect-ACK";
    42 = "Disconnect-NAK";
    43 = "CoA-Request";
    44 = "CoA-ACK";
    45 = "CoA-NAK";
    50 = "IP-Address-Allocate";
    51 = "IP-Address-Release";
    } 

    $LOGIN_SERVICES =@{
    0  = "Telnet";
    1  = "Rlogin";
    2  = "TCP Clear";
    3  = "PortMaster";
    4  = "LAT";
    5  = "X25-PAD";
    6  = "X25-T3POS";
    8  = "TCP Clear Quiet"
    }

    $SERVICE_TYPES = @{
    1 =	"Login";
    2 =	"Framed";
    3 =	"Callback Login";
    4 =	"Callback Framed";
    5 =	"Outbound";
    6 =	"Administrative";
    7 =	"NAS Prompt";
    8 =	"Authenticate Only";
    9 =	"Callback NAS Prompt";
    10 = "Call Check";
    11 = "Callback Administrative";
    12 = "Voice";
    13 = "Fax";
    14 = "Modem Relay";
    15 = "IAPP-Register";
    16 = "IAPP-AP-Check";
    17 = "Authorize Only";
    18 = "Framed-Management"
    19 = "Additional-Authorization"
    }

    $AUTHENTICATION_TYPES = @{ 
    1 = "PAP";
    2 = "CHAP";
    3 = "MS-CHAP";
    4 = "MS-CHAP v2";
    5 = "EAP";
    7 = "None";
    8 = "Custom";
    11 = "PEAP"
    }  

    $REASON_CODES = @{ 
    0 = "IAS_SUCCESS"; 
    1 = "IAS_INTERNAL_ERROR"; 
    2 = "IAS_ACCESS_DENIED"; 
    3 = "IAS_MALFORMED_REQUEST"; 
    4 = "IAS_GLOBAL_CATALOG_UNAVAILABLE"; 
    5 = "IAS_DOMAIN_UNAVAILABLE"; 
    6 = "IAS_SERVER_UNAVAILABLE"; 
    7 = "IAS_NO_SUCH_DOMAIN"; 
    8 = "IAS_NO_SUCH_USER"; 
    16 = "IAS_AUTH_FAILURE"; 
    17 = "IAS_CHANGE_PASSWORD_FAILURE"; 
    18 = "IAS_UNSUPPORTED_AUTH_TYPE"; 
    32 = "IAS_LOCAL_USERS_ONLY"; 
    33 = "IAS_PASSWORD_MUST_CHANGE"; 
    34 = "IAS_ACCOUNT_DISABLED"; 
    35 = "IAS_ACCOUNT_EXPIRED"; 
    36 = "IAS_ACCOUNT_LOCKED_OUT"; 
    37 = "IAS_INVALID_LOGON_HOURS"; 
    38 = "IAS_ACCOUNT_RESTRICTION"; 
    48 = "IAS_NO_POLICY_MATCH"; 
    64 = "IAS_DIALIN_LOCKED_OUT"; 
    65 = "IAS_DIALIN_DISABLED"; 
    66 = "IAS_INVALID_AUTH_TYPE"; 
    67 = "IAS_INVALID_CALLING_STATION"; 
    68 = "IAS_INVALID_DIALIN_HOURS"; 
    69 = "IAS_INVALID_CALLED_STATION"; 
    70 = "IAS_INVALID_PORT_TYPE"; 
    71 = "IAS_INVALID_RESTRICTION"; 
    80 = "IAS_NO_RECORD"; 
    96 = "IAS_SESSION_TIMEOUT"; 
    97 = "IAS_UNEXPECTED_REQUEST"; 
    } 

    $ACCT_TERMINATE_CAUSES = @{
    1 =	"User Request";
    2 =	"Lost Carrier";
    3 =	"Lost Service";
    4 =	"Idle Timeout";
    5 =	"Session Timeout";
    6 =	"Admin Reset";
    7 =	"Admin Reboot";
    8 =	"Port Error";
    9 =	"NAS Error";
    10 = "NAS Request";
    11 = "NAS Reboot";
    12 = "Port Unneeded";
    13 = "Port Preempted";
    14 = "Port Suspended";
    15 = "Service Unavailable";
    16 = "Callback";
    17 = "User Error";
    18 = "Host Request";
    19 = "Supplicant Restart";
    20 = "Reauthentication Failure";
    21 = "Port Reinitialized";
    22 = "Port Administratively Disabled";
    23 = "Lost Power";
    }

    $ACCT_STATUS_TYPES = @{
    1 =	"Start";
    2 =	"Stop";
    3 =	"Interim-Update";	
    7 =	"Accounting-On";
    8 =	"Accounting-Off";
    9 =	"Tunnel-Start";
    10 = "Tunnel-Stop";
    11 = "Tunnel-Reject";
    12 = "Tunnel-Link-Start";
    13 = "Tunnel-Link-Stop";
    14 = "Tunnel-Link-Reject";
    15 = "Failed";
    }

    $ACCT_AUTHENTICS = @{
    1 =	"RADIUS";
    2 =	"Local";
    3 =	"Remote";
    4 =	"Diameter";
    }

    $PARAMETERS =@{
    4 =	"NAS-IP-Address";				#The IP address of the NAS originating the request.
    5 =	"NAS-Port";	 					#The physical port number of the NAS originating the request.
    7 = "Framed-Protocol";				#The protocol to be used.
    8 =	"Framed-IP-Address";			#The framed address to be configured for the user.
    9 =	"Framed-IP-Netmask"; 			#The IP netmask to be configured for the user.
    10 = "Framed-Routing";				#The Routing method to be used by the user.
    11 = "Filter-ID";					#The name of the filter list for the user requesting authentication.
    12 = "Framed-MTU";					#The maximum transmission unit to be configured for the user.
    13 = "Framed-Compression";			#The compression protocol to be used.
    14 = "Login-IP-Host";				#The IP address of the host to which the user should be connected.
    16 = "Login-TCP-Port";				#The TCP port to which the user should be connected.
    18 = "Reply-Message";				#The message displayed to the user when an authentication request is accepted.
    19 = "Callback-Number";				#The callback phone number.
    20 = "Callback-ID";					#The name of a location to be called by the access server when performing callback.
    22 = "Framed-Route";				#The routing information that is configured on the access client.
    23 = "Framed-IPX-Network";			#The IPX network number to be configured on the NAS for the user.
    25 = "Class";						#The attribute sent to the client in an Access-Accept packet, which is useful for correlating Accounting-Request packets with authentication sessions. The format is:
    27 = "Session-Timeout";				#The length of time (in seconds) before a session is terminated.
    28 = "Idle-Timeout";				#The length of idle time (in seconds) before a session is terminated.
    29 = "Termination-Action";			#The action that the NAS should take when service is completed.
    30 = "Called-Station-ID";			#The phone number that is dialed by the user.
    31 = "Workstation-MAC";				#The MAC Address - calling workstation
    32 = "NAS-Identifier";				#The string that identifies the NAS originating the request.
    34 = "Login-LAT-Service";			#The host with which the user is to be connected by LAT.
    35 = "Login-LAT-Node";				#The node with which the user is to be connected by LAT.
    36 = "Login-LAT-Group";				#The LAT group codes for which the user is authorized.
    37 = "Framed-AppleTalk-Link";		#The AppleTalk network number for the serial link to the user (this is used only when the user is a router).
    38 = "Framed-AppleTalk-Network";	#The AppleTalk network number that the NAS must query for existence in order to allocate the user's AppleTalk node.
    39 = "Framed-AppleTalk-Zone";		#The AppleTalk default zone for the user.
    41 = "Acct-Delay-Time";				#The length of time (in seconds) for which the NAS has been sending the same accounting packet.
    42 = "Acct-Input-Octets";			#The number of octets received during the session.
    43 = "Acct-Output-Octets";			#The number of octets sent during the session.
    44 = "Acct-Session-ID";				#The unique numeric string that identifies the server session.
    46 = "Acct-Session-Time";			#The length of time (in seconds) for which the session has been active.
    47 = "Acct-Input-Packets";			#The number of packets received during the session.
    48 = "Acct-Output-Packets";			#The number of packets sent during the session.
    50 = "Acct-Multi-SSN-ID";			#The unique numeric string that identifies the multilink session.
    51 = "Acct-Link-Count";				#The number of links in a multilink session.
    55 = "Event-Timestamp";				#The date and time that this event occurred on the NAS.
    61 = "NAS-Port-Type";				#The type of physical port that is used by the NAS originating the request.
    62 = "Port-Limit";					#The maximum number of ports that the NAS provides to the user.
    63 = "Login-LAT-Port";				#The port with which the user is connected by Local Area Transport (LAT).
    64 = "Tunnel-Type";					#The tunneling protocols to be used.
    65 = "Tunnel-Medium-Type";			#The transport medium to use when creating a tunnel for protocols. For example, L2TP packets can be sent over multiple link layers.
    66 = "Tunnel-Client-Endpt";			#The IP address of the tunnel client.
    67 = "Tunnel-server-Endpt";			#The IP address of the tunnel server.
    68 = "Acct-Tunnel-Connection";		#An identifier assigned to the tunnel.
    75 = "Password-Retry";				#The number of times a user can try to be authenticated before the NAS terminates the connection.
    76 = "Prompt";						#A number that indicates to the NAS whether or not it should (Prompt=1) or should not (Prompt=0) echo the userâ€™s response as it is typed.
    77 = "Connect-Info";				#Information that is used by the NAS to specify the type of connection made. Typical information includes connection speed and data encoding protocols.
    78 = "Configuration-Token";			#The type of user profile to be used (sent from a RADIUS proxy server to a RADIUS proxy client) in an Access-Accept packet.
    81 = "Tunnel-Pvt-Group-ID";			#The group ID for a particular tunneled session.
    82 = "Tunnel-Assignment-ID";		#The tunnel to which a session is to be assigned.
    83 = "Tunnel-Preference";			#A number that indicates the preference of the tunnel type, as indicated with the Tunnel-Type attribute when multiple tunnel types are supported by the access server.
    85 = "Acct-Interim-Interval";		#The length of interval (in seconds) between each interim update sent by the NAS.
    87 = "SwitchInterface";
    #107 to 255	Ascend					#The vendor-specific attributes for Ascend. For more information, see the Ascend documentation.
    4108 = "Switch-IP-Address";			#The IP address of the RADIUS client.
    4116 = "NAS-Manufacturer";			#The manufacturer of the NAS.
    4121 = "MS-CHAP-Error";				#The error data that describes an MS-CHAP transaction.
    4127 = "Authentication-Type";		#The authentication scheme that is used to verify the user.
    4128 = "Switch-Friendly-Name";		#The friendly name for the RADIUS client.
    4129 = "SAM-Account-Name";			#The user account name in the Security Accounts Manager (SAM) database.
    4130 = "Fully-Qualified-User-Name";	#The user name in canonical format.
    4132 = "EAP-Friendly-Name";			#The friendly name that is used with Extensible Authentication Protocol (EAP).
    4136 = "Packet-Type";				#The type of packet		
    4142 = "Reason-Code";				#The Reason Code
    4149 = "NPS-Policy-Name";			#The friendly name of a remote access policy.
    4154 = "Connection-Request-Policy";
    4155 = "Not_Documented";
    }

    ##############################################

    # VARIABLES 

    $Servers = New-Object System.Collections.Arraylist
    $Logpaths = New-Object System.Collections.Arraylist

    $Servers += 'DC1-RS-01'     #You must change it to name of Your NPS/RADIUS Server
    $logs = '\LogFiles\'          #You must change it to name of Your shared folder with NPS/RADIUS Logs with '\' char at the beginning and at the end

    ##############################################

    if ( [string]::IsNullOrEmpty($filename) )
    { 	
    $DateAfter = (Get-Date).AddDays(-$SearchDays+1)
    $DateBefore = (Get-Date).AddDays(+1)
    $After = "IN" + (([string]($DateAfter.Year)).PadLeft(2,"0")).ToString().Substring(2) + ([string]($DateAfter.Month)).PadLeft(2,"0")+ ([string]($DateAfter.Day)).PadLeft(2,"0")
    $Before = "IN" + (([string]($DateBefore.Year)).PadLeft(2,"0")).ToString().Substring(2) + ([string]($DateBefore.Month)).PadLeft(2,"0") + ([string]($DateBefore.Day)).PadLeft(2,"0")

    $Servers | ForEach-Object {$Logpaths += "\\" + $PSItem + $logs }

    if ([string]::IsNullOrEmpty($SearchData) )
    {
        $content = Get-Content ( Get-Childitem $Logpaths -Include *.log  | Where-Object { ($PSItem.Name.Length -lt '13' -and  $PSItem.Name -ge $after -and  $PSItem.Name -le $before) } )
    }
    else
    {
        $content = Get-Content (Get-Childitem $Logpaths -Include *.log | Where-Object{ ($PSItem.Name.Length -lt '13' -and  $PSItem.Name -ge $after -and  $PSItem.Name -le $before) } ) | Select-String -Pattern $SearchData 
    }
    }
    else
    {
    if ([string]::IsNullOrEmpty($SearchData) )
    {
        $content = Get-Content $filename
    } 
    else 
    {
        $content =  Get-Content $filename | Select-String -Pattern $SearchData
    }
    }

    $FormattedBaseOutput = New-Object System.Collections.Arraylist

    foreach ($line in $content) 
    { 

    $Tab = $line -split ','
    $i = 6                                #First 6 positions are Header
    $LogParameters = @{}

    do 
    {
        if ( $tab[$i] -eq '4142')
        {
            $name = 'Reason-Code'
            $next = $i+1
            [int]$Val = $tab[$next]
            [string]$Value = $null
            $Value = ($REASON_CODES[$Val])
            try
            {
            $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif ( $tab[$i] -eq '4136' )
        {
            $name = 'Packet-Type'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($PACKET_TYPES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif ($tab[$i] -eq '4127')
        {
            $name = 'Authentication-Type'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($AUTHENTICATION_TYPES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        } 
        elseif ( $tab[$i] -eq '15' )
        {
            $name = 'Login-Service'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($LOGIN_SERVICES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif($tab[$i] -eq '6')
        {
            $name = 'Service-Type'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($SERVICE_TYPES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif ($tab[$i] -eq '49')
        {
            $name = 'Acct-Terminate-Cause'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($ACCT_TERMINATE_CAUSES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif ($tab[$i] -eq '40')
        {
            $name = 'Acct-Status-Type'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($ACCT_STATUS_TYPES[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        elseif ($tab[$i] -eq '45')
        {
            $name = 'Acct-Authentic'
            $next = $i+1
            [int]$val = $tab[$next]
            [string]$Value = $null
            $Value = ($ACCT_AUTHENTICS[$Val])
            try
            {
                $LogParameters.Add($name,$value)
            }
            catch
            {
                $null
            }
        }
        else
        {
        try
        {
            [int]$curr = $tab[$i]
            $name = $PARAMETERS[$curr]
            [int]$next = $i+1
            $value = $tab[$next]
            $LogParameters.Add($name,$value)
        }
        catch
        {
                $null
        }
        }
        $i++
    }
    while ($i -le $tab.count)

    $logobj = New-Object PSObject 
    Add-Member -InputObject $logobj -MemberType NoteProperty -name "SwitchIP" -value $($tab[0])   # This is 802.1x Client IP, but in most common Case Clinet = 802.1x Switch
    Add-Member -InputObject $logobj -MemberType NoteProperty -name "Username" -value $($tab[1])
    Add-Member -InputObject $logobj -MemberType NoteProperty -name "Date-Time" -value $($($tab[3]) + " " + $($tab[2]) )
    Add-Member -InputObject $logobj -MemberType NoteProperty -name "RADIUS-Server" -value $($tab[5])    # !!!!!!!!!!!!!!!!!!!!!!!!!!! DO sprawdzenia, czy nie 4
    $LogParameters.GetEnumerator() | ForEach-Object { try {Add-Member -InputObject $logobj -MemberType NoteProperty -name $($PSItem.Name) -value $($PSItem.Value) }  catch {$null} }  # In specific Events the same parameters are serveral times, so without catch generates errors
    
    $FormattedBaseOutput += $logobj

    if ($NotStreaming)
    {
        $null
    }
    elseif ($BaseInfo)
    {
        $logobj | Format-Table Date-Time, Username, Workstation-MAC, SwitchIP, SwitchInterface, NPS-Policy-Name, Packet-Type, Reason-Code -AutoSize 
    }
    else
    {
        $logobj 
    }

    }
    if ($NotStreaming)
    {
    $FormattedBaseOutput | Format-Table Date-Time, Username, Workstation-MAC, SwitchIP, NPS-Policy-Name, Packet-Type, Reason-Code -AutoSize
    }   
}


##############################################################
####             Get parent organizational unit           ####
##############################################################
function Get-ADParent {
    [CmdletBinding()]
    param (
        # User or computer name
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('DistinguishedName')]
        [string]$Identity,

        # Properties of parent object
        [Parameter(
            Mandatory = $false
        )]
        [string[]]$Properties = @('Name','description')
    )

    begin {
        # Import ActiveDirectory if avaliable.
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            throw "ActiveDirectory powershell module required. Install RSAT and try again"
        }
    }
    process {
        foreach ($ObjectName in $Identity) {
            try {
                $TargetADObject = Get-ADObject $ObjectName -ErrorAction Stop
            }
            catch {
                try {
                    $TargetADObject = Get-ADUser $ObjectName -ErrorAction Stop
                }
                catch {
                    try {
                        $TargetADObject = Get-ADComputer $ObjectName -ErrorAction Stop            
                    }
                    catch {
                        continue
                    }
                }
            }
            
        
            $ParentObjectDN = ([adsi]"LDAP://$TargetADObject").Parent.Replace('LDAP://','')
            return (Get-ADObject -Identity $ParentObjectDN -Properties $Properties)
        }
    }
    end {}   
}




##############################################################
####                 Convert string to hex                ####
##############################################################
function Convert-StringToHex {
    [cmdletbinding()]
    param(
        [Parameter(
            Mandatory=$true,
            Position = 0
        )]
        [string]$String
    )
    [Byte[]]$Bytes = $String.ToCharArray()
    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    foreach ($Byte in $Bytes) {
        $HexString.AppendFormat("{0:x2}", $Byte) | Out-Null
    }
    return $HexString.ToString()
}




##############################################################
####                 Convert string to hex                ####
##############################################################
function Convert-HexToString {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            Position = 0
        )]
        [String]$HexString
    )
    $Bytes = [byte[]]::new($HexString.Length / 2)

    for ($i=0; $i -lt $HexString.Length; $i+=2) {
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    $String = [char[]]$Bytes -join ''
    return $String
}



##############################################################
####               Delay restarting servers               ####
##############################################################
function Restart-Server {
    [CmdletBinding()]
    param (
        # List of servers
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string[]]$ComputerName,

        # date of reboot
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [ValidatePattern("^(3[01]|[12][0-9]|0?[1-9])\.(1[012]|0?[1-9])\.((?:19|20)\d{2})$")]
        [string]$Date,

        
        # Time of reboot
        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [ValidatePattern("^([0-1][0-9]|[2][0-3]):([0-5][0-9])$")]
        [string]$Time
    )
    
    begin {
        try {
            $RebootDateTime = [datetime]::ParseExact("$Date $Time", "dd.MM.yyyy HH:mm", $null)
        }
        catch {
            break
        }

        $ServerCimSessions = @()
    }
    
    process {
        foreach ($Server in $ComputerName) {
            try {
                $ServerCimSessions += New-CimSession -ComputerName $Server -ErrorAction Stop
                Write-Host "CONNECTED " -NoNewline -ForegroundColor Green
                Write-Host ": $Server"
            }
            catch {
                Write-Host "FAILED " -NoNewline -ForegroundColor Red
                Write-Host ": $Server"
            }
        }
    }
    
    end {
        $Trigger = New-ScheduledTaskTrigger -Once -At $RebootDateTime 
        $Action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c shutdown -r -t 0"
        $Principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "Reboot" -Trigger $Trigger -Action $Action -Principal $Principal -Force -CimSession $ServerCimSessions
    }
}



##############################################################
####                     Check Ports                      ####
##############################################################
function Test-Port {
    param (
        # Hostname or ip address
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string]$ComputerName,

        # TCP port number
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [int]$Port,
        
        # Timeout (ms)
        [Parameter(
            Mandatory = $false
        )]
        [int]$Timeout = 1000
    )


    # Create TCP Client
    $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

    # Tell TCP Client to connect to machine on Port
    $Connection = $TcpClient.BeginConnect($ComputerName,$Port,$null,$null)

    # Set the wait time
    $Wait = $Connection.AsyncWaitHandle.WaitOne($Timeout,$false) 

    # Check to see if the connection is done
    if ($Wait) {
        try {
            $TcpClient.EndConnect($Connection)
        }
        catch {
            $TcpClient.Close()
            return $false
        }
        
        $TcpClient.Close()
        return $true
    }

    else {
        $TcpClient.Close()
        return $false
    }
}



##############################################################
####              Get password experation date            ####
##############################################################
function Get-PasswordExperationDate {
    [CmdletBinding()]
    param (
        # Username list
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [string[]]$SamAccountName,

        # Domain to search. Own at default
        [Parameter(
            Mandatory = $false
        )]
        [string]$Domain = ($env:USERDNSDOMAIN).ToLower()
    )
    
    begin {
        Import-Module ActiveDirectory
        $Result = @()
        Write-Debug "Begin done"
    }
    
    process {
        foreach ($User in $SamAccountName) {
            Write-Debug "Processing $User"
            try {
                $ADUser = Get-ADUser -Identity $User -Properties PasswordLastSet,msDS-UserPasswordExpiryTimeComputed,PasswordNeverExpires,Enabled
            }
            catch {
                Write-Error -Message "User $User not found in domain $Domain" `
                    -Category ObjectNotFound `
                    -RecommendedAction "Check if username existing." `
                    -TargetObject "$User" `
                    -ErrorId 1
                continue
            }

            Set-StrictMode -Version Latest
            $Result += [PSCustomObject]@{
                Name = $ADUser.Name
                SamAccountName = $ADUser.SamAccountName
                Enabled = $ADUser.Enabled
                PasswordLastSet = $ADUser.PasswordLastSet
                PasswordExpires = & {
                    try {
                        [datetime]::FromFileTime($ADUser."msDS-UserPasswordExpiryTimeComputed") 
                    }
                    catch {
                        [DateTime]::MaxValue
                    }
                }
                DaysLeft = & {
                    try {
                        ([datetime]::FromFileTime($ADUser."msDS-UserPasswordExpiryTimeComputed") - (Get-Date)).Days
                    } 
                    catch {
                        -1
                    }
                }
                PasswordNeverExpires = $ADUser.PasswordNeverExpires
            }
            Set-StrictMode -Off
        }
    }
    
    end {
        return $Result
    }
}



##############################################################
####            Record log entry in CM style              ####
##############################################################
function Write-CMLog {
    [CmdletBinding()]
    Param(
        # Log message
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0

        )]
        [string]$Message,
        
        # Log file
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$LogFilePath,

        # Log file
        [Parameter(
            Mandatory = $true,
            Position = 2
        )]
        [ValidateSet(
            'Info',
            'Warning',
            'Error'
        )]
        [string]$Level,

        # Component name
        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [String]$Component,

        # Source
        [Parameter(
            Mandatory=$false
        )]
        [String]$Source        
    )

    # Define record type
    switch ($Level) {
        "Info" {[int]$Type = 1}
        "Warning" {[int]$Type = 2}
        "Error" {[int]$Type = 3}
    }

    if (!$Component) {
        $Component = [System.IO.Path]::GetFileName($($MyInvocation.ScriptName))
        if (!$Component) {
            $Component = "PSConsole"
        }    
    }


    # Create a log entry
    $Content = "<![LOG[$Message]LOG]!>" +`
        "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " +`
        "date=`"$(Get-Date -Format "M-d-yyyy")`" " +`
        "component=`"$Component`" " +`
        "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " +`
        "type=`"$Type`" " +`
        "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " +`
        "file=`"`">"

    # Write the line to the log file
    [bool]$LogSuccess = $false
    $AttemptsLeft = 10
    while (!($LogSuccess -or $AttemptsLeft -eq 0)) {
        try {
            Add-Content -Path $LogFilePath -Value $Content -Encoding UTF8 -ErrorAction Stop
            $LogSuccess = $true
        }
        catch {
            $Error.RemoveAt(0)                
            Start-Sleep -Milliseconds (Get-Random (10..99))
        }
        $AttemptsLeft--
    }
}


##############################################################
####          Record log entry in simple style            ####
##############################################################
function Write-Log {
    [CmdletBinding()]
    param (
        # Log message
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0

        )]
        [string]$Message,
        
        # Log file
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$LogFilePath,

        # Log file
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateSet(
            'INFO',
            'WARN',
            'FAIL'
        )]
        [string]$Level = 'INFO'
    )

    if (!(Test-Path $LogFilePath)) {
        $ScriptPath = $MyInvocation.MyCommand.Path
        if (!$ScriptPath) {
            $ScriptPath = "PowerShell CLI"
        }
        "#  This is $([System.IO.Path]::GetFileNameWithoutExtension($LogFilePath)) log from $ScriptPath" | Out-File $LogFilePath -Encoding utf8 
        "# " | Out-File $LogFilePath -Encoding utf8 -Append #-NoNewline
        # [string]::Join('',(1..80 | ForEach-Object {'='})) | Out-File $LogFilePath -Encoding utf8 -Append
    }

    $LogString = "$(Get-Date -Format "dd.MM.yyyy HH:mm:ss") : $Level : $Message" 
    Write-Verbose $LogString
    $LogString | Out-File $LogFilePath -Encoding utf8 -Append
}




##############################################################
####                 IP address calculator                ####
##############################################################
function Get-IPAddressCalculation {
    <#PSScriptInfo
 
    .VERSION 1.0.3
    
    .GUID cb059a0e-09b6-4756-8df4-28e997b9d97f
    
    .AUTHOR saw-friendship@yandex.ru
    
    .COMPANYNAME
    
    .COPYRIGHT
    
    .TAGS IP Subnet Calculator WildCard CIDR
    
    .LICENSEURI
    
    .PROJECTURI https://sawfriendship.wordpress.com/
    
    .ICONURI
    
    .EXTERNALMODULEDEPENDENCIES
    
    .REQUIREDSCRIPTS
    
    .EXTERNALSCRIPTDEPENDENCIES
    
    .RELEASENOTES
    
    
    #>

    <#
    
    .DESCRIPTION
    IP Calculator for calculation IP Subnet
    
    .EXAMPLE
    IP-Calc -IPAddress 192.168.0.0 -Mask 255.255.255.0
    
    IP : 192.168.0.0
    Mask : 255.255.255.0
    PrefixLength : 24
    WildCard : 0.0.0.255
    IPcount : 256
    Subnet : 192.168.0.0
    Broadcast : 192.168.0.255
    CIDR : 192.168.0.0/24
    ToDecimal : 3232235520
    IPBin : 11000000.10101000.00000000.00000000
    MaskBin : 11111111.11111111.11111111.00000000
    SubnetBin : 11000000.10101000.00000000.00000000
    BroadcastBin : 11000000.10101000.00000000.11111111
    
    
    .EXAMPLE
    IP-Calc -IPAddress 192.168.3.0 -PrefixLength 23
    
    IP : 192.168.3.0
    Mask : 255.255.254.0
    PrefixLength : 23
    WildCard : 0.0.1.255
    IPcount : 512
    Subnet : 192.168.2.0
    Broadcast : 192.168.3.255
    CIDR : 192.168.2.0/23
    ToDecimal : 3232236288
    IPBin : 11000000.10101000.00000011.00000000
    MaskBin : 11111111.11111111.11111110.00000000
    SubnetBin : 11000000.10101000.00000010.00000000
    BroadcastBin : 11000000.10101000.00000011.11111111
    
    
    .EXAMPLE
    IP-Calc -IPAddress 192.168.0.0 -WildCard 0.0.3.0
    
    IP : 192.168.0.0
    Mask : 255.255.252.255
    PrefixLength : 30
    WildCard : 0.0.3.0
    IPcount : 4
    Subnet : 192.168.0.0
    Broadcast : 192.168.3.0
    CIDR : 192.168.0.0/30
    ToDecimal : 3232235520
    IPBin : 11000000.10101000.00000000.00000000
    MaskBin : 11111111.11111111.11111100.11111111
    SubnetBin : 11000000.10101000.00000000.00000000
    BroadcastBin : 11000000.10101000.00000011.00000000
    
    .EXAMPLE
    IP-Calc -IPAddress 172.16.0.0 -PrefixLength 12
    
    IP : 172.16.0.0
    Mask : 255.240.0.0
    PrefixLength : 12
    WildCard : 0.15.255.255
    IPcount : 1048576
    Subnet : 172.16.0.0
    Broadcast : 172.31.255.255
    CIDR : 172.16.0.0/12
    ToDecimal : 2886729728
    IPBin : 10101100.00010000.00000000.00000000
    MaskBin : 11111111.11110000.00000000.00000000
    SubnetBin : 10101100.00010000.00000000.00000000
    BroadcastBin : 10101100.00011111.11111111.11111111
    
    
    .EXAMPLE
    IP-Calc -IPAddress 192.0.2.48 -PrefixLength 30 -CreateIParrayPassThru
    
    192.0.2.48
    192.0.2.49
    192.0.2.50
    192.0.2.51
    
    #> 


    [CmdletBinding(DefaultParameterSetName="ParameterSet1")]
    param(
        [parameter(ParameterSetName="ParameterSet1",Position=0)][Alias("IP")][IPAddress]$IPAddress,
        [parameter(ParameterSetName="ParameterSet1",Position=1)][IPAddress]$Mask,
        [parameter(ParameterSetName="ParameterSet1",Position=1)][ValidateRange(0,32)][int]$PrefixLength,
        [parameter(ParameterSetName="ParameterSet1",Position=1)][Alias("Joker")][IPAddress]$WildCard,
        [Parameter(ParameterSetName="ParameterSet2",Position=2,ValueFromPipeline = $true)][string]$CIDR,
        [Parameter(Position=3)][switch]$CreateIParray,
        [Parameter(Position=4)][switch]$CreateIParrayPassThru
    )

    if($CIDR){
        [IPAddress]$IPAddress,[int]$PrefixLength = $CIDR -split '[^\d\.]' -match "\d"
    }
    if($PrefixLength){
        [IPAddress]$Mask = (([string]'1'*$PrefixLength + [string]'0'*(32-$PrefixLength)) -split "(\d{8})" -match "\d" | ForEach-Object {[convert]::ToInt32($_,2)}) -split "\D" -join "."
    }
    if($WildCard){
        $SplitWildCard = $WildCard -split "\." -match "\d"
        [IPAddress]$Mask = ($SplitWildCard | ForEach-Object {255 - $_}) -join "."
    }
    if($Mask){
        $SplitIPAddress = [int[]]@($IPAddress -split "\." -match "\d")
        $ToDecimal = ($SplitIPAddress | ForEach-Object -Begin {$i = 3;$null = $i} -Process {([Math]::Pow(256,$i))*$_; $i--} | Measure-Object -Sum).Sum
        $SplitMask = $Mask -split "\." -match "\d"
        $PrefixLength = 32 - ($SplitMask | ForEach-Object {256-$_} | ForEach-Object {[math]::Log($_,2)} | Measure-Object -Sum).Sum
        $IPBin = ($SplitIPAddress | ForEach-Object {[convert]::ToString($_,2).PadLeft(8,"0")}) -join "."
        $MaskBin = ($SplitMask | Foreach-Object {[convert]::ToString($_,2).PadLeft(8,"0")}) -join "."
        if((($MaskBin -replace "\.").TrimStart("1").Contains("1")) -and (!$WildCard)){
            Write-Warning "Mask Length error, you can try put WildCard"; break
        }
        $WildCard = ($SplitMask | Foreach-Object {255 - $_}) -join "."
        $Subnet = ((0..31 | Foreach-Object {@($IPBin -split "" -match "\d")[$_] -band @($MaskBin -split "" -match "\d")[$_]}) -join '' -split "(\d{8})" -match "\d" | Foreach-Object {[convert]::ToInt32($_,2)}) -join "."
        $SplitSubnet = [int[]]@($Subnet -split "\." -match "\d")
        $SubnetBin = ($SplitSubnet | Foreach-Object {[convert]::ToString($_,2).PadLeft(8,"0")}) -join "."
        $Broadcast = (0..3 | Foreach-Object {[int]$(@($Subnet -split "\." -match "\d")[$_]) + [int]$(@($WildCard -split "\." -match "\d")[$_])}) -join "."
        $SplitBroadcast = [int[]]@($Broadcast -split "\." -match "\d")
        $BroadcastBin = ($SplitBroadcast | Foreach-Object {[convert]::ToString($_,2).PadLeft(8,"0")}) -join "."
        $CIDR = $Subnet + '/' + $PrefixLength
        $IPcount = [math]::Pow(2,$(32 - $PrefixLength))
    }

    $Object = [ordered]@{
    'IP' = $IPAddress.IPAddressToString
    'Mask' = $Mask.IPAddressToString
    'PrefixLength' = $PrefixLength
    'WildCard' = $WildCard.IPAddressToString
    'IPcount' = $IPcount
    'Subnet' = $Subnet
    'Broadcast' = $Broadcast
    'CIDR' = $CIDR
    'ToDecimal' = $ToDecimal
    'IPBin' = $IPBin
    'MaskBin' = $MaskBin
    'SubnetBin' = $SubnetBin
    'BroadcastBin' = $BroadcastBin
    }

    if ($CreateIParray -or $CreateIParrayPassThru){
        $SplitSubnet = $Subnet -split "\." -match "\d"
        $SplitBroadcast = $Broadcast -split "\." -match "\d"
        $w,$x,$y,$z =  @($SplitSubnet[0]..$SplitBroadcast[0]),@($SplitSubnet[1]..$SplitBroadcast[1]),@($SplitSubnet[2]..$SplitBroadcast[2]),@($SplitSubnet[3]..$SplitBroadcast[3])
        $IParray = $w | Foreach-Object {$wi = $_; $x | Foreach-Object {$xi = $_; $y | Foreach-Object {$yi = $_; $z | Foreach-Object {$zi = $_; $wi,$xi,$yi,$zi -join '.'}}}}
        $Object.IParray = $IParray
    }


    if(!$CreateIParrayPassThru){[pscustomobject]$Object}else{$IParray}
}




##############################################################
####          Get net user /domain as PSObject            ####
##############################################################
function Get-NetUserDomain {
    [CmdletBinding()]
    param (
        # User account name
        [Parameter(
            Mandatory = $false,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$SamAccountName = $env:USERNAME
        
    )
    begin {
        $AllResult = @()
    }
    process {
        foreach ($UserName in $SamAccountName) {
            $NetUserDomainStrings = (net user $UserName /DOMAIN | Where-Object {$PSItem -match "\s{4}"}) -replace "\s{4,}",";"
            $Result = New-Object -TypeName psobject                

            foreach ($String in $NetUserDomainStrings) {
                [bool]$PrevProperty = $false
                # Define property name
                $ParsedString = $String.Split(';')

                if ($ParsedString[0]) {
                    $PropertyName = [string]::Join('',($ParsedString[0].Replace("/",' ').Replace("'",'').Split(' ') | ForEach-Object {
                        $PSItem.SubString(0,1).ToUpper() + $PSItem.Substring(1,$_.Length - 1)
                    })).Replace("'",'')

                    Add-Member -InputObject $Result -MemberType NoteProperty -Name $PropertyName -Value (New-Object -TypeName psobject)
                }
                else {
                    $PrevProperty = $true
                }
                
                # Define value type
                switch -regex ($ParsedString[1]) {
                    ("^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}$") {
                        $Value = [datetime]::ParseExact($ParsedString[1],"dd.MM.yyyy HH:mm:ss",$null)
                    }
                    ("\*") {
                        Write-Debug "Groups"
                        $Value = @()
                        $Value += $ParsedString[1].Split('*').Trim(' ')
                    }
                    "(^Yes$)|(^Да$)" {
                        $Value = $true
                    }
                    "(^No$)|(^Нет$)" {
                        $Value = $false
                    }
                    Default {
                        $Value = $ParsedString[1]
                    }
                }

                # Write value
                if (!$PrevProperty) {
                    $Result.$PropertyName = $Value
                }
                else {
                    $SumValue = @()
                    $SumValue += $Result.$PropertyName
                    $SumValue += $Value
                    $Result.$PropertyName = $SumValue
                }

                # Remove empty entries.
                if ((Get-Member -InputObject $Result.$PropertyName).GetType().BaseType.Name -eq 'Array') {
                    $Result.$PropertyName = $Result.$PropertyName | Where-Object {$PSItem}
                }
            }
           $AllResult += $Result              
        }
    }
    end {
        return $AllResult
    }
}




##############################################################
####            Import data from excel files              ####
##############################################################
function Import-Excel {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$FullName
    )

    begin {
        # Create excel process
        $Excel = New-Object -ComObject Excel.Application
        $Excel.Visible = $false
        $Result = @()

    }
    process {
        foreach ($File in $FullName) {
            if (!(Test-Path $File)) {
                Write-Error -Message "File $File not found. It will be skipped." `
                    -RecommendedAction "Check file path and read permissions." `
                    -Category ObjectNotFound `
                    -TargetObject $File `

                continue
            }
            elseif ([System.IO.Path]::GetExtension($File) -notlike ".xls*") {
                Write-Error -Message "File $File is not excel file. It will be skipped." `
                    -RecommendedAction "Check file extension." `
                    -Category InvalidArgument `
                    -TargetObject $File `
                
            }

            $FileItem = Get-Item $File
            $TempFileName = [System.IO.Path]::ChangeExtension([guid]::NewGuid().Guid,'csv')
            $TempFile = Join-Path -Path $Env:TEMP -ChildPath $TempFileName
            $WorkBook = $Excel.Workbooks.Open($FileItem.FullName)
            $WorkBook.SaveAs($TempFile,62)
            $WorkBook.Close()
            $Result += Import-Csv -Path $TempFile -Encoding UTF8 -UseCulture
            Get-ChildItem (Join-Path $env:TEMP '*') -Include $TempFileName | Remove-Item -Force
        }
    }

    end {
        $Excel.Quit()
        return $Result
    }
}


##############################################################
####                   Update script version              ####
##############################################################
function Update-ScriptVersion {
    param (
        # Path to updatind files
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("FullName")]
        [string[]]$Path,

        [Parameter()]
        [switch]$Major,
        
        [Parameter()]
        [switch]$Minor,

        [Parameter()]
        [switch]$Build,

        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string]$ReleaseNotes
    )

    begin {}

    process {
        foreach ($File in $Path) {
            $FileItem = Get-Item $File
            $CurrentVersion = $null
            try {
                $CurrentVersion = (Test-ScriptFileInfo -Path $FileItem.FullName -ErrorAction Stop).Version
            }
            catch {
                Write-Warning "$FileItem has no version info!"
            }
            if ($CurrentVersion) {
                [int]$RevisionVer = $CurrentVersion.Revision + 1
                [int]$BuildVer = $CurrentVersion.Build
                [int]$MinorVer = $CurrentVersion.Minor
                [int]$MajorVer = $CurrentVersion.Major
                if ($Build) {
                    $BuildVer++
                }
                if ($Minor) {
                    $BuildVer = 0
                    $MinorVer++
                }
                if ($Major) {
                    $BuildVer = 0
                    $MinorVer = 0
                    $MajorVer++
                }

                $NewVersion = [System.Version]::new(
                    $MajorVer,
                    $MinorVer,
                    $BuildVer,
                    $RevisionVer
                )

                # Update-ScriptFileInfo -Path $FileItem.FullName -Version $NewVersion -Force
                $ScriptContent = Get-Content -Path $FileItem.FullName -Raw
                $ScriptContent -match "^\s*<#PSScriptInfo\s*[\s\w\.\-\\\/\|\[\],@:;'`"<>=+_()*&^%$#]*#>\s*"
                $InfoBlock = $Matches[0]

                $UpdatedInfoBlock = $InfoBlock `
                    -replace `
                        "\.VERSION\s(\d{1,}\.){3}(\d{1,})`r`n",`
                        ".VERSION $($NewVersion.ToString())`r`n" `
                        -replace `
                            "\.RELEASENOTES\s*[\s\w\.\-\\\/\|\[\],@:;'`"<>=+_()*&^%$#]*#>\s*<#",`
                            ".RELEASENOTES`n$((Get-Date).ToString('dd.MM.yyyy HH:mm'))`n$ReleaseNotes`n`n#>`n`n<#"
                   
                
                $ScriptContent -replace `
                    "^\s*<#PSScriptInfo\s*[\s\w\.\-\\\/\|\[\],@:;'`"<>=+_()*&^%$#]*#>\s*",`
                    $UpdatedInfoBlock | 
                        Out-File $FileItem.FullName -Encoding utf8 -Force
                
            }
      
        }
    }
    end {}
}


##############################################################
####                   Update module version              ####
##############################################################
function Update-ModuleVersion {
    param (
        # Path to updatind files
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("FullName","Path")]
        [string[]]$Module,

        [Parameter()]
        [switch]$Major,
        
        [Parameter()]
        [switch]$Minor,

        [Parameter()]
        [switch]$Build,

        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string]$ReleaseNotes
    )

    begin {}

    process {
        foreach ($File in $Module) {
            try {
                $ManifestPath = [System.IO.Path]::ChangeExtension((Get-Module $File -ErrorAction Stop).Path,'psd1')
            }
            catch {
                $ManifestPath = [System.IO.Path]::ChangeExtension($File,'psd1')
            }
            
            Write-Verbose $ManifestPath
            $CurrentVersion = $null
            try {
                $CurrentVersion = (Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop).Version
                Write-Verbose $CurrentVersion
            }
            catch {
                Write-Warning "$FileItem has no version info!"
            }
            if ($CurrentVersion) {
                [int]$RevisionVer = $CurrentVersion.Revision + 1
                [int]$BuildVer = $CurrentVersion.Build
                [int]$MinorVer = $CurrentVersion.Minor
                [int]$MajorVer = $CurrentVersion.Major
                if ($Build) {
                    $BuildVer++
                }
                if ($Minor) {
                    $BuildVer = 0
                    $MinorVer++
                }
                if ($Major) {
                    $BuildVer = 0
                    $MinorVer = 0
                    $MajorVer++
                }

                $NewVersion = [System.Version]::new(
                    $MajorVer,
                    $MinorVer,
                    $BuildVer,
                    $RevisionVer
                )
                Write-Verbose $NewVersion
                Update-ModuleManifest -Path $ManifestPath -ModuleVersion $NewVersion
                if ($ReleaseNotes) {
                    $ReleaseNotesString = $NewVersion.ToString() + 
                        (Get-Date -Format ' (dd.MM.yyyy): ') +
                        "$ReleaseNotes`n" +
                        (Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop).ReleaseNotes
                    Update-ModuleManifest -Path $ManifestPath -ReleaseNotes $ReleaseNotesString
                }  
            }            
        }
    }
    end {}
}



##############################################################
####      Connect to exchange server via powershell       ####
##############################################################
function Connect-ExchangeServer {
    param (
        # Exchange server FQDN.
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [string]
        $ExchangeServer
    )

    if (!$ExchangeServer) {
        $ExchangeServers = @()
        try {
            $ExchangeServersGroup = ([adsisearcher]"(&(objectClass=group)(cn=Exchange servers))").FindOne().GetDirectoryEntry().member
        }
        catch {
            throw "Cannot find Exchange server $($ExchangeServer) in this forest."
        }
        
        foreach ($Member in $ExchangeServersGroup) {
            $ExchSearcher = [adsisearcher]"(&(objectClass=computer)(distinguishedName=$Member))"
            $null = $ExchSearcher.PropertiesToLoad.Add('dNSHostName')
            try {
                $ExchangeServers += $ExchSearcher.FindOne().GetDirectoryEntry().dNSHostName
                Write-Verbose "$Member is exchange server."
            }
            catch {
                Write-Verbose "$Member is not server."
            }
        }
        $ExchangeServer = $ExchangeServers[0]
    }
        

    $DegrExSess = Get-PSSession | Where-Object {($ComputerName -eq $ExchangeServer) -and ($PSItem.State -ne "Opened")}
    if ($DegrExSess) {
        $DegrExSess | Remove-PSSession -Confirm:$false
    }
    $OpenedExSess = Get-PSSession | Where-Object {($PSItem.ComputerName -eq $ExchangeServer) -and ($PSItem.State -eq "Opened")}
    if (!$OpenedExSess) {
        $Exchange = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/PowerShell/ -Authentication Kerberos
    }
    else {
        $Exchange = $OpenedExSess[0]
    }
    Import-PSSession $Exchange -DisableNameChecking -AllowClobber
}




##############################################################
####    Search user in ActiveDirectory by displayname     ####
##############################################################
function Get-ADUserByName {
    [CmdletBinding()]
    param (
        # User's human name.
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("DisplayName")]
        [string[]]$Name,

         # Properties to load.
         [Parameter(
            Mandatory = $false,
            Position = 1,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("PropertiesToLoad")]
        [string[]]$Properties = @(
            'displayName',
            'Description',
            'EmailAddress',
            'telephoneNumber',
            'AccountExpirationDate',
            'Enabled',
            'Title',
            'DepartMent',
            'Company'
        ),

        # Search base DistinguishedName
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [string]$SearchBase = "$(([adsi]'').distinguishedName)",

        [switch]$ByDisplayName,
        
        [switch]$Strict,

        [switch]$ValidOnly
    )
    
    begin {
        $SurnameAttribute = 'Surname'
        $GivennameAttribute = 'GivenName'
        $MiddlenameAttribute = "MiddleName"

        $NameFilter = $null

        if (!(Get-Module ActiveDirectory)) {
            Import-Module ActiveDirectory
        }
    }
    
    process {
        foreach ($Record in $Name) {
            $RawName = $Record.Trim(' ') -replace "\s{2,}",' '
            Write-Verbose "RAWNAME : $RawName"

            switch -Regex ($RawName) {
                # Фамилия Имя Отчество
                "^([А-ЯЁ][а-яё]{1,}\s){2}([А-ЯЁ][а-яё]{1,})$" {
                    $RawNameParts = $RawName.Split(' ').Split('.') | Where-Object {$PSItem}
                    if ($ByDisplayName) {
                        $NameFilter = "(displayName -eq '$RawName')"
                    }
                    else {
                        $NameFilter = "(" +    
                            "($SurnameAttribute -eq '$($RawNameParts[0])') -and " +
                            "($GivennameAttribute -eq '$($RawNameParts[1])') -and "+
                            "($MiddlenameAttribute -eq '$($RawNameParts[2])')" +
                        ")"
                    }
                    Write-Verbose "PATTERN : Surname GivenName MiddleName"
                    break  
                }

                # Фамилия И.О.
                # Фамилия И. О.
                "^[А-ЯЁ][а-яё]{1,}\s([А-ЯЁ]\.\s{0,}){2}$" {
                    $RawNameParts = $RawName.Split(' ').Split('.')| Where-Object {$PSItem}
                    if ($ByDisplayName) {
                        $NameFilter = "(displayName -like '$($RawNameParts[0]) $($RawNameParts[1])* $($RawNameParts[2])*')"
                    }
                    else {
                        $NameFilter = "(" +
                            "($SurnameAttribute -eq '$($RawNameParts[0])') -and " +
                            "($GivennameAttribute -like '$($RawNameParts[1])*') -and " +
                            "($MiddlenameAttribute -like '$($RawNameParts[2])*')" +
                        ")"
                    }
                    Write-Verbose "PATTERN : Surname G.M."
                    break  
                }

                # И.О.Фамилия 
                # И. О. Фамилия
                "^([А-ЯЁ]\.\s{0,}){2}[А-ЯЁ][а-яё]{1,}$" {
                    $RawNameParts = $RawName.Split(' ').Split('.') | Where-Object {$PSItem}
                    if ($ByDisplayName) {
                        $NameFilter = "(displayName -like '$($RawNameParts[2]) $($RawNameParts[0])* $($RawNameParts[1])*'"
                    }
                    else {
                        $NameFilter = "(" +
                            "($SurnameAttribute -eq '$($RawNameParts[0])') -and " +
                            "($GivennameAttribute -like '$($RawNameParts[1])*') -and " +
                            "($MiddlenameAttribute -like '$($RawNameParts[2])*')" +
                        ")"
                    }
                    Write-Verbose "PATTERN : G.M. Surname"
                    break  
                }
                    

                # Имя Фамилия
                # Фамилия Имя
                "^[А-ЯЁ][а-яё]{1,}\s[А-ЯЁ][а-яё]{1,}$" {
                    $RawNameParts = $RawName.Split(' ') | Where-Object {$PSItem}
                    if ($ByDisplayName) {
                        $NameFilter = "(" + 
                            "(displayName -like '$($RawNameParts[0]) $($RawNameParts[1]) *') -or " +
                            "(displayName -like '$($RawNameParts[1]) $($RawNameParts[0]) *') -or " +
                            "(displayName -eq '$($RawNameParts[0]) $($RawNameParts[1])') -or " +
                            "(displayName -eq '$($RawNameParts[0]) $($RawNameParts[0])')" +
                        ")"
                    }
                    else {
                        $NameFilter = "(" +
                            "(" +
                                "($SurnameAttribute -eq '$($RawNameParts[0])') -and " +
                                "($GivennameAttribute -eq '$($RawNameParts[1])')" +
                            ") -or " +
                            "(" +
                                "($SurnameAttribute -eq '$($RawNameParts[1])') -and " +
                                "($GivennameAttribute -eq '$($RawNameParts[0])')" +
                            ")" +
                        ")"
                    }
                    Write-Verbose "PATTERN : GivenName Surname"
                    break  
                }

                # И. Фамилия
                # Фамилия И.
                "^([А-ЯЁ]\.\s?[А-ЯЁ][а-яё]{1,})|([А-ЯЁ][а-яё]{1,}\s[А-ЯЁ]\.)$" {
                    $RawNameParts = $RawName.Split(' ').Split('.') | Where-Object {$PSItem}
                    if ($ByDisplayName) {
                        $NameFilter = "(" + 
                            "(displayName -like '$($RawNameParts[0]) $($RawNameParts[1])*') -or " +
                            "(displayName -like '$($RawNameParts[0])* $($RawNameParts[1])') -or " +
                            "(displayName -like '$($RawNameParts[1]) $($RawNameParts[0])*') -or " +
                            "(displayName -like '$($RawNameParts[1])* $($RawNameParts[0])')" +
                        ")"
                    }
                    else {
                        $NameFilter = "(" +
                            "(" +
                                "($SurnameAttribute -eq '$($RawNameParts[0])') -and " +
                                "($GivennameAttribute -like '$($RawNameParts[1])*')" +
                            ") -or " +
                            "(" +
                                "($SurnameAttribute -eq '$($RawNameParts[1])') -and " +
                                "($GivennameAttribute -like '$($RawNameParts[0])*')" +
                            ")" +
                        ")"
                    }
                    Write-Verbose "PATTERN : G. Surname"
                    break  
                }
                default {
                    Write-Verbose "PATTERN : Unknown"
                    if (!$Strict) {
                        Write-Warning "Cannot parse $Record correctly! Searching directly by displayName"
                        $NameFilter = "(displayName -like '*$RawName*')"                        
                    }
                    else {
                        Write-Warning "Cannot parse $Record correctly!"
                        return $null
                    }    
                }     
            }

            if (!$NameFilter) { 
                continue                
            }

            Write-Verbose "FILTER  : $NameFilter"
            $ADUsers = [Microsoft.ActiveDirectory.Management.ADUser[]](
                Get-ADUser -Filter (
                    "(objectClass -eq 'user') -and " + 
                    $NameFilter
                ) -Properties $Properties -SearchBase $SearchBase
            )

            if ($ValidOnly) {
                return (
                    $ADUsers | 
                    Where-Object {
                        ($PSItem.SamAccountName -match "^([a-zA-Z]{3}_)?([a-zA-Z]\.){2}[A-Z][a-z]{1,}$")
                    }
                )
            }
            else {
                return $ADUsers
            }
        }
    }
    end {}
}