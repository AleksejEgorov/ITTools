using module .\ITTools_Classes.psm1
$Global:ITToolsPath = $PSScriptRoot

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
            Write-Host "Export done to: `n$SaveAsPathNR" -ForegroundColor Green 
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
                Import-Module -Name $File -Force -ErrorAction Stop
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

            try {
                $NestedModules = (Get-Module $File).NestedModules.Path | ForEach-Object {[System.IO.Path]::GetFileName($PSItem)}
                Write-Verbose "$FileItem nested modules are $([string]::Join(', ', $NestedModules))"
            }
            catch {
                Write-Verbose "$FileItem has no nested modules"
            }
            

            Write-Debug "Variables defined"
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

                $ModuleInfo = @{
                    Path = $ManifestPath
                    ModuleVersion = $NewVersion
                    FunctionsToExport = '*'
                }

                if ($ReleaseNotes) {
                    $ReleaseNotesString = (
                        $NewVersion.ToString() + 
                        (Get-Date -Format ' (dd.MM.yyyy): ') +
                        "$ReleaseNotes`n" +
                        (Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop).ReleaseNotes
                    )
                    $ModuleInfo.Add('ReleaseNotes',$ReleaseNotesString)
                }
                if ($NestedModules) {
                    $ModuleInfo.Add('NestedModules',$NestedModules)
                }
                Update-ModuleManifest @ModuleInfo
               
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
####             Invoke process and grub output           ####
##############################################################
function Invoke-Process {
    [CmdletBinding()]
    param (
        # Command path
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$Command,

        # Command path
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string[]]$ArgumentList
    )
    
    $ProcessInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $ProcessInfo.FileName = $Command
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = [string]::Join(' ',$ArgumentList)

    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $ProcessInfo
    $null = $Process.Start()
    $Process.WaitForExit()

    return [ProcessInvocationResult]::new($Process)
    
}