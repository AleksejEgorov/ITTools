function Write-CMLog {
    <#
    .SYNOPSIS
        Write log entry in CM style
    .DESCRIPTION
        Write log record to specified file in configuration manager style.
        Log can be read and processed by CMTrace.exe
    .PARAMETER Message
        Message text as System.String
    .PARAMETER LogFilePath
        Path to log file as System.String.
    .PARAMETER Level
        Log entry level as System.String from fixed set (Info, Warning, Error).
    .PARAMETER Component
        Source of log entry as System.String. Script file name or PSConsole is Default
    .INPUTS
        Message as System.String.
    .OUTPUTS
        None. Write-CMLog don't return anything.
    .EXAMPLE
        PS> Write-CMLog -LogFilePath C:\Application\some.log -Level Info -Message "File created"

        Write info message "File created" to log file C:\Application\some.log
    .EXAMPLE
        PS>$Error[0].Exception | Write-CMLog -LogFilePath C:\Application\some.log -Level Error

        Write last error message to log file C:\Application\some.log as error record.
    .LINK
        https://docs.microsoft.com/en-us/mem/configmgr/core/support/tools
    #>
    [CmdletBinding()]
    Param(
        # Log message
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string]$Message,

        # Log file
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$LogFilePath,

        # Entry level
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
        [String]$Component
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
    if ($PSVersionTable.PSVersion -ge [version]'6.0.0') {
        $Encoding = 'utf8bom'
    }
    else {
        $Encoding = 'utf8'
    }

    while (!($LogSuccess -or $AttemptsLeft -eq 0)) {
        try {
            Add-Content -Path $LogFilePath -Value $Content -Encoding $Encoding -ErrorAction Stop
            $LogSuccess = $true
        }
        catch {
            $AttemptsLeft--
            # if ($Error -and ($AttemptsLeft -ne 0)) {
            $global:Error.RemoveAt(0)
            # }
            Start-Sleep -Milliseconds (Get-Random (10..99))
        }
    }
    if (!$LogSuccess) {
        Write-Error -Message $global:Error[0].Exception.Message `
            -Category $global:Error[0].CategoryInfo.Category `
            -CategoryActivity $global:Error[0].CategoryInfo.Activity `
            -CategoryReason $global:Error[0].CategoryInfo.Reason`
            -CategoryTargetName $global:Error[0].CategoryInfo.TargetName`
            -CategoryTargetType $global:Error[0].CategoryInfo.TargetType `
            -ErrorId $global:Error[0].FullyQualifiedErrorId `
            -TargetObject $global:Error[0].TargetObject `
            -Exception $global:Error[0].Exception
    }
}


function Write-Log {
    <#
    .SYNOPSIS
        Write log entry in simple
    .DESCRIPTION
        Write log record to specified file in simple plain text style.
        Log can be read and processed by any text editor, like notepad.
    .PARAMETER Message
        Message text as System.String
    .PARAMETER LogFilePath
        Path to log file as System.String.
    .PARAMETER Level
        Log entry level as System.String from fixed set (INFO, WARN, FAIL).
    .INPUTS
        Message as System.String.
    .OUTPUTS
        None. Write-CMLog don't return anything.
    .EXAMPLE
        PS> Write-Log -LogFilePath C:\Application\some.log -Level INFO -Message "File created"
        Write info message "File created" to log file C:\Application\some.log
    .EXAMPLE
        PS> $Error[0].Exception | Write-Log -LogFilePath C:\Application\some.log -Level FAIL
        Write last error message to log file C:\Application\some.log as error record.
    .LINK
        https://docs.microsoft.com/en-us/mem/configmgr/core/support/tools
    .LINK
        Write-CMLog
    #>
    [CmdletBinding()]
    param (
        # Log message
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
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

function Get-NpsLog {
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$LogFile,

        # Number of last records
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [int]$Last,

        # Number of last values
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [datetime]$After,

        [Parameter()]
        [switch]$Full
    )

    $PacketTypes = @{
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

    $LoginServices =@{
        0  = "Telnet";
        1  = "Rlogin";
        2  = "TCP Clear";
        3  = "PortMaster";
        4  = "LAT";
        5  = "X25-PAD";
        6  = "X25-T3POS";
        8  = "TCP Clear Quiet"
    }

    $ServiceTypes = @{
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

    $AuthenticationTypes = @{
        1 = "PAP";
        2 = "CHAP";
        3 = "MS-CHAP";
        4 = "MS-CHAP v2";
        5 = "EAP";
        7 = "None";
        8 = "Custom";
        11 = "PEAP"
    }

    $ReasonCodes = @{
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

    $AcctTerminateCauses = @{
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

    $AcctStatusTypes = @{
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

    $AcctAuthentics = @{
        1 =	"RADIUS";
        2 =	"Local";
        3 =	"Remote";
        4 =	"Diameter";
    }

    $DiditProperties = @(
        'Packet-Type',
        'Service-Type',
        'Authentication-Type',
        'Reason-Code',
        'Acct-Terminate-Cause'
        'Acct-Status-Type',
        'Acct-Authentic',
        'Login-Service'
    )


    $FirstProperties = @(
        # When
        'TimeStamp',
        # What happens?
        'PacketType'
        # Who?
        'SAMAccountName',
        'UserName',
        # From?
        'CallingStationId'
        'FramedIPAddress',
        # To?
        'CalledStationId',
        'ClientFriendlyName',
        'ClientIPAddress',
        # Result?
        'ReasonCode',
        # Why?
        'ProxyPolicyName',
        'AcctTerminateCause'
        'NPPolicyName'
        # By?
        'AcctAuthentic'
        'ComputerName'
        'EventSource'
    )

    [void]($PacketTypes,$LoginServices,$ServiceTypes,$AuthenticationTypes,$ReasonCodes,$AcctTerminateCauses,$AcctStatusTypes,$AcctAuthentics)

    $LogContent = Get-Content $LogFile
    if ($Last) {
        $LogContent = $LogContent[-1..-$Last]
    }

    foreach ($XmlRow in $LogContent) {
        $EventObject = [pscustomobject]::new()
        $EventXml = ([xml]$XmlRow).Event

        if ($After -and ([datetime]($EventXml.Timestamp.'#text') -lt $After)) {
            continue
        }

        foreach ($Property in ($EventXml | Get-Member -MemberType Properties).Name) {

            if ($DiditProperties -contains $Property) {
                $Value = (Get-Variable -Name "$($Property.Replace('-',''))s").Value[[int]$EventXml.$Property.'#text']
            }
            else {
                $Value = $EventXml.$Property.'#text'
            }
            Add-Member -InputObject $EventObject -MemberType NoteProperty -Name $Property.Replace('-','') -Value $Value
        }

        $EventObject.TimeStamp = [datetime]($EventObject.TimeStamp)

        $AcceptedProperties = @()
        foreach ($Property in $FirstProperties) {
            if ($EventObject.psobject.Properties.Name -contains $Property) {
                $AcceptedProperties += $Property
            }
        }

        if ($Full) {
            foreach ($Property in $EventObject.psobject.Properties.Name) {
                if ($AcceptedProperties -notcontains $Property) {
                    $AcceptedProperties += $Property
                }
            }
        }


        $EventObject | Select-Object -Property $AcceptedProperties
    }
}

function Get-SmtpLog {
    [CmdletBinding()]
    param(
        # Please specify email address
        [Parameter(
            Mandatory = $true,
            Position = 0
        )]
        [string]$SmtpAddress,

        # Please specify log file path, accepts wildcard
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$LogFilePath,

        # Please specify log file path, accepts wildcard
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [ValidateSet(
            'All',
            'User'
        )]
        [string]$Display
    )

    try {
        [void](LogParser.exe)
    }
    catch {
        Write-Error -Category NotInstalled `
            -TargetObject 'LogParser.exe' `
            -Message 'Seems like LogParser.exe is not installed or not in PATH'
        return
    }

    #cls
    $SearchString = "TO:<$($SmtpAddress.Replace('*','%'))>";
    $SearchRegex = "TO:<$($SmtpAddress.Replace('*','[A-Za-z0-9_\.\-]*').Replace('.','\.').Replace('-','\-'))>";
     # regex to match any of 421,450,451,452,500,501,
    # 502,503,504,550,551,552,553,554 smtp error codes
    $ErrorRegex =  "(-\s+)?(421|45[0-2]|5(0|5)[0-4])\+";
    Write-Verbose "Search string is : $SearchString"
    Write-Verbose "Search regexp is : $SearchRegex"


    # generic code to colorize SMTP errors
    function PaintRows {
        [CmdletBinding()]
        param (
            [Parameter(
                Mandatory = $true,
                Position = 0,
                ValueFromPipeline = $true
            )]
            [AllowEmptyCollection()]
            [AllowNull()]
            [string[]]$Array
        )

        begin {}

        process {
            foreach ($String in $Array) {
                switch -Regex ($String) {
                    $SearchRegex {$Color = 'Yellow'}
                    $ErrorRegex {$Color = 'Red'}
                    Default {$Color = 'Gray'}
                }
                Write-Host $String -ForegroundColor $Color
            }
        }

        end {}
    }


    # the user may have more than one server associated, get list of all mail servers ips
    $Query="SELECT DISTINCT c-ip FROM $LogFilePath WHERE cs-uri-query LIKE '%$SearchString%'";

    $IPs = logparser -i:W3C -q:ON $Query;

    if(!$IPs){
        Write-Host "Address not found.`n" -b black -f red;
        return;
    }

    # foreach ip returned emit the session

    foreach ($IP in $IPs) {
        $Skip = $false
        Write-Verbose "Processing IP $IP."

        $IpQuery = "SELECT date,time,c-ip,cs-method,cs-uri-query FROM $LogFilePath WHERE c-ip = '$IP'";
        Write-Verbose "[QUERY] $IpQuery"

        $ParseResult = LogParser.exe -i:W3C -q:ON $IpQuery;
        Write-Verbose "$($ParseResult.Count) records found"

        # set start anchors where line matches "220+" (session starts)
        $SessionNumbers=@();

        for($i = 0; $i -lt $ParseResult.Count; $i++) {
            if ($ParseResult[$i] -match "-\s+220\+") {
                $SessionNumbers += $i
            }
        }
        $SessionNumbers += $ParseResult.Count;

        if ($SessionNumbers.Count -eq 0){
            write-host "`nNo sessions found for <$IP>`n" -ForegroundColor red;
            return;
        }

        switch ($Display) {
            'All' {$UserOnly = $false}
            'User' {$UserOnly = $true}
            default {
                $Key = Read-Host "Found $($SessionNumbers.Count) sessions for <$IP>.`nDisplay User sessions, All sessions, or None [U/a/n]";
                switch ($Key) {
                    'A' {$UserOnly = $false}
                    'U' {$UserOnly = $true}
                    'N' {$Skip = $true}
                    default {$UserOnly = $true}
                }
            }
        }

        if ($Skip) {
            continue
        }

        for ($i=0; $i -lt ($SessionNumbers.Count - 1); $i++) {
            # slice array
            $SessionStrings = $ParseResult[$SessionNumbers[$i]..$($SessionNumbers[$i+1]-1)];


            if ($SessionStrings -and ($i -lt $SessionNumbers.Count)) {
                if ($UserOnly -and !($SessionStrings | Where-Object {$PSItem -Match $SearchRegex})) {
                    continue
                }
                PaintRows $SessionStrings
                Write-Host '---- more ----'
                [void]($Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'))
            }
        }
    }
}