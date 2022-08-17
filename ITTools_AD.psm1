using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management
using module .\ITTools_Classes.psm1

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

        [string]$Server = (& {Get-ADDomainController}).HostName,

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
                    ) `
                    -Properties $Properties `
                    -SearchBase $SearchBase `
                    -Server $Server
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

##############################################################
####                  Define user's groups                ####
##############################################################
function Get-ADUserGroups {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("SamAccountName")]
        [string[]]$UserName,

        [Parameter(Mandatory = $false)]
        [switch]$AsObject,

        [string]$Server = (& {Get-ADDomainController}).HostName
    )

    begin {
        $Result = New-Object 'Dictionary[string,psobject]'
    }

    process {
        foreach ($User in $UserName) {
            try {
                $ADUser = Get-ADUser $User -Properties MemberOf -Server $Server -ErrorAction Stop
            }
            catch {
                Write-Warning "User $User not found in $env:USERDOMAIN."
                continue
            }

            $GroupList = $ADUser.MemberOf

            $Groups = New-Object 'List[ADGroup]'
            foreach ($Group in $GroupList) {
                $Groups += Get-ADGroup -Identity $Group -Server $Server
            }
            $UserResult = [PSCustomObject]@{
                User = $ADUser
                Groups = $Groups
            }
            $Result.Add($User,$UserResult)

        }
    }

    end {
        if ($AsObject) {
            return $Result
        }
        else {
            foreach ($Record in $Result.Keys) {
                Write-Host ":::::: $($Result.$Record.User.Name) ($($Result.$Record.User.UserPrincipalName)) ::::::" -ForegroundColor Green
                foreach ($Group in $Result.$Record.Groups) {
                    Write-Host $Group.Name
                }
            }
        }
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
        [string[]]$Properties = @('Name','description'),

        [string]$Server = (& {Get-ADDomainController}).HostName
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
                $TargetADObject = Get-ADObject $ObjectName -Server $Server -ErrorAction Stop
            }
            catch {
                try {
                    $TargetADObject = Get-ADUser $ObjectName -Server $Server -ErrorAction Stop
                }
                catch {
                    try {
                        $TargetADObject = Get-ADComputer $ObjectName -Server $Server -ErrorAction Stop
                    }
                    catch {
                        continue
                    }
                }
            }


            $ParentObjectDN = ([adsi]"LDAP://$TargetADObject").Parent.Replace('LDAP://','')
            return (Get-ADObject -Identity $ParentObjectDN -Properties $Properties -Server $Server)
        }
    }
    end {}
}

##############################################################
####          Test user if member of specific group       ####
##############################################################
function Test-ADGroupMembership {
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
        [Switch]$Add,

        [string]$Server = (& {Get-ADDomainController}).HostName

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
                $GroupList += (Get-ADUser $User -Properties MemberOf -Server $Server -ErrorAction Stop).MemberOf | ForEach-Object {
                    (Get-ADGroup $PSItem -Server $Server)
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
                    Add-ADGroupMember -Identity $Group -Members $User -Server $Server
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
####           Get locked account source from PDC         ####
##############################################################
function Get-ADLockSource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true)]
        [string[]]
        $UserName,

        [string]$Server = (& {Get-ADDomainController}).HostName
    )

    begin {
        $PDC = (Get-AdDomain -Server $Server).PDCEmulator
        $Result = @()
    }

    process {
        foreach ($User in $UserName) {
            try {
                $null = Get-ADUser "$User" -Server $Server
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
        [string]$Domain = ($env:USERDNSDOMAIN).ToLower(),

        [string]$Server = (& {Get-ADDomainController}).HostName
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
                $ADUser = Get-ADUser -Identity $User -Properties PasswordLastSet,msDS-UserPasswordExpiryTimeComputed,PasswordNeverExpires,Enabled -Server $Server
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

function Get-GPOStatus {
    [CmdletBinding()]
    param (
        [string]$RegEx = '^.*$',
        [string]$Server = (& {Get-ADDomain}).DNSRoot,
        [string]$Domain = $Server
    )

    begin {
        $AllGPOs = Get-GPO -All -Server $Server -Domain $Domain | Where-Object {$PSItem.DisplayName -match $RegEx}
        $Result = New-Object 'List[psobject]'
        $i = 0
    }

    process {
        foreach ($GPO in $AllGPOs) {

            Write-Progress -Activity 'Processing policy'-Status $GPO.DisplayName -PercentComplete (($i++/ $AllGPOs.Count) * 100) -CurrentOperation "$i of $($AllGPOs.Count)"

            $Active = $false
            $Reason = ''
            $GPOReport = ([xml](Get-GPOReport -Guid $GPO.Id.Guid -ReportType Xml -Server $Server -Domain $Domain)).GPO

            if (($GPO.Computer.DSVersion -eq 0) -and ($GPO.User.DSVersion -eq 0)) {
                $Reason = 'Empty'
            }
            elseif (!$GPOReport.LinksTo) {
                $Reason = 'NotLinked'
            }
            elseif (!($GPOReport.LinksTo | Where-Object {$PSItem.Enabled -eq $true})) {
                $Reason = 'LinksDisabled'
            }
            elseif (!$GPO.Computer.Enabled -and !$GPO.User.Enabled) {
                $Reason = 'Disabled'
            }
            else {
                $Active = $true
            }

            $Result.Add(
                [PSCustomObject]@{
                    Name = $GPOReport.Name
                    Guid = $GPO.Id.Guid
                    Created = $GPO.CreationTime
                    Modified = $GPO.ModificationTime
                    Description = $GPO.Description
                    WmiFilter = $GPO.WmiFilter.Name
                    Links = $GPOReport.LinksTo.SOMPath
                    Active = $Active
                    Reason = $Reason
                }
            )

        }

    }

    end {
        return $Result
    }
}


function Get-ADDomainInfo {
    [CmdletBinding()]
    param (
        # Domains list
        [Parameter(
            Mandatory = $false,
            Position = 0
        )]
        [Alias('DnsRoot')]
        [string]$Domain = $env:USERDNSDOMAIN,

        # Friendly name
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [Alias('FriendlyName')]
        [string]$Prefix
    )

    if (!$Prefix) {
        $Prefix = $Domain.Split('.')[0].ToUpperInvariant()
    }
    return [DomainSummaryInfo]::new($Prefix,$Domain)
}

function New-ADStructure {
    [CmdletBinding()]
    param (
        # Input array of OUs
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [OU[]]$OUs,

        # Where to create OUs
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$DNPath
    )

    begin {
        $CurrentDomain = Get-ADDomain
        if ((Get-CimInstance -ClassName Win32_ComputerSystem).Domain -ne $CurrentDomain.DnsRoot) {
            $PSDefaultParameterValues = @{"*-AD*:Server"=$CurrentDomain.DnsRoot}
        }
    }

    process {
        foreach ($OU in $OUs) {
            if (!(Get-ADOrganizationalUnit -SearchBase $DNPath -SearchScope OneLevel -Filter "Name -eq '$($OU.Name)'")) {
                New-ADOrganizationalUnit -Name $OU.Name -Path $DNPath -Description $OU.Description
                Write-Verbose "Created OU $($OU.Name) in $DNPath"
            }
            else {
                Set-ADOrganizationalUnit -Identity "OU=$($OU.Name),$DNPath" -Description $OU.Description
                Write-Verbose "OU $($OU.Name) exists in $DNPath"
            }
            if ($OU.Child) {
                if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
                    New-ADStructure -OUs $OU.Child -DNPath "OU=$($OU.Name),$DNPath" -Verbose
                }
                else {
                    New-ADStructure -OUs $OU.Child -DNPath "OU=$($OU.Name),$DNPath"
                }
            }
        }
    }
    end {}
}


function Get-ADGroupUsers {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [string[]]$Name,

        # AD user properties
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string[]]$Properties = @(
            'EmailAddress',
            'Description',
            'Company',
            'Department',
            'Title',
            'info'
        ),

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [string]$Domain = (& {Get-ADDomain}).DnsRoot
    )

    begin {
        $Adsi = [adsi]"LDAP://$Domain"
        $AdsiSearcher = [adsisearcher]$Adsi
        $Result = @()
    }

    process {
        foreach ($GroupName in $Name) {
            $MemberDNs = $null
            $AdsiSearcher.Filter = "(&(objectClass=group)(cn=$GroupName))"
            $MemberDNs = $AdsiSearcher.FindOne().GetDirectoryEntry().Member
            Write-Debug "Error on 765"

            foreach ($MemberDN in $MemberDNs) {
                Write-Verbose "Processing member $MemberDN"
                $AdsiSearcher.Filter = "(distinguishedName=$MemberDN)"
                $AdsiObject = $AdsiSearcher.FindOne().GetDirectoryEntry()

                if ($AdsiObject.objectClass -contains 'user') {
                    $Result += Get-ADUser -Identity $MemberDN -Properties $Properties -Server $Domain
                }

                elseif ($AdsiObject.objectClass -contains 'foreignSecurityPrincipal') {
                    Write-Debug "foreignSecurityPrincipal detected."
                    $ReadableName = ([System.Security.Principal.SecurityIdentifier]($AdsiObject.cn.ToString())).Translate([System.Security.Principal.NTAccount]).Value
                    $RemoteName = $ReadableName.Split('\')[1]
                    $RemoteDomain = Get-ADDomain $ReadableName.Split('\')[0]
                    $RemoteAdsi = [adsi]"LDAP://$($RemoteDomain.DNSRoot)"
                    $RemoteSearcher = [adsisearcher]$RemoteAdsi
                    $RemoteSearcher.Filter = "(sAMAccountName=$RemoteName)"
                    $RemoteObject = $RemoteSearcher.FindOne().GetDirectoryEntry()
                    Write-Debug "foreignSecurityPrincipal remote properties."


                    if ($RemoteObject.objectClass -contains 'user') {
                        $Result += Get-ADUser -Identity $RemoteName -Properties $Properties -Server $RemoteDomain.DNSRoot
                    }
                    elseif ($RemoteObject.objectClass -contains 'group') {
                        $Result += Get-ADGroupUsers -Name $RemoteName -Domain $RemoteDomain.DNSRoot -Properties $Properties
                    }
                }
                elseif ($AdsiObject.objectClass -contains 'group') {
                    $Result += Get-ADGroupUsers -Name $AdsiObject.Name -Domain $Domain -Properties $Properties
                }

                elseif ($AdsiObject.objectClass -contains 'contact') {
                    $Result +=  Get-ADObject $MemberDN -Server $Domain -Properties $Properties
                }

                else {
                    Write-Warning "$($AdsiObject.DistinguishedName) has unprocessed object class $($AdsiObject.objectClass -join ',')!"
                    $Result += Get-ADObject $MemberDN -Server $Domain
                }
            }
        }
    }

    end {
        return $Result
    }
}

function Set-ADUserThumbnailPhoto {
    [CmdletBinding()]
    param (
        # AD object distinguishedName
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('DistinguishedName')]
        [string]$Identity,

        # Photo path
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$Path,

        [switch]$Jpeg
    )

    $PhotoItem = Get-Item $Path -ErrorAction Stop
    $ADUser = Get-ADUser -Identity $Identity -ErrorAction Stop

    $ThumbnailPhoto = [byte[]]($(Get-ResizedPicture -ImageSource $PhotoItem.FullName -CanvasSize 96 -Quality 96))
    Set-ADUser -Identity $ADUser -Replace @{thumbnailPhoto = $ThumbnailPhoto}
    if ($Jpeg) {
        $JpegPhoto = [byte[]]( $(Get-ResizedPicture -ImageSource $PhotoItem.FullName -CanvasSize 256 -Quality 96))
        Set-ADUser -Identity $ADUser -Replace @{jpegPhoto = $JpegPhoto}
    }
}

function Set-ADGroupThumbnailPhoto {
    [CmdletBinding()]
    param (
        # AD object distinguishedName
        [Parameter(
            Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('DistinguishedName')]
        [string]$Identity,

        # Photo path
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$Path,

        [switch]$Jpeg
    )

    $PhotoItem = Get-Item $Path -ErrorAction Stop
    $ADGroup = Get-ADGroup -Identity $Identity -ErrorAction Stop

    $ThumbnailPhoto = [byte[]]($(Get-ResizedPicture -ImageSource $PhotoItem.FullName -CanvasSize 96 -Quality 96))
    Set-ADGroup -Identity $ADGroup -Replace @{thumbnailPhoto = $ThumbnailPhoto}
    if ($Jpeg) {
        $JpegPhoto = [byte[]]( $(Get-ResizedPicture -ImageSource $PhotoItem.FullName -CanvasSize 256 -Quality 96))
        Set-ADGroup -Identity $ADGroup -Replace @{jpegPhoto = $JpegPhoto}
    }
}

