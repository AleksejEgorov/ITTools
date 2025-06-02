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


function Get-ADGroupGroups {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias("DistinguishedName")]
        [string]$GroupName,

        [Alias('Recurse')]
        [switch]$Nested,

        [switch]$AsObject,

        [string]$Server = (& {Get-ADDomainController}).HostName
    )

    begin {
        $Result = @()
    }
    process {

        try {
            $Group = Get-ADGroup $GroupName -Properties MemberOf -Server $Server -ErrorAction Stop
        }
        catch {
            Write-Warning "Group $GroupName is not found in $env:USERDOMAIN."
            continue
        }

        # $Groups = New-Object 'List[ADGroup]'
        foreach ($GroupDN in $Group.MemberOf) {
            $ParentGroup = Get-ADGroup -Identity $GroupDN -Server $Server
            Write-Progress -Activity 'Inspecting groups:' -CurrentOperation $ParentGroup.Name

            $Result += $ParentGroup
            if ($Nested) {
                foreach ($NestedGroup in (Get-ADGroupGroups $GroupDN -Nested -AsObject)) {
                    if ($Result.DistinguishedName -notcontains $NestedGroup.DistinguishedName) {
                        $Result += $NestedGroup
                    }
                }
            }
        }
    }
    end {
        if ($AsObject) {
            return ($Result | Sort-Object SamAccountName)
        }
        return $Result.SamAccountName | Sort-Object
    }

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
        [Alias("SamAccountName",'DistinguishedName')]
        [string]$UserName,

        [Alias('Recurse')]
        [switch]$Nested,

        [switch]$AsObject,

        [string]$Server = (& {Get-ADDomainController}).HostName
    )

    begin {
        $Result = @()
    }

    process {

        try {
            $ADUser = Get-ADUser $UserName -Properties MemberOf -Server $Server -ErrorAction Stop
        }
        catch {
            Write-Warning "User $UserName not found in $env:USERDOMAIN."
            continue
        }

        foreach ($Group in $ADUser.MemberOf) {
            $UserGroup = Get-ADGroup -Identity $Group -Server $Server
            $Result += $UserGroup
            if ($Nested) {
                foreach ($NestedGroup in (Get-ADGroupGroups $UserGroup -Nested -AsObject)) {
                    if ($Result.DistinguishedName -notcontains $NestedGroup.DistinguishedName) {
                        $Result += $NestedGroup
                    }
                }
            }
        }
    }

    end {
        if ($AsObject) {
            return ($Result | Sort-Object SamAccountName)
        }
        return $Result.SamAccountName | Sort-Object
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
function Get-ADPasswordExperationDate {
    [CmdletBinding()]
    param (
        # Username list
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('DistinguishedName')]
        [string]$Identity,

        # Properties list
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string[]]$Properties,

        # Domain to search. Own at default
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [Alias('Domain')]
        [string]$Server = ($env:USERDNSDOMAIN).ToLower()
    )

    begin {
        Import-Module ActiveDirectory
        $Result = @()
        Write-Debug "Begin done"
        $RequestedProperties = @(
            'Name',
            'SamAccountName'
            'PasswordLastSet',
            'msDS-UserPasswordExpiryTimeComputed',
            'PasswordNeverExpires',
            'Enabled'
        )
        foreach ($Property in $Properties) {
            $RequestedProperties += $Property
        }
    }

    process {
        foreach ($User in $Identity) {
            Write-Debug "Processing $User"
            try {
                $ADUser = Get-ADUser -Identity $User -Properties $RequestedProperties -Server $Server -ErrorAction Stop
            }
            catch {
                # $global:Error[0]
                Write-Error -ErrorRecord $global:Error[0]
                continue
            }

            Set-StrictMode -Version Latest
            $ResultObject = [PSCustomObject]@{
                DistinguishedName = $ADUser.DistinguishedName
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

            foreach ($Property in $Properties) {
                Add-Member -InputObject $ResultObject -MemberType NoteProperty -Name $Property -Value $ADUser.$Property
            }

            $Result += $ResultObject
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
            'Mail',
            'Description',
            'Company',
            'Department',
            'Title',
            'Info'
        ),

        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [Alias('Domain')]
        [string]$Server = (& {Get-ADDomain}).DnsRoot,

        [switch]$DirectOnly
    )

    begin {
        $Adsi = [adsi]"LDAP://$Server"
        $AdsiSearcher = [adsisearcher]$Adsi
        $Result = @()
    }

    process {
        foreach ($GroupName in $Name) {
            $MemberDNs = $null
            $AdsiSearcher.Filter = "(&(objectClass=group)(cn=$GroupName))"
            $MemberDNs = $AdsiSearcher.FindOne().GetDirectoryEntry().Member

            foreach ($MemberDN in $MemberDNs) {
                Write-Verbose "Processing member $MemberDN"
                $AdsiSearcher.Filter = "(distinguishedName=$MemberDN)"
                $AdsiObject = $AdsiSearcher.FindOne().GetDirectoryEntry()

                if ($AdsiObject.objectClass -contains 'user') {
                    $Result += Get-ADUser -Identity $MemberDN -Properties $Properties -Server $Server
                }

                elseif ($AdsiObject.objectClass -contains 'foreignSecurityPrincipal') {

                    Write-Debug "foreignSecurityPrincipal detected."
                    try {
                        $ReadableName = ([System.Security.Principal.SecurityIdentifier]($AdsiObject.cn.ToString())).Translate([System.Security.Principal.NTAccount]).Value
                    }
                    catch {
                        Write-Warning "Cannot translate foreign security principal in domain $Server : $($AdsiObject.cn.ToString())"
                        continue
                    }

                    $RemoteName = $ReadableName.Split('\')[1]
                    try {
                        $RemoteDomain = Get-ADDomain $ReadableName.Split('\')[0]
                    }
                    catch {
                        Write-Warning "Cannot contact remote domain $($ReadableName.Split('\')[0]) to find user $RemoteName. $($global:Error[0].Exception.Message) "
                        continue
                    }
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
                        if (!$DirectOnly) {
                            $Result += Get-ADGroupUsers -Name $RemoteName -Domain $RemoteDomain.DNSRoot -Properties $Properties
                        }
                    }
                }
                elseif ($AdsiObject.objectClass -contains 'group') {
                    if (!$DirectOnly) {
                        $Result += Get-ADGroupUsers -Name $AdsiObject.Name -Domain $Server -Properties $Properties
                    }
                }

                elseif ($AdsiObject.objectClass -contains 'contact') {
                    $Result +=  Get-ADObject $MemberDN -Server $Server -Properties $Properties
                }

                else {
                    Write-Warning "$($AdsiObject.DistinguishedName) has unprocessed object class $($AdsiObject.objectClass -join ',')!"
                    $Result += Get-ADObject $MemberDN -Server $Server
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
        [string]$Path
    )

    $PhotoItem = Get-Item $Path -ErrorAction Stop
    $ADGroup = Get-ADGroup -Identity $Identity -ErrorAction Stop

    $ThumbnailPhoto = [byte[]]($(Get-ResizedPicture -ImageSource $PhotoItem.FullName -CanvasSize 96 -Quality 96))
    Set-ADGroup -Identity $ADGroup -Replace @{thumbnailPhoto = $ThumbnailPhoto}
}


function Get-ADUserByMail {
    <#
    .SYNOPSIS
        Search users in AD by email address
    .DESCRIPTION
        Search users in AD by email address in your and all trusted domains. Search by proxy addresses, not only primary.
    .INPUTS
        Email addresses as string[]
    .OUTPUTS
        Active Directory user objects as Microsoft.ActiveDirectory.Management.ADUser[]
    .EXAMPLE
        Get-ADUserByMail email@maildomain.tld
        Search AD user with mail email@maildomain.tld
    .EXAMPLE
        Get-ADUserByMail emailone@maildomain.tld, emailtwo@otherdomain.tld
        Search multiple AD users with mails.
    .EXAMPLE
        Get-ADUserByMail emailone@maildomain.tld, emailtwo@otherdomain.tld
        Search multiple AD users with mails.
    .EXAMPLE
        'emailone@maildomain.tld; emailtwo@otherdomain.tld'.Split('; ') | ? {PSItem} | Get-ADUserByMail -Server firstdomain.tld, seconddomain.tld
        Parse line of mails and search users in domains firstdomain.tld and seconddomain.tld using pipeline. Empty lines will be iglored.
    .EXAMPLE
        Get-Content .\mail_list.txt | Get-ADUserByMail -Properties Company,Title,Info
        Search users by mails from txt file. Returned objects will contain Company, Title and Info attributes
    .EXAMPLE
        Get-ADUserByMail *@maildomain.tld -Wildcard
        Search all AD users with mail domain @maildomain.tld
    #>


    [CmdletBinding()]
    param (
        # Email address
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [Alias('EmailAddress','WindowsEmailAddress')]
        [string[]]$Mail,

        # From domains
        [Parameter(
            Mandatory = $false,
            Position = 1
        )]
        [string[]]$Server,

        # AD filter
        [Parameter(
            Mandatory = $false
        )]
        [string]$Filter = "(mail -like '*') -and (Enabled -eq 'true')",

        # AD Propertiers
        [Parameter(
            Mandatory = $false
        )]
        [string[]]$Properies = @('mail','proxyAddresses'),

        [switch]$Wildcard,

        [switch]$Renew
    )

    begin {
        # Define search domains
        if (!$Server) {
            $Server = @()
            $Server += (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
            Get-ADTrust -Filter "*" | ForEach-Object {$Server += $PSItem.Target}
        }

        # Add mandatory properties
        @('mail','proxyAddresses') | ForEach-Object {
            if ($Properies -notcontains $PSItem) {$Properies += $PSItem}
        }


        # Collect users from each domain
        if ($Renew -or !$global:AllMailUsers) {
            $global:AllMailUsers = @()
            for ($i = 0; $i -lt $Server.Count; $i++) {
                Write-Progress -Activity "Collect mail users:" -Status $Server[$i] -PercentComplete (($i + 1) /$Server.Count * 100)
                $global:AllMailUsers += Get-ADUser -Server $Server[$i] -Filter "$Filter" -Properties $Properies
                Write-Progress -Activity "Collect mail users:" -Status "$($global:AllMailUsers) found." -Completed
            }
        }
    }

    process {
        foreach ($Address in $Mail) {
            Write-Progress -Activity "Searching" -Status $Address
            Write-Debug $Address
            if ($Wildcard) {
                $ADUsers = @($global:AllMailUsers | Where-Object {$PSItem.proxyAddresses -like "smtp:$Address"})

            }
            else {
                $ADUsers = @($global:AllMailUsers | Where-Object {$PSItem.proxyAddresses -contains "smtp:$Address"})
                if ($ADUsers.Count -gt 1) {
                    Write-Warning "Multiple objects found with mail $Address"
                }
            }
            $ADUsers | ForEach-Object {$PSItem}
        }
    }

    end {}
}

function New-DistributionGroupMigration {
        <#
    .SYNOPSIS
        Migrates distribution lists betweeen Exchange organizations
    .DESCRIPTION
        Creates distribution lists in target organization and mail contacts in source organization, both with x500 addresses. Membership migration is supported, if members exist in target organization.
    .INPUTS
        Groups email addresses as string[]
    .OUTPUTS
        None
    .EXAMPLE
        New-DistributionGroupMigration -Mail Group0@source.tld -FromDomain sourceforest.tld -MigrateMembers -NewName "Migrated Group 0" -NewMail "Group0@target.tld"
        Migrates Group0@source.tld from sourceforest.tld to current administrator's org with new name and mail and old members.
    #>
    [CmdletBinding()]
    param (
        # Groups email addresses.
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [Alias('WindowsEmailAddres','PrimarySmtpAddress')]
        [string[]]$Mail,

        # Remote domain
        [Parameter(
            Mandatory = $true,
            Position = 1
        )]
        [string]$FromDomain,

        # Local domain
        [Parameter(
            Mandatory = $false,
            Position = 2
        )]
        [string]$ToDomain = $Env:USERDNSDOMAIN.ToLower(),

        # OU for new groups
        [Parameter(
            Mandatory = $false,
            Position = 3
        )]
        [string]$CreateInOU,

        # Remote Exchange credentials
        [Parameter(
            Mandatory = $false
        )]
        [pscredential]$FromCreds,

        # Local Exchange credentials
        [Parameter(
            Mandatory = $false
        )]
        [pscredential]$ToCreds,

        # New group displayName
        [Parameter(
            Mandatory = $false
        )]
        [string]$NewName,

        # New group primarySmtpAddress
        [Parameter(
            Mandatory = $false
        )]
        [string]$NewMail,


        [switch]$MigrateMembers

    )

    begin {
        #region Create Sessions
            $FromExchange = @(((Get-ADGroupMember "Exchange Servers" -Server $FromDomain | Where-Object {$PSItem.objectClass -eq 'computer'}) | Get-ADComputer ).DnsHostName)[0]
            $ToExchange = @(((Get-ADGroupMember "Exchange Servers" -Server $ToDomain | Where-Object {$PSItem.objectClass -eq 'computer'}) | Get-ADComputer).DnsHostName)[0]

            if (!$FromCreds) {
                $FromCreds = Get-Credential -Message "Type Exchange Recipient Manager credential for remote domain $FromDomain" -UserName "$env:USERNAME@$FromDomain"
            }

            if (!$ToCreds) {
                $ToCreds =  Get-Credential -Message "Type Exchange Recipient Manager credential for local domain $ToDomain" -UserName "$env:USERNAME@$ToDomain"
            }

            $FromSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$FromExchange/PowerShell/" -Authentication Kerberos -Credential $FromCreds
            $ToSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$ToExchange/PowerShell/" -Authentication Kerberos -Credential $ToCreds

        #endregion

        #region Begin checks
            try {
                $null = Invoke-Command -Session $FromSession -ScriptBlock {Get-ExchangeServer $using:FromExchange} -ErrorAction Stop
            }
            catch {
                throw
            }

            try {
                $null = Invoke-Command -Session $ToSession -ScriptBlock {Get-ExchangeServer $using:ToExchange} -ErrorAction Stop
            }
            catch {
                throw
            }

            if ($CreateInOU) {
                try {
                    $TargetOU = (Get-ADOrganizationalUnit $CreateInOU -ErrorAction Stop).DistinguishedName
                }
                catch {
                    $TargetOU = (Get-ADDomain $ToDomain).UsersContainer
                    Write-Warning "Groups will be created in $TargetOU. $($global:Error[0].Exception.Message)"
                }
            }
            else {
                $TargetOU = (Get-ADDomain $ToDomain).UsersContainer
                Write-Warning "Groups will be created in $TargetOU."
            }
        #endregion

    }

    process {
        foreach ($GroupMail in $Mail) {
            try {
                $SourceGroupObject = Invoke-Command -Session $FromSession -ErrorAction Stop -ScriptBlock {
                    Get-DistributionGroup $using:GroupMail
                }
                Write-Verbose "...source group found: $($SourceGroupObject.DistinguishedName)"
            }
            catch {
                Write-Warning $($global:Error[0].Exception.Message)
                continue
            }

            try {
                $TargetContactObject = Invoke-Command -Session $ToSession -ErrorAction Stop -ScriptBlock {
                    Get-MailContact $using:GroupMail
                }
                Write-Verbose "...target contact found: $($TargetContactObject.DistinguishedName)"
            }
            catch {
                Write-Warning $($global:Error[0].Exception.Message)
            }


            if ($NewName) {
                $AliasName = Get-Translit $NewName.Replace(' ','')

                $TargetDisplayName = $NewName
                $TargetName = $NewName
                $TargetAlias = $AliasName
            }
            else {
                $TargetDisplayName = $SourceGroupObject.DisplayName
                $TargetName = $SourceGroupObject.Name
                $TargetAlias = $SourceGroupObject.Alias
            }

            $TargetAddresses = @()
            $TargetAddresses += "X500:$($SourceGroupObject.LegacyExchangeDN)"

            if ($TargetContactObject) {
                $TargetAddresses += "x500:$($TargetContactObject.LegacyExchangeDN)"
            }

            if ($NewMail) {
                $TargetPrimarySmtpAddress = $NewMail
                $TargetAddresses += "SMTP:$NewMail"
                $SourceGroupObject.EmailAddresses | ForEach-Object {
                    $TargetAddresses += $PSItem.Replace('SMTP:','smtp:').Replace('X500:','x500:')
                }
            }
            else {
                $TargetPrimarySmtpAddress = $SourceGroupObject.PrimarySmtpAddress
                $SourceGroupObject.EmailAddresses | ForEach-Object {
                    $TargetAddresses += $PSItem.Replace('X500:','x500:')
                }
            }
            Write-Verbose "...addreses defined: $($TargetAddresses -join '; ')"

            if ($TargetContactObject) {
                try {
                    Invoke-Command -Session $ToSession -ErrorAction Stop -ScriptBlock {
                        Get-MailContact $using:GroupMail | Remove-MailContact -Confirm:$false
                    }
                    Write-Verbose "...target contact removed."
                }
                catch {
                    Write-Warning "Cannot remove mail contact in $ToDomain. $($global:Error[0].Exception.Message)"
                }
            }

            try {
                $TargetGroupObject = Invoke-Command -Session $ToSession -ErrorAction Stop -ScriptBlock {
                    New-DistributionGroup -OrganizationalUnit $using:TargetOU `
                        -MemberJoinRestriction $using:SourceGroupObject.MemberJoinRestriction `
                        -MemberDepartRestriction $using:SourceGroupObject.MemberDepartRestriction `
                        -Alias $using:TargetAlias `
                        -DisplayName $using:TargetDisplayName `
                        -Name $using:TargetName `
                        -PrimarySmtpAddress $using:TargetPrimarySmtpAddress
                }
                Write-Verbose "...target group created: $($TargetGroupObject.DistinguishedName)"
            }
            catch {
                Write-Warning "Cannot create distribution group in $ToDomain. $($global:Error[0].Exception.Message)"
                continue
            }


            try {
                Invoke-Command -Session $ToSession -ErrorAction Stop -ScriptBlock {
                    Get-DistributionGroup $using:TargetGroupObject.DistinguishedName | `
                        Set-DistributionGroup -EmailAddresses $using:TargetAddresses `
                            -RequireSenderAuthenticationEnabled $using:SourceGroupObject.RequireSenderAuthenticationEnabled
                }
                Write-Verbose "...target group addresses applied"
            }
            catch {
                Write-Warning "Cannot add addresses to distribution group $TargetPrimarySmtpAddress in $ToDomain. $($global:Error[0].Exception.Message)"
            }

            if ($MigrateMembers) {
                try {
                    $SourceMembers = @(Invoke-Command -Session $FromSession -ErrorAction Stop -ScriptBlock {
                        Get-DistributionGroupMember $using:GroupMail
                    })
                    Write-Verbose "...source group members found: $($SourceMembers.Count)"
                }
                catch {
                    Write-Warning "Cannot get members of distribution group in $FromDomain. $($global:Error[0].Exception.Message)"
                }

                $SourceMembers.PrimarySmtpAddress | Where-Object {$PSItem} | ForEach-Object {
                    try {
                        Invoke-Command -Session $ToSession -ErrorAction Stop -ScriptBlock {
                            Get-Recipient $using:PSItem | Add-DistributionGroupMember -identity $using:TargetPrimarySmtpAddress
                        }
                        Write-Verbose "...recipient added: $($PSItem)"
                    }
                    catch {
                        Write-Warning "$($global:Error[0].Exception.Message)"
                    }
                }
            }


            try {
                Invoke-Command -Session $FromSession -ErrorAction Stop -ScriptBlock {
                    Remove-DistributionGroup $using:GroupMail -Confirm:$false
                }
                Write-Verbose "...source group removed."
            }
            catch {
                Write-Warning "Cannot remove distribution group in $FromDomain. $($global:Error[0].Exception.Message)"
            }

            $SourceOU = $SourceGroupObject.DistinguishedName.Replace("CN=$($SourceGroupObject.Name),",'')
            Write-Verbose "...source OU defined: $SourceOU"
            try {
                $null = Invoke-Command -Session $FromSession -ErrorAction Stop -ScriptBlock {
                    New-MailContact -Name $using:TargetName `
                        -Alias $using:TargetAlias `
                        -DisplayName $using:TargetDisplayName `
                        -PrimarySmtpAddress $using:TargetPrimarySmtpAddress `
                        -ExternalEmailAddress $using:TargetPrimarySmtpAddress `
                        -OrganizationalUnit $using:SourceOU
                }
                Write-Verbose "...source contact created."
            }
            catch {
                Write-Warning "Cannot create mail contact in $FromDomain. $($global:Error[0].Exception.Message)"
            }


            try {
                Invoke-Command -Session $FromSession -ErrorAction Stop -ScriptBlock {
                    Set-MailContact $using:TargetPrimarySmtpAddress -EmailAddresses $using:TargetAddresses
                }
                Write-Verbose "...source contact addressed applied."
            }
            catch {
                Write-Warning "Cannot add addresses to mail contact $TargetPrimarySmtpAddress in $FromDomain. $($global:Error[0].Exception.Message)"
            }
        }
    }

    end {
        Remove-PSSession $FromSession
        Remove-PSSession $ToSession
    }
}