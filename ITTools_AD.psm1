using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

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
