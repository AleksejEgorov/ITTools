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




##############################################################
####                  Define user's groups                ####
##############################################################
function Get-ADUserGroups {
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