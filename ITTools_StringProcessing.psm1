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

    $MailRegex = "^[a-zA-Z0-9\-_.]{1,}@[a-zA-Z0-9\-_.]{1,}\.[a-zA-Z]{2,5}$"
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
####                 Generate random password             ####
##############################################################
function New-Password {
    [cmdletbinding(DefaultParameterSetName='ConditionNumber')]
    param (
        [Parameter()]
        [ValidateRange(7,[int]::MaxValue)]
        [int]$Length = 10,

        [ValidateRange(0,[int]::MaxValue)]
        [int]$SpecChar = 0,

        # Number of conditions
        [Parameter(
            ParameterSetName = 'ConditionNumber'
        )]
        [ValidateRange(0,4)]
        [int]$Conditions = 3,

        [Parameter(ParameterSetName = 'ConditionSpecified')]
        [switch]$UpperCase,

        [Parameter(ParameterSetName = 'ConditionSpecified')]
        [switch]$LowerCase,

        [Parameter(ParameterSetName = 'ConditionSpecified')]
        [switch]$Digits,

        [Parameter(ParameterSetName = 'ConditionSpecified')]
        [switch]$SpecChars
    )

    $Needs = @()

    $CharSets = [ordered]@{
        UppercaseLetters = 65..90 | ForEach-Object {[char]$PSItem}
        LowerCaseLetters = 97..122 | ForEach-Object {[char]$PSItem}
        Digits = 0..9
        Symbols = '!@#$%^&*()-_=+<>'.ToCharArray()
    }

    if ($Conditions) {
        for ($i = 0; $i -lt ($Conditions); $i++) {
            $Condition = $CharSets.Keys.Clone()[$i]
            $Needs += $Condition
            Write-Verbose "i = $i, now needs $Condition"
        }
    }
    else {
        if ($UpperCase) {$Needs += 'UppercaseLetters'}
        if ($LowerCase) {$Needs += 'LowerCaseLetters'}
        if ($Digits) {$Needs += 'Digits'}
        if ($SpecChars) {$Needs += 'Symbols'}
    }

    Write-Verbose "Needs: $([string]::Join(', ', $Needs))"


    do {
        Write-Verbose "==== Generation started ===="
        $Passwd = ""
        $ConditionMets = @()

        for ($i = 0; $i -lt $Length; $i++) {
            $Set = $Needs | Get-Random
            $Char = $CharSets.$Set | Get-Random
            $Passwd += $Char
            Write-Verbose "Char $Char is $Set"
            if ($Set -notin $ConditionMets) {
                $ConditionMets += $Set
                Write-Verbose "Condition $Set is met"
            }
        }
        Write-Verbose "==== Generation ended ===="
    }
    while ($ConditionMets.Length -ne $Needs.Length)

    Write-Verbose "Need conditions: $($Needs.Length)"
    Write-Verbose "Condition mets: $($ConditionMets.Length)"
    Write-Verbose "Conditions are mets: $([string]::Join(', ', $ConditionMets))"
    Write-Verbose "Password is $Passwd"


    return $Passwd
}


##############################################################
####                Translit string en → ru               ####
##############################################################
function Get-Translit {
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$InputString
    )

    begin {
        $TransDict = [System.Collections.Generic.Dictionary[[char],[string]]]::new()
        $TransDict.Add('а','a')
        $TransDict.Add('б','b')
        $TransDict.Add('в','v')
        $TransDict.Add('г','g')
        $TransDict.Add('д','d')
        $TransDict.Add('е','e')
        $TransDict.Add('ё','yo')
        $TransDict.Add('ж','zh')
        $TransDict.Add('з','z')
        $TransDict.Add('и','i')
        $TransDict.Add('й','y')
        $TransDict.Add('к','k')
        $TransDict.Add('л','l')
        $TransDict.Add('м','m')
        $TransDict.Add('н','n')
        $TransDict.Add('о','o')
        $TransDict.Add('п','p')
        $TransDict.Add('р','r')
        $TransDict.Add('с','s')
        $TransDict.Add('т','t')
        $TransDict.Add('у','u')
        $TransDict.Add('ф','f')
        $TransDict.Add('х','h')
        $TransDict.Add('ц','ts')
        $TransDict.Add('ч','ch')
        $TransDict.Add('ш','sh')
        $TransDict.Add('щ','sch')
        $TransDict.Add('ъ','')
        $TransDict.Add('ы','y')
        $TransDict.Add('ь','')
        $TransDict.Add('э','e')
        $TransDict.Add('ю','yu')
        $TransDict.Add('я','ya')
    }

    process {
        foreach ($String in $InputString) {
            if (!$String) {
                return $null
            }

            Write-Verbose '===================================================='
            Write-Verbose "PROCESSING WORD : $String"
            Write-Verbose '----------------------------------------------------'
            $TransString = ''

            for ($i = 0; $i -lt $String.Length; $i++) {
                $VerboseString = ("SYMBOL $i").PadRight(12,' ') + " : $($String[$i]) :    "

                if ($TransDict.Keys -notcontains $String[$i]) {
                    $TransString += $String[$i]
                    Write-Verbose ($VerboseString + "Not modified. Transsymbol : $($String[$i])")
                    continue
                }

                switch ($String[$i]) {
                'е' {
                        if (
                            ($i -ne 0) -and
                            ($String[$i - 1] -match "[ъь]")
                        ) {
                            $TransSymbol = 'ye'
                        }
                    }

                'ё' {
                        if (
                            ($i -ne 0) -and
                            ($String[$i - 1] -match "[жчшщ]")
                        ) {
                            $TransSymbol = 'o'
                        }
                    }

                    'и' {
                        if (
                            ($i -ne 0) -and
                            ($String[$i - 1] -match "[ъь]")
                        ) {
                            $TransSymbol = 'yi'
                        }
                        elseif (
                            ($String[$i + 1] -match "й") -and
                            # https://www.regular-expressions.info/unicode.html
                            (
                                ($String[$i + 2] -match "[\p{S}\p{P}\p{Z}\p{Nd}\p{C}]") -or
                                ($i + 2 -eq $String.Length)
                            )
                        ) {
                            $TransSymbol = ''
                        }
                    }

                    'х' {
                        if (
                            ($i -eq 0) -or
                            ($String[$i - 1] -match "[\p{S}\p{P}\p{Z}\p{Nd}\p{C}]")
                        ) {
                            $TransSymbol = 'kh'
                        }

                    }

                    'ы' {
                        if (
                            ($String[$i + 1] -match "й") -and
                            (
                                # https://www.regular-expressions.info/unicode.html
                                ($String[$i + 2] -match "[\p{S}\p{P}\p{Z}\p{Nd}\p{C}]") -or
                                ($i + 2 -eq $String.Length)
                            )
                        ) {
                            $TransSymbol = ''
                        }
                    }

                    Default {}
                }

                try {
                    [void](Get-Variable -Name 'TransSymbol' -ErrorAction Stop)
                    $VerboseString += 'Special case. '
                }
                catch {
                    $TransSymbol = $TransDict[([string]$String[$i]).ToLower()]
                    $VerboseString += 'Regular case. '
                }


                # For uppercase
                if ($String[$i] -cmatch ([string]$String[$i]).ToUpper()) {

                    for ($j = 0; $j -lt $TransSymbol.Length; $j++) {
                        if ($j -eq 0) {
                            $TransString += ([string]$TransSymbol[$j]).ToUpper()
                        }
                        else {
                            $TransString += $TransSymbol[$j]
                        }
                    }
                }
                else {
                    $TransString += $TransSymbol
                }
                $VerboseString += "Transsymbol : $TransSymbol"
                Write-Verbose $VerboseString
                Remove-Variable -Name 'TransSymbol'
            }
            Write-Verbose '===================================================='
            return $TransString
        }
    }
    end {}
}


function New-TranslitRegex {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [string[]]$InputString
    )

    begin {}
    process {
        foreach ($String in $InputString) {
            Get-Translit (
                '^' + (
                    $String -replace 'e','..?' `
                        -replace 'ё','.?(e|o)' `
                        -replace 'ж','..?' `
                        -replace 'ый','(i|y|iy|ij|yi|yy)' `
                        -replace 'ий','(i|y|iy|ij|yi|yy)' `
                        -replace 'и','.?(i|y)' `
                        -replace 'й','.' `
                        -replace 'х','.?h' `
                        -replace 'ц','(с|tz|ts|tc)' `
                        -replace 'щ','s.?c?h' `
                        -replace 'ы','.' `
                        -replace 'э','.?e' `
                        -replace 'ю','.?u' `
                        -replace 'я','.?a' `
                        -replace 'кс','(ks|x)' `
                        -replace ' ','\s+'
                ) + '$'
            )
        }
    }
    end {}
}