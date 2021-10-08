using module .\ITTools_Classes.psm1

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
        [string]$String
    )

    begin {
        $TransDict = New-Object "System.Collections.Generic.Dictionary[[char],[string]]"
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

        $ExtraCases = @(
            # [TraslitCase]::new(BaseSymbol, Shift, RegEx, Translit)
            [TraslitCase]::new('е',-1,'[ъь]','ye')
            [TraslitCase]::new('ё',-1,'[жчшщ]','o')
            [TraslitCase]::new('и',-1,'[ъь]','yi')
            # [TraslitCase]::new(BaseSymbol, Position, Shift, RegEx, Translit)
            [TraslitCase]::new('и',-2,1,'[й]','')
            # [TraslitCase]::new(BaseSymbol, Position, Translit)
            [TraslitCase]::new('х',0,'kh')
            [TraslitCase]::new('ы',-2,1,'[й]','')
        )
    }

    process {
        if (!$String) {
            return $null
        }

        Write-Verbose '==========================================='
        Write-Verbose "PROCESSING WORD : $String"
        Write-Verbose '-------------------------------------------'
        $TransString = ''

        for ($i = 0; $i -lt $String.Length; $i++) {
            $ExtraCase = $false

            Write-Verbose "SYMBOL $i : $($String[$i])"

            foreach ($Case in $ExtraCases) {
                

                if (
                    $String[$i] -eq $Case.BaseSymbol -and 
                    $String[$i + $Case.Shift] -match $Case.RegEx -and
                    (
                        (
                            (($Case.Shift + $i) -ge 0) -and 
                            ($Case.SymbolPosition -eq [int]::MinValue)
                        ) -or 
                        (
                            $Case.SymbolPosition -eq $i
                        ) -or
                        (
                            ($String.Length + $Case.SymbolPosition) -eq $i
                        )
                    )
                ) {
                    foreach ($Property in $Case.psobject.Properties.Name) {
                        Write-Verbose "$($Property.PadRight(16,' ')):$($Case.$Property)"
                    }
                    
                    $TransSymbol = $Case.TransSymbol
                    Write-Verbose "Extra case found. Transsymbol : $TransSymbol"
                    $ExtraCase = $true
                    break            
                }
            }

            if (!$ExtraCase) {
                $TransSymbol = $TransDict[([string]$String[$i]).ToLower()]
                Write-Verbose "Regular case. Transsymbol : $TransSymbol"
                if (!$TransSymbol) {
                    $TransSymbol = $String[$i]
                    Write-Verbose "Not modified. Transsymbol : $TransSymbol"
                }
            }
            
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
            
        }
        Write-Verbose '=================================================='
    }
    end {
        return $TransString
    }
}
