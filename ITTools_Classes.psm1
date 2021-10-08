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

class ProcessInvocationResult {
    [string]$Command
    [string[]]$ArgumentList
    [string[]]$StdOut
    [string[]]$StdErr
    [int]$ExitCode

    ProcessInvocationResult() {
        $this.Command = ''
        $this.ArgumentList = @()
        $this.StdOut = @()
        $this.StdErr = @()
        $this.ExitCode = 0
    }

    ProcessInvocationResult([System.Diagnostics.Process]$proc) {
        $this.Command = $proc.StartInfo.FileName
        $this.ArgumentList = $proc.StartInfo.Arguments
        $this.StdOut = $proc.StandardOutput.ReadToEnd().Split("`n")
        $this.StdErr = $proc.StandardError.ReadToEnd().Split("`n")
        $this.ExitCode = $proc.ExitCode
    }

    ProcessInvocationResult(
        [string]$cmnd,
        [string[]]$arglst,
        [string[]]$sout,
        [string[]]$serr,
        [int]$exit
    ) {
        $this.Command = $cmnd
        $this.ArgumentList = $arglst
        $this.StdOut = $sout
        $this.StdErr = $serr
        $this.ExitCode = $exit
    }

    [ProcessInvocationResult]GetResult([System.Diagnostics.Process]$proc) {
        return [ProcessInvocationResult]::new(
            $proc.StartInfo.FileName,
            $proc.StartInfo.Arguments,
            $proc.StandardOutput.ReadToEnd().Split("`n"),
            $proc.StandardError.ReadToEnd().Split("`n"),
            $proc.ExitCode
        )
    }
}

class TraslitCase {
    [char]$BaseSymbol
    [int]$SymbolPosition
    [int]$Shift
    [string]$RegEx
    [string]$TransSymbol

    TraslitCase (
        [char]$bs,
        [int]$sp,
        [string]$ts
    ) {
        $this.BaseSymbol = $bs
        $this.SymbolPosition = $sp
        $this.Shift = 0
        $this.RegEx = '.'
        $this.TransSymbol = $ts
    }

    TraslitCase (
        [char]$bs,
        [int]$shft,
        [string]$re,
        [string]$ts
    ) {
        $this.BaseSymbol = $bs
        $this.SymbolPosition = [int]::MinValue
        $this.Shift = $shft
        $this.RegEx = $re
        $this.TransSymbol = $ts
    }

    TraslitCase (
        [char]$bs,
        [int]$pos,
        [int]$shft,
        [string]$re,
        [string]$ts
    ) {
        $this.BaseSymbol = $bs
        $this.SymbolPosition = $pos
        $this.Shift = $shft
        $this.RegEx = $re
        $this.TransSymbol = $ts
    }
}