using namespace System.DirectoryServices.ActiveDirectory
using namespace System.Collections.Generic


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

class OU {
    [string]$Name
    [string]$Description
    [OU[]]$Child

    OU() {
        $this.Name = ''
        $this.Description = ''
        $this.Child = @()
    }

    OU(
        [string]$nm,
        [string]$dscr
    ) {
        $this.Name = $nm
        $this.Description = $dscr
        $this.Child = @()
    }

    OU(
        [string]$nm,
        [string]$dscr,
        [OU[]]$chld 
    ) {
        $this.Name = $nm
        $this.Description = $dscr
        $this.Child = $chld
    }
}


class DomainSummaryInfo {
    [string]$Prefix
    [string]$FQDN
    [DomainController[]]$DomainControllers
    [Dictionary[[string],[DomainController]]]$FSMO
    [psobject[]]$DNSServers
    [psobject[]]$DHCPServers

    DomainSummaryInfo() {
        $this.Prefix = [string]::new('')
        $this.FQDN = [string]::new('')
        $this.DomainControllers = [DomainController[]]::new($null)
        $this.FSMO = [Dictionary[[string],[string]]]::new()
        $this.FSMO.Add('SchemaMaster',$null)
        $this.FSMO.Add('DomainNamingMaster',$null)
        $this.FSMO.Add('PDCEmulator',$null)
        $this.FSMO.Add('RIDMaster',$null)
        $this.FSMO.Add('InfrastructureMaster',$null)
        $this.DNSServers = [psobject[]]::new($null)
        $this.DHCPServers = [psobject[]]::new($null)
    }

    DomainSummaryInfo([string]$pre, [string]$dmn) {
        $this.Prefix = [string]::new($pre)
        $this.FQDN = [string]::new($dmn)

        [DirectoryContext]$DomainContext = [DirectoryContext]::new([DirectoryContextType]::Domain,$dmn)
        [Domain]$Domain = [Domain]::GetDomain($DomainContext)

        if ($Domain.Parent) {
            $ForestName = $Domain.Parent            
        }
        else {
            $ForestName = $Domain.Name
        }

        [DirectoryContext]$ForestContext = [DirectoryContext]::new([DirectoryContextType]::Forest,$ForestName)
        [Forest]$Forest = [Forest]::GetForest($ForestContext)        
        $this.DomainControllers = $Domain.DomainControllers
        $this.FSMO = [Dictionary[[string],[DomainController]]]::new()
        $this.FSMO.Add('SchemaMaster',$Forest.SchemaRoleOwner)
        $this.FSMO.Add('DomainNamingMaster',$Forest.NamingRoleOwner)
        $this.FSMO.Add('PDCEmulator',$Domain.PdcRoleOwner)
        $this.FSMO.Add('RIDMaster',$Domain.RidRoleOwner)
        $this.FSMO.Add('InfrastructureMaster',$Domain.InfrastructureRoleOwner)

        $Resolve = Resolve-DnsName -name $dmn -Type 'NS'
        $this.DNSServers = [psobject[]]::new($null)
        foreach ($Record in ($Resolve | Where-Object Type -eq 'NS')) {
            $this.DNSServers += [PSCustomObject]@{
                Name = $Record.NameHost
                IPv4Address = ($Resolve | Where-Object {($PSItem.QueryType -eq 'A') -and ($PSItem.Name -eq $Record.NameHost)}).IP4Address
            }
        }

        $FoundDHCPServers = [psobject[]]::new($null)
        [string]$ConfigDN = ([adsi]"LDAP://$ForestName/RootDSE").configurationNamingContext | ForEach-Object {return $PSItem}
        $Searcher = [adsisearcher]'(&(objectClass=dHCPClass)(!(name=DhcpRoot)))'
        $Searcher.SearchRoot = "LDAP://$ForestName/$ConfigDN"
        $ADSIResult = $Searcher.FindAll()
        foreach ($Server in $ADSIResult) {
            $ServerInfo = $Server.GetDirectoryEntry()
            $DhcpInfo = $ServerInfo.dhcpServers[0]
            
            # now for a little regex magic
            $IP = [regex]::Match($DhcpInfo, '^i(.+?)\$').Groups[1].Value
            
            try {
                [string]$Name = $ServerInfo.Name[0] 
            }
            catch {
                $Name = [string]::new('')                
            }
            
            $FoundDHCPServers += [PSCustomObject]@{
                Name = $Name
                IPv4Address = $IP
            }
        }
        $this.DHCPServers = $FoundDHCPServers
    }
}