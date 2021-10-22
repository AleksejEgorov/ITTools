#
# Module manifest for module 'PSGet_ITtools'
#
# Generated by: Aleksej Egorov
#
# Generated on: 22.10.2021
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'ITtools.psm1'

# Version number of this module.
ModuleVersion = '1.19.0.65'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'c9c51153-be63-49c0-b317-7da4582cdf24'

# Author of this module
Author = 'Aleksej Egorov'

# Company or vendor of this module
CompanyName = 'Private person'

# Copyright statement for this module
Copyright = '(c) 2021 Aleksej Egorov. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Tools collection for daily admin tasks.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('ITTools_Classes.psm1', 
               'ITTools_AD.psm1', 
               'ITTools_Logging.psm1', 
               'ITTools_FileProcessing.psm1', 
               'ITTools_StringProcessing.psm1')

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = '*'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'http://www.wtfpl.net/txt/copying/'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/AleksejEgorov/ITTools'

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        ReleaseNotes = '1.19.0.65 (22.10.2021): Get-NpsLog added.
1.18.0.64 (21.10.2021): New-ADStructure and Get-ADDomainInfo added
1.17.0.63 (11.10.2021): Get-GPOStatus added.
1.16.0.57 (09.10.2021): Get-Translit is fully rewrited.
1.15.0.56 (09.10.2021): String functions are in separate file.
1.14.0.48 (28.09.2021): ActiveDirectory modules in separate file
1.13.6.47 (19.09.2021): Write-CMLog: Encoding fixed
1.13.4.45 (15.09.2021): Required modules added.
1.13.3.44 (15.09.2021): Comment-Based help added
1.13.2.43 (15.09.2021): Update-ModuleVersion: Minor updates.
1.13.0.41 (15.09.2021): Logging anf FileProcessing in separate files.
1.12.1.40 (16.08.2021): New-TestFile: Bugs fixed.
1.12.0.39 (16.08.2021): New-TestFile: Function added.
1.11.1.38 (16.08.2021): Connect-ExchangeServer: Rewrite. Discover bugs fixed.
1.11.0.37 (12.08.2021): Get-InventoryInfo: Fulli rewrite. Now using CIM.
1.10.1.36 (11.08.2021): Update-ModuleManifest: Now old release notes are keeped.
1.10.0.35 (11.08.2021): Get-ADUserByName: Search devided to "by specific attributes" & "by displayname"
Function Get-LoggedInUsers: Fixed work with multiple servers.'

        # External dependent modules of this module
        # ExternalModuleDependencies = ''

    } # End of PSData hashtable
    
 } # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

