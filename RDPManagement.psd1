#
# Module manifest for module 'RDPManagement'
#
# Generated on: 4/20/2025
#

@{
    # Script module or binary module file associated with this manifest.
    RootModule = $null

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # Supported PSEditions
    CompatiblePSEditions = 'Desktop', 'Core'

    # ID used to uniquely identify this module
    GUID = '6e335e18-4b7d-48c2-9eaf-a36db0a3e378'

    # Author of this module
    Author = 'IT Support Team'

    # Company or vendor of this module
    CompanyName = 'IT Department'

    # Copyright statement for this module
    Copyright = '(c) 2025 IT Department. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell module for managing Remote Desktop Protocol (RDP) sessions, access, and configurations.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        'RDPSessionManagement.ps1',
        'RDPAccessControl.ps1'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        # Session Management
        'Get-RDPSessions',
        'Stop-RDPSession',
        'Test-RDPStatus',
        
        # Access Control
        'Enable-RemoteDesktop',
        'Disable-RemoteDesktop',
        'Test-RDPAccess'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport = @(
        'Terminate-RDPSession',
        'Get-RDPStatus'
    )

    # List of all modules packaged with this module
    ModuleList = @()

    # List of all files packaged with this module
    FileList = @(
        'RDPManagement.psd1',
        'RDPSessionManagement.ps1',
        'RDPAccessControl.ps1'
    )

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module
    # metadata used by PowerShell.
    PrivateData = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('RDP', 'RemoteDesktop', 'WindowsAdmin', 'IT', 'Support', 'SessionManagement', 'Firewall')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/ITSupport/RDPManagement'

            # A URL to an icon representing this module.
            IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = @'
Version 1.0.0 (April 2025):
- Initial release
- Session management capabilities
- Access control for enabling/disabling RDP
- User permission management
- Reporting capabilities
'@

            # Prerelease string of this module
            Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false

            # External dependent modules of this module
            ExternalModuleDependencies = @()
        }
    }

    # HelpInfo URI of this module
    HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    DefaultCommandPrefix = ''
}
