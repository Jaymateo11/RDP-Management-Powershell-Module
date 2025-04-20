<#
.SYNOPSIS
    PowerShell module for Remote Desktop access control.

.DESCRIPTION
    This module provides functions for managing Remote Desktop Protocol (RDP) access,
    including enabling/disabling RDP and configuring Windows Firewall rules.

.NOTES
    File Name      : RDPAccessControl.ps1
    Author         : IT Support Team
    Prerequisite   : PowerShell 5.1 or later
                     Administrative privileges required
    Version        : 1.0
    
.EXAMPLE
    # Import the module
    Import-Module .\RDPAccessControl.ps1

    # Enable RDP on local machine
    Enable-RemoteDesktop

    # Disable RDP on a remote server
    Disable-RemoteDesktop -Server "server1" -Force

    # Test RDP access configuration
    Test-RDPAccess -Server "server1" -Detailed
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Module configuration
$script:ModuleName = "RDPAccessControl"
$script:ModuleVersion = "1.0"

# -----------------------------------------------------------------------------------
# Function: Enable-RemoteDesktop
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Enables Remote Desktop and configures necessary firewall rules.

.DESCRIPTION
    This function enables Remote Desktop Protocol (RDP) on specified servers by modifying registry settings
    and configuring appropriate firewall rules to allow incoming connections.

.PARAMETER Servers
    One or more server names to configure. Default is localhost.

.PARAMETER Force
    Switch to enable without confirmation prompt.

.PARAMETER SkipFirewall
    Switch to skip configuring Windows Firewall rules.

.EXAMPLE
    Enable-RemoteDesktop
    Enables RDP on the local machine with confirmation.

.EXAMPLE
    Enable-RemoteDesktop -Servers "server1","server2" -Force
    Enables RDP on server1 and server2 without prompting for confirmation.

.OUTPUTS
    PSCustomObject[] - Collection of configuration result objects with properties:
    - Server: The server name
    - Success: Whether the operation was successful
    - Status: Text status of the operation
#>
function Enable-RemoteDesktop {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Servers = @("localhost"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [switch]$SkipFirewall
    )
    
    # Function to enable RDP on a server
    function Enable-ServerRDP {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Server,
            
            [Parameter(Mandatory=$false)]
            [switch]$SkipFirewall
        )
        
        try {
            $isLocal = ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME)
            
            # Check if server is reachable
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
                Write-Host "Error: Cannot reach server $Server" -ForegroundColor Red
                return $false
            }
            
            Write-Host "Enabling Remote Desktop on $Server..." -ForegroundColor Cyan
            
            # Create scriptblock to enable RDP
            $enableRdpScript = {
                # Check if running as administrator
                $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isAdmin) {
                    Write-Host "Error: Administrative privileges required to enable Remote Desktop" -ForegroundColor Red
                    return $false
                }
                
                try {
                    # Enable Remote Desktop by setting registry value
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
                    
                    # Enable the service
                    Set-Service -Name "TermService" -StartupType Automatic -ErrorAction SilentlyContinue
                    Start-Service -Name "TermService" -ErrorAction SilentlyContinue
                    
                    # Make sure we allow connections from any version of RDP (optional)
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                    
                    # Enable the firewall rule if not skipping
                    if (-not $using:SkipFirewall) {
                        # Check if the firewall rule exists
                        $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
                        
                        if ($rdpRules) {
                            # Enable existing rules
                            $rdpRules | Set-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue
                            Write-Host "  Enabled existing RDP firewall rules" -ForegroundColor Green
                        } else {
                            # Create new rule if doesn't exist
                            New-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow -ErrorAction SilentlyContinue | Out-Null
                            Write-Host "  Created new RDP firewall rule" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  Skipped firewall rule configuration as requested" -ForegroundColor Yellow
                    }
                    
                    # Verify the changes
                    $rdpEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
                    
                    if ($rdpEnabled) {
                        Write-Host "  Remote Desktop successfully enabled on this server" -ForegroundColor Green
                        return $true
                    } else {
                        Write-Host "  Failed to verify Remote Desktop was enabled" -ForegroundColor Red
                        return $false
                    }
                } catch {
                    Write-Host "  Error enabling Remote Desktop: $_" -ForegroundColor Red
                    return $false
                }
            }
            
            # Execute the script locally or remotely
            if ($isLocal) {
                $result = & $enableRdpScript
            } else {
                $result = Invoke-Command -ComputerName $Server -ScriptBlock $enableRdpScript -ErrorAction Stop
            }
            
            return $result
            
        } catch {
            Write-Host "Error executing RDP configuration on $Server`: $_" -ForegroundColor Red
            return $false
        }
    }
    
    # Check for administrative privileges if local execution
    if ($Servers -contains "localhost" -or $Servers -contains $env:COMPUTERNAME) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Error "This command must be run with administrative privileges for local execution"
            if (-not $Force) {
                $continue = Read-Host "Do you want to continue with remote servers only? (y/n)"
                if ($continue -ne "y") {
                    Write-Host "Operation cancelled" -ForegroundColor Yellow
                    return
                }
                # Filter out local servers
                $Servers = $Servers | Where-Object { $_ -ne "localhost" -and $_ -ne $env:COMPUTERNAME }
                if ($Servers.Count -eq 0) {
                    Write-Host "No remote servers specified, exiting" -ForegroundColor Yellow
                    return
                }
            } else {
                return
            }
        }
    }
    
    # Confirm action with user if not forced
    $serverList = $Servers -join ", "
    $operationDescription = "Enable Remote Desktop on these servers: $serverList"
    
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($serverList, $operationDescription)) {
        Write-Host "Operation cancelled" -ForegroundColor Yellow
        return
    }
    
    # Process each server
    $results = @()
    $overallSuccess = $true
    
    foreach ($server in $Servers) {
        $success = Enable-ServerRDP -Server $server -SkipFirewall:$SkipFirewall
        $results += [PSCustomObject]@{
            Server = $server
            Success = $success
            Status = if ($success) { "Enabled" } else { "Failed" }
        }
        $overallSuccess = $overallSuccess -and $success
    }
    
    # Display results
    $results | Format-Table -AutoSize
    
    # Return summary
    $successCount = ($results | Where-Object { $_.Success -eq $true }).Count
    $total = $results.Count
    
    Write-Host "Summary: Enabled Remote Desktop on $successCount of $total servers" -ForegroundColor Cyan
    
    # Return the results for pipeline processing
    return $results
}

# -----------------------------------------------------------------------------------
# Function: Disable-RemoteDesktop
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Disables Remote Desktop and updates firewall rules accordingly.

.DESCRIPTION
    This function disables Remote Desktop Protocol (RDP) on specified servers by modifying registry settings
    and optionally disabling related firewall rules.

.PARAMETER Servers
    One or more server names to configure. Default is localhost.

.PARAMETER Force
    Switch to disable without confirmation prompt.

.PARAMETER KeepFirewall
    Switch to keep Windows Firewall rules enabled even when disabling RDP.

.EXAMPLE
    Disable-RemoteDesktop
    Disables RDP on the local machine with confirmation.

.EXAMPLE
    Disable-RemoteDesktop -Servers "server1","server2" -Force
    Disables RDP on server1 and server2 without prompting for confirmation.

.OUTPUTS
    PSCustomObject[] - Collection of configuration result objects with properties:
    - Server: The server name
    - Success: Whether the operation was successful
    - Status: Text status of the operation
#>
function Disable-RemoteDesktop {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Servers = @("localhost"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        
        [Parameter(Mandatory=$false)]
        [switch]$KeepFirewall
    )
    
    # Function to disable RDP on a server
    function Disable-ServerRDP {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Server,
            
            [Parameter(Mandatory=$false)]
            [switch]$KeepFirewall
        )
        
        try {
            $isLocal = ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME)
            
            # Check if server is reachable
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
                Write-Host "Error: Cannot reach server $Server" -ForegroundColor Red
                return $false
            }
            
            Write-Host "Disabling Remote Desktop on $Server..." -ForegroundColor Cyan
            
            # Create scriptblock to disable RDP
            $disableRdpScript = {
                # Check if running as administrator
                $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isAdmin) {
                    Write-Host "Error: Administrative privileges required to disable Remote Desktop" -ForegroundColor Red
                    return $false
                }
                
                try {
                    # Disable Remote Desktop by setting registry value
                    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1 -Type DWord -Force
                    
                    # Disable the firewall rule if not keeping
                    if (-not $using:KeepFirewall) {
                        # Check if the firewall rule exists
                        $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
                        
                        if ($rdpRules) {
                            # Disable existing rules
                            $rdpRules | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
                            Write-Host "  Disabled RDP firewall rules" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  Kept firewall rules as requested" -ForegroundColor Yellow
                    }
                    
                    # Verify the changes
                    $rdpDisabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1
                    
                    if ($rdpDisabled) {
                        Write-Host "  Remote Desktop successfully disabled on this server" -ForegroundColor Green
                        return $true
                    } else {
                        Write-Host "  Failed to verify Remote Desktop was disabled" -ForegroundColor Red
                        return $false
                    }
                } catch {
                    Write-Host "  Error disabling Remote Desktop: $_" -ForegroundColor Red
                    return $false
                }
            }
            
            # Execute the script locally or remotely
            if ($isLocal) {
                $result = & $disableRdpScript
            } else {
                $result = Invoke-Command -ComputerName $Server -ScriptBlock $disableRdpScript -ErrorAction Stop
            }
            
            return $result
            
        } catch {
            Write-Host "Error executing RDP configuration on $Server`: $_" -ForegroundColor Red
            return $false
        }
    }
    
    # Check for administrative privileges if local execution
    if ($Servers -contains "localhost" -or $Servers -contains $env:COMPUTERNAME) {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Error "This command must be run with administrative privileges for local execution"
            if (-not $Force) {
                $continue = Read-Host "Do you want to continue with remote servers only? (y/n)"
                if ($continue -ne "y") {
                    Write-Host "Operation cancelled" -ForegroundColor Yellow
                    return
                }
                # Filter out local servers
                $Servers = $Servers | Where-Object { $_ -ne "localhost" -and $_ -ne $env:COMPUTERNAME }
                if ($Servers.Count -eq 0) {
                    Write-Host "No remote servers specified, exiting" -ForegroundColor Yellow
                    return
                }
            } else {
                return
            }
        }
    }
    
    # Confirm action with user if not forced
    $serverList = $Servers -join ", "
    $operationDescription = "Disable Remote Desktop on these servers: $serverList"
    
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($serverList, $operationDescription)) {
        Write-Host "Operation cancelled" -ForegroundColor Yellow
        return
    }
    
    # Process each server
    $results = @()
    $overallSuccess = $true
    
    foreach ($server in $Servers) {
        $success = Disable-ServerRDP -Server $server -KeepFirewall:$KeepFirewall
        $results += [PSCustomObject]@{
            Server = $server
            Success = $success
            Status = if ($success) { "Disabled" } else { "Failed" }
        }
        $overallSuccess = $overallSuccess -and $success
    }
    
    # Display results
    $results | Format-Table -AutoSize
    
    # Return summary
    $successCount = ($results | Where-Object { $_.Success -eq $true }).Count
    $total = $results.Count
    
    Write-Host "Summary: Disabled Remote Desktop on $successCount of $total servers" -ForegroundColor Cyan
    
    # Return the results for pipeline processing
    return $results
}

# -----------------------------------------------------------------------------------
# Function: Test-RDPAccess
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Tests Remote Desktop connectivity and configuration status.

.DESCRIPTION
    This function tests Remote Desktop Protocol (RDP) connectivity and configuration status on specified servers,
    including RDP settings, firewall rules, port availability, and optionally user access permissions.

.PARAMETER Servers
    One or more server names to test. Default is localhost.

.PARAMETER Detailed
    Switch to show detailed diagnostic information about RDP configuration.

.PARAMETER TestUser
    Optional username to test for RDP access permissions.

.EXAMPLE
    Test-RDPAccess
    Tests RDP access on the local machine.

.EXAMPLE
    Test-RDPAccess -Servers "server1","server2" -Detailed
    Tests RDP access on server1 and server2 with detailed diagnostics.

.EXAMPLE
    Test-RDPAccess -TestUser "username"
    Tests if the specified user has RDP access permissions.

.OUTPUTS
    PSCustomObject[] - Collection of RDP access test objects with properties:
    - Server: The server name
    - RDPEnabled: If RDP is enabled
    - FirewallStatus: Status of firewall rules
    - Port3389Open: If the RDP port is open
    - UserAccess: Access status for the specified user (if provided)
    - OverallStatus: Summary of the access test results
#>
function Test-RDPAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Servers = @("localhost"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Detailed,
        
        [Parameter(Mandatory=$false)]
        [string]$TestUser = ""
    )
    
    function Test-ServerRDPAccess {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Server,
            
            [Parameter(Mandatory=$false)]
            [string]$TestUser = "",
            
            [Parameter(Mandatory=$false)]
            [switch]$Detailed
        )
        
        try {
            Write-Host "Testing RDP access on $Server..." -ForegroundColor Cyan
            
            # Check if server is reachable
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
                Write-Host "Error: Cannot reach server $Server" -ForegroundColor Red
                return [PSCustomObject]@{
                    Server = $Server
                    Reachable = $false
                    RDPEnabled = "Unknown"
                    FirewallStatus = "Unknown"
                    Port3389Open = "Unknown"
                    UserAccess = "Unknown"
                    OverallStatus = "Failed - Server unreachable"
                }
            }
            
            # Initialize variables
            $rdpEnabled = $false
            $firewallOpen = $false
            $portOpen = $false
            $userAccessOK = "Not Tested"
            $detailedInfo = @{}
            
            # Check RDP configuration
            Write-Host "  Checking RDP configuration..." -ForegroundColor Cyan
            
            try {
                # Check if the server is local or remote
                $isLocal = ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME)
                
                if ($isLocal) {
                    # Check if RDP is enabled on local machine
                    $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -ErrorAction Stop
                    $rdpEnabled = ($rdpSetting.fDenyTSConnections -eq 0)
                    
                    # Check Terminal Services service
                    $tsService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
                    $serviceStatus = if ($tsService) { $tsService.Status } else { "Not Found" }
                    $serviceStartup = if ($tsService) { $tsService.StartType } else { "Unknown" }
                    
                    # Check firewall rules
                    $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | 
                                 Where-Object { $_.Direction -eq "Inbound" }
                    $firewallOpen = ($null -ne ($rdpRules | Where-Object { $_.Enabled -eq $true }))
                    
                    # If detailed is specified, add more information
                    if ($Detailed) {
                        $detailedInfo.Add("TerminalServiceStatus", $serviceStatus)
                        $detailedInfo.Add("TerminalServiceStartup", $serviceStartup)
                        
                        $rdpRuleDetails = @()
                        foreach ($rule in $rdpRules) {
                            $rdpRuleDetails += [PSCustomObject]@{
                                Name = $rule.Name
                                DisplayName = $rule.DisplayName
                                Enabled = $rule.Enabled
                                Profile = $rule.Profile
                                Direction = $rule.Direction
                                Action = $rule.Action
                            }
                        }
                        $detailedInfo.Add("FirewallRules", $rdpRuleDetails)
                    }
                    
                } else {
                    # For remote servers, attempt to use PowerShell remoting
                    try {
                        $remoteInfo = Invoke-Command -ComputerName $Server -ScriptBlock {
                            # Check RDP status
                            $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -ErrorAction SilentlyContinue
                            $rdpEnabled = if ($rdpSetting) { ($rdpSetting.fDenyTSConnections -eq 0) } else { $false }
                            
                            # Check Terminal Services service
                            $tsService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
                            $serviceStatus = if ($tsService) { $tsService.Status } else { "Not Found" }
                            $serviceStartup = if ($tsService) { $tsService.StartType } else { "Unknown" }
                            
                            # Check firewall rules
                            $rdpRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | 
                                         Where-Object { $_.Direction -eq "Inbound" }
                            $firewallOpen = ($null -ne ($rdpRules | Where-Object { $_.Enabled -eq $true }))
                            
                            # Return collected information
                            return @{
                                RDPEnabled = $rdpEnabled
                                FirewallOpen = $firewallOpen
                                ServiceStatus = $serviceStatus
                                ServiceStartup = $serviceStartup
                                FirewallRules = if ($rdpRules) { $rdpRules | Select-Object Name, DisplayName, Enabled, Profile, Direction, Action } else { $null }
                            }
                        } -ErrorAction Stop
                        
                        # Extract information from remote command
                        $rdpEnabled = $remoteInfo.RDPEnabled
                        $firewallOpen = $remoteInfo.FirewallOpen
                        
                        # If detailed is specified, add more information
                        if ($Detailed) {
                            $detailedInfo.Add("TerminalServiceStatus", $remoteInfo.ServiceStatus)
                            $detailedInfo.Add("TerminalServiceStartup", $remoteInfo.ServiceStartup)
                            $detailedInfo.Add("FirewallRules", $remoteInfo.FirewallRules)
                        }
                        
                    } catch {
                        Write-Host "  Cannot query remote server using PowerShell remoting: $_" -ForegroundColor Yellow
                        Write-Host "  Using basic connectivity tests instead..." -ForegroundColor Yellow
                    }
                }
                # Test port connectivity regardless of server type
                Write-Host "  Testing RDP port connectivity..." -ForegroundColor Cyan
                $portTest = Test-NetConnection -ComputerName $Server -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                $portOpen = $portTest.TcpTestSucceeded
                
                # Test user access if provided
                if (-not [string]::IsNullOrEmpty($TestUser)) {
                    Write-Host "  Testing access for user $TestUser..." -ForegroundColor Cyan
                    
                    try {
                        # Test if the user exists and has RDP access
                        if ($isLocal) {
                            # Check local Remote Desktop Users group membership
                            $rdpGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                            $builtinAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                            
                            # Check for exact match or domain\user format
                            $userFound = $false
                            $userInRDPGroup = ($null -ne ($rdpGroupMembers | Where-Object { $_.Name -like "*$TestUser" }))
                            $userInAdminGroup = ($null -ne ($builtinAdmins | Where-Object { $_.Name -like "*$TestUser" }))
                            
                            if ($userInRDPGroup -or $userInAdminGroup) {
                                $userAccessOK = "Access Granted"
                                $userFound = $true
                            } else {
                                # Check if user exists but doesn't have access
                                $userExists = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
                                if ($userExists) {
                                    $userAccessOK = "Access Denied - User not in Remote Desktop Users or Administrators group"
                                    $userFound = $true
                                }
                            }
                            
                            if (-not $userFound) {
                                $userAccessOK = "Access Unknown - User not found"
                            }
                            
                        } else {
                            # For remote servers, try to query the group membership remotely
                            try {
                                $remoteUserInfo = Invoke-Command -ComputerName $Server -ScriptBlock {
                                    param($TestUser)
                                    
                                    try {
                                        $rdpGroupMembers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
                                        $builtinAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
                                        
                                        $userInRDPGroup = ($null -ne ($rdpGroupMembers | Where-Object { $_.Name -like "*$TestUser" }))
                                        $userInAdminGroup = ($null -ne ($builtinAdmins | Where-Object { $_.Name -like "*$TestUser" }))
                                        
                                        if ($userInRDPGroup -or $userInAdminGroup) {
                                            return "Access Granted"
                                        } else {
                                            # Check if user exists but doesn't have access
                                            $userExists = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
                                            if ($userExists) {
                                                return "Access Denied - User not in Remote Desktop Users or Administrators group"
                                            }
                                            return "Access Unknown - User not found"
                                        }
                                    } catch {
                                        return "Access Unknown - Error checking user access: $_"
                                    }
                                } -ArgumentList $TestUser -ErrorAction Stop
                                
                                $userAccessOK = $remoteUserInfo
                            } catch {
                                $userAccessOK = "Access Unknown - Cannot query user access remotely: $_"
                            }
                        }
                    } catch {
                        $userAccessOK = "Access Unknown - Error: $_"
                    }
                }
                
                # Determine overall status
                $overallStatus = "Unknown"
                if ($rdpEnabled -and $firewallOpen -and $portOpen) {
                    $overallStatus = "Fully Operational"
                    if ($userAccessOK -eq "Access Granted") {
                        $overallStatus = "Fully Operational - User Access Confirmed"
                    } elseif ($userAccessOK -eq "Access Denied - User not in Remote Desktop Users or Administrators group") {
                        $overallStatus = "Operational but User Access Denied"
                    }
                } elseif ($rdpEnabled -and $firewallOpen) {
                    $overallStatus = "Configured but Port Blocked"
                } elseif ($rdpEnabled) {
                    $overallStatus = "RDP Enabled but Firewall Blocked"
                } elseif ($firewallOpen -and $portOpen) {
                    $overallStatus = "Firewall Open but RDP Disabled"
                } else {
                    $overallStatus = "RDP Not Properly Configured"
                }
                
                # Create result object
                $result = [PSCustomObject]@{
                    Server = $Server
                    Reachable = $true
                    RDPEnabled = if ($rdpEnabled) { "Yes" } else { "No" }
                    FirewallStatus = if ($firewallOpen) { "Open" } else { "Blocked" }
                    Port3389Open = if ($portOpen) { "Yes" } else { "No" }
                    UserAccess = $userAccessOK
                    OverallStatus = $overallStatus
                }
                
                # Add detailed information if requested
                if ($Detailed -and $detailedInfo.Count -gt 0) {
                    foreach ($key in $detailedInfo.Keys) {
                        Add-Member -InputObject $result -MemberType NoteProperty -Name $key -Value $detailedInfo[$key]
                    }
                }
                
                return $result
                
            } catch {
                Write-Host "Error testing RDP configuration: $_" -ForegroundColor Red
                return [PSCustomObject]@{
                    Server = $Server
                    Reachable = $true
                    RDPEnabled = "Error"
                    FirewallStatus = "Error"
                    Port3389Open = "Error"
                    UserAccess = "Error"
                    OverallStatus = "Error: $_"
                }
            }
        }
    }
    
    # Process each server
    $results = @()
    foreach ($server in $Servers) {
        $result = Test-ServerRDPAccess -Server $server -Detailed:$Detailed -TestUser $TestUser
        $results += $result
    }
    
    # Display basic results for all servers
    $results | Format-Table -Property Server, RDPEnabled, FirewallStatus, Port3389Open, OverallStatus -AutoSize
    
    # Display user access results if provided
    if (-not [string]::IsNullOrEmpty($TestUser)) {
        Write-Host "`nAccess results for user '$TestUser':" -ForegroundColor Cyan
        $results | Format-Table -Property Server, UserAccess -AutoSize
    }
    
    # Display detailed information if requested
    if ($Detailed) {
        foreach ($result in $results) {
            Write-Host "`nDetailed information for $($result.Server):" -ForegroundColor Cyan
            
            if ($result.PSObject.Properties.Name -contains "TerminalServiceStatus") {
                Write-Host "  Terminal Service Status: $($result.TerminalServiceStatus)" -ForegroundColor Yellow
                Write-Host "  Terminal Service Startup: $($result.TerminalServiceStartup)" -ForegroundColor Yellow
            }
            
            if ($result.PSObject.Properties.Name -contains "FirewallRules" -and $null -ne $result.FirewallRules) {
                Write-Host "  Firewall Rules:" -ForegroundColor Yellow
                $result.FirewallRules | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host "    $_" }
            }
        }
    }
    
    # Return summary
    $operational = ($results | Where-Object { $_.OverallStatus -like "Fully Operational*" }).Count
    $partialConfig = ($results | Where-Object { 
        $_.OverallStatus -like "*but*" -or 
        $_.OverallStatus -eq "Configured but Port Blocked" -or
        $_.OverallStatus -eq "RDP Enabled but Firewall Blocked" -or
        $_.OverallStatus -eq "Firewall Open but RDP Disabled"
    }).Count
    $failed = ($results | Where-Object { 
        $_.OverallStatus -eq "RDP Not Properly Configured" -or 
        $_.OverallStatus -like "Error*" -or
        $_.Reachable -eq $false
    }).Count
    $total = $results.Count
    
    Write-Host "`nRDP Access Summary:" -ForegroundColor Cyan
    Write-Host "  Fully Operational: $operational of $total servers" -ForegroundColor Green
    if ($partialConfig -gt 0) {
        Write-Host "  Partially Configured: $partialConfig of $total servers" -ForegroundColor Yellow
    }
    if ($failed -gt 0) {
        Write-Host "  Failed/Unconfigured: $failed of $total servers" -ForegroundColor Red
    }
    
    # Return the results for pipeline processing
    return $results
}

# -----------------------------------------------------------------------------------
# Module Export
# -----------------------------------------------------------------------------------

# Export the functions
Export-ModuleMember -Function Enable-RemoteDesktop, Disable-RemoteDesktop, Test-RDPAccess
