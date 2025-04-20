<#
.SYNOPSIS
    PowerShell module for Remote Desktop session management.

.DESCRIPTION
    This module provides functions for managing Remote Desktop Protocol (RDP) sessions,
    including listing active sessions, terminating sessions, and checking RDP configuration status.

.NOTES
    File Name      : RDPSessionManagement.ps1
    Author         : IT Support Team
    Prerequisite   : PowerShell 5.1 or later
                     Administrative privileges for most operations
    Version        : 1.0
    
.EXAMPLE
    # Import the module
    Import-Module .\RDPSessionManagement.ps1

    # List RDP sessions on local machine
    Get-RDPSessions

    # List RDP sessions on multiple servers
    Get-RDPSessions -Servers "server1","server2"

    # Terminate session
    Stop-RDPSession -Server "server1" -SessionID 3
#>

#Requires -Version 5.1

# Module configuration
$script:ModuleName = "RDPSessionManagement"
$script:ModuleVersion = "1.0"

# -----------------------------------------------------------------------------------
# Function: Get-RDPSessions
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all active Remote Desktop sessions on specified servers.

.DESCRIPTION
    This function retrieves information about active RDP sessions on one or more 
    servers using the 'query session' command. It provides detailed information about
    each session including SessionID, Username, State, and Type.

.PARAMETER Servers
    One or more server names to query. Default is localhost.

.PARAMETER Detailed
    Switch to show detailed information about each session.

.EXAMPLE
    Get-RDPSessions
    Lists all RDP sessions on the local machine.

.EXAMPLE
    Get-RDPSessions -Servers "server1","server2"
    Lists all RDP sessions on server1 and server2.

.OUTPUTS
    PSCustomObject[] - Collection of RDP session objects with properties:
    - Server: The server name
    - SessionID: Numeric ID of the session
    - Username: User account name
    - State: Active, Disconnected, etc.
    - Type: Console, RDP-Tcp, etc.
#>
function Get-RDPSessions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Servers = @("localhost"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Detailed
    )
    
    # Function to get RDP sessions from a server
    function Get-ServerRDPSessions {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Server
        )
        
        try {
            Write-Host "Querying RDP sessions on $Server..." -ForegroundColor Cyan
            
            # Check if server is reachable
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
                Write-Host "Error: Cannot reach server $Server" -ForegroundColor Red
                return $false
            }
            
            # Use 'query session' command to list sessions
            if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
                $sessions = query session 2>&1
            } else {
                $sessions = query session /server:$Server 2>&1
            }
            
            # Check for errors in query command
            if ($sessions -is [System.Management.Automation.ErrorRecord]) {
                Write-Host "Error querying sessions on $Server`: $sessions" -ForegroundColor Red
                return $false
            }
            
            # Parse and display sessions in a formatted table
            $sessions = $sessions | Where-Object { $_ -match "\S" } | Select-Object -Skip 1
            
            if ($sessions.Count -eq 0 -or $null -eq $sessions) {
                Write-Host "No active sessions found on $Server" -ForegroundColor Yellow
                return $true
            }
            
            Write-Host "Active sessions on $Server`:" -ForegroundColor Green
            
            # Create objects from the text output
            $sessionObjects = @()
            foreach ($line in $sessions) {
                $parts = $line -split '\s+', 4
                if ($parts.Count -ge 3) {
                    $sessionId = $parts[1]
                    $username = $parts[0]
                    $state = $parts[2]
                    $type = if ($parts.Count -ge 4) { $parts[3] } else { "N/A" }
                    
                    $sessionObjects += [PSCustomObject]@{
                        "Server" = $Server
                        "SessionID" = $sessionId
                        "Username" = $username
                        "State" = $state
                        "Type" = $type
                    }
                }
            }
            
            # Display sessions
            $sessionObjects | Format-Table -AutoSize
            
            # Also return the session objects for pipeline processing
            return $sessionObjects
        } catch {
            Write-Host "Error: $_" -ForegroundColor Red
            return $false
        }
    }
    
    # Process each server and collect session information
    $allSessions = @()
    $overallSuccess = $true
    
    foreach ($server in $Servers) {
        $result = Get-ServerRDPSessions -Server $server
        # Only add to all sessions if we got session objects back
        if ($result -is [System.Object[]] -or $result -is [PSCustomObject]) {
            $allSessions += $result
        }
        elseif ($result -is [Boolean]) {
            $overallSuccess = $overallSuccess -and $result
        }
    }
    
    # Return summary
    if ($overallSuccess) {
        Write-Host "Query completed successfully for all servers." -ForegroundColor Green
    } else {
        Write-Host "Query completed with errors on some servers." -ForegroundColor Yellow
    }
    
    # Return session objects for further processing
    return $allSessions
}

# -----------------------------------------------------------------------------------
# Function: Stop-RDPSession
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Terminates a specific Remote Desktop session by ID.

.DESCRIPTION
    This function ends a specific RDP session identified by its SessionID on a specified
    server using the 'logoff' command. It includes validation and confirmation prompts.

.PARAMETER Server
    The server where the session exists. Default is localhost.

.PARAMETER SessionID
    The ID of the session to terminate. This is required.

.PARAMETER Force
    Switch to terminate without confirmation prompt.

.EXAMPLE
    Stop-RDPSession -SessionID 3
    Terminates session ID 3 on the local machine, with confirmation.

.EXAMPLE
    Stop-RDPSession -Server "server1" -SessionID 5 -Force
    Terminates session ID 5 on server1 without prompting for confirmation.

.OUTPUTS
    Boolean - True if successful, False if failed.
#>
function Stop-RDPSession {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Server = "localhost",
        
        [Parameter(Mandatory=$true)]
        [string]$SessionID,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    try {
        # Validate SessionID is numeric
        if ($SessionID -notmatch '^\d+$') {
            Write-Error "Error: Session ID must be a numeric value"
            return $false
        }
        
        # Check if server is reachable
        if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
            Write-Error "Error: Cannot reach server $Server"
            return $false
        }
        
        # Build description for the operation
        $operationDescription = "Terminate session $SessionID on $Server"
        
        # Using ShouldProcess for confirmation
        if ($Force -or $PSCmdlet.ShouldProcess($Server, $operationDescription)) {
            Write-Host "Attempting to terminate session $SessionID on $Server..." -ForegroundColor Cyan
            
            # Use the logoff command to terminate the session
            if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
                $result = logoff $SessionID 2>&1
            } else {
                $result = logoff $SessionID /server:$Server 2>&1
            }
            
            # Check for errors
            if ($result -is [System.Management.Automation.ErrorRecord]) {
                Write-Error "Failed to terminate session: $result"
                return $false
            }
            
            Write-Host "Successfully terminated session $SessionID on $Server" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Operation cancelled by user." -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Error "Error: $_"
        return $false
    }
}

# Alias for backward compatibility with the original workflow name
Set-Alias -Name Terminate-RDPSession -Value Stop-RDPSession

# -----------------------------------------------------------------------------------
# Function: Test-RDPStatus
# -----------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks Remote Desktop connectivity and configuration status on specified servers.

.DESCRIPTION
    This function tests the RDP configuration status on one or more servers,
    including checking if RDP is enabled, if appropriate firewall rules exist,
    and if the port is accessible.

.PARAMETER Servers
    One or more server names to check. Default is localhost.

.PARAMETER Detailed
    Switch to show detailed information about RDP configuration.

.EXAMPLE
    Test-RDPStatus
    Checks RDP status on the local machine.

.EXAMPLE
    Test-RDPStatus -Servers "server1","server2" -Detailed
    Checks detailed RDP status on server1 and server2.

.OUTPUTS
    PSCustomObject[] - Collection of RDP status objects with properties:
    - Server: The server name
    - Reachable: If the server can be contacted
    - RDP_Enabled: If RDP is enabled in settings
    - Firewall_Open: If firewall allows RDP
    - Port3389Open: If the RDP port is listening
    - OverallStatus: Summary status
#>
function Test-RDPStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Servers = @("localhost"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Detailed
    )
    
    function Test-ServerRDPStatus {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Server
        )
        
        try {
            Write-Host "Checking RDP status on $Server..." -ForegroundColor Cyan
            
            # Check if server is reachable
            if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet)) {
                Write-Host "Error: Cannot reach server $Server" -ForegroundColor Red
                return [PSCustomObject]@{
                    "Server" = $Server
                    "Reachable" = $false
                    "RDP_Enabled" = "Unknown"
                    "Firewall_Open" = "Unknown"
                    "Port3389Open" = "Unknown"
                    "Status" = "Unreachable"
                }
            }
            
            # Check if RDP is enabled
            $rdpEnabled = $false
            $firewallOpen = $false
            
            if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
                try {
                    $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -ErrorAction Stop
                    $rdpEnabled = ($rdpSetting.fDenyTSConnections -eq 0)
                } catch {
                    Write-Host "  Cannot determine RDP status: $_" -ForegroundColor Yellow
                }
                
                # Check firewall status for RDP
                try {
                    $firewallRule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | 
                                   Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Inbound" }
                    $firewallOpen = ($null -ne $firewallRule)
                } catch {
                    Write-Host "  Cannot determine firewall status: $_" -ForegroundColor Yellow
                }
            } else {
                # For remote servers, use PowerShell remoting if available
                try {
                    $rdpInfo = Invoke-Command -ComputerName $Server -ScriptBlock {
                        $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -ErrorAction SilentlyContinue
                        $firewallRule = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | 
                                      Where-Object { $_.Enabled -eq $true -and $_.Direction -eq "Inbound" }
                        
                        return @{
                            RDPEnabled = if ($null -ne $rdpSetting) { ($rdpSetting.fDenyTSConnections -eq 0) } else { $false }
                            FirewallOpen = ($null -ne $firewallRule)
                        }
                    } -ErrorAction Stop
                    
                    $rdpEnabled = $rdpInfo.RDPEnabled
                    $firewallOpen = $rdpInfo.FirewallOpen
                } catch {
                    Write-Host "  Cannot retrieve RDP information remotely: $_" -ForegroundColor Yellow
                    Write-Host "  Using connection test as fallback..." -ForegroundColor Yellow
                    
                    # Fallback to simple connection test
                    $rdpConnection = Test-NetConnection -ComputerName $Server -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    $rdpEnabled = $rdpConnection.TcpTestSucceeded
                    $firewallOpen = $rdpConnection.TcpTestSucceeded
                }
            }
            
            # Check port connectivity
            $portTest = Test-NetConnection -ComputerName $Server -Port 3389 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            $portOpen = $portTest.TcpTestSucceeded
            
            # Determine overall status
            $status = "Unknown"
            if ($rdpEnabled -and $firewallOpen -and $portOpen) {
                $status = "Fully Operational"
            } elseif ($rdpEnabled -and $firewallOpen) {
                $status = "Configured but Port Blocked"
            } elseif ($rdpEnabled) {
                $status = "RDP Enabled but Firewall Blocked"
            } elseif ($firewallOpen -and $portOpen) {
                $status = "Firewall Open but RDP Disabled"
            } else {
                $status = "Not Configured for RDP"
            }
            
            # Create result object
            $result = [PSCustomObject]@{
                "Server" = $Server
                "Reachable" = $true
                "RDP_Enabled" = if ($rdpEnabled) { "Yes" } else { "No" }
                "Firewall_Open" = if ($firewallOpen) { "Yes" } else { "No" }
                "Port3389Open" = if ($portOpen) { "Yes" } else { "No" }
                "Status" = $status
            }
            
            return $result
            
        } catch {
            Write-Host "Error checking RDP status on $Server`: $_" -ForegroundColor Red
            return [PSCustomObject]@{
                "Server" = $Server
                "Reachable" = $true
                "RDP_Enabled" = "Error"
                "Firewall_Open" = "Error"
                "Port3389Open" = "Error"
                "Status" = "Error: $_"
            }
        }
    }
    
    # Process each server
    $results = @()
    foreach ($server in $Servers) {
        $results += Test-ServerRDPStatus -Server $server
    }
    
    # Display basic results for all servers
    $results | Format-Table -Property Server, RDP_Enabled, Firewall_Open, Port3389Open, Status -AutoSize
    
    # Return summary
    $operational = ($results | Where-Object { $_.Status -eq "Fully Operational" }).Count
    $unreachable = ($results | Where-Object { $_.Reachable -eq $false }).Count
    $total = $results.Count
    
    Write-Host "Summary: $operational of $total servers fully operational for RDP" -ForegroundColor Cyan
    if ($unreachable -gt 0) {
        Write-Host "$unreachable servers were unreachable" -ForegroundColor Yellow
    }
    
    # Return the results for pipeline processing
    return $results
}

# Alias for backward compatibility with the original workflow name
Set-Alias -Name Get-RDPStatus -Value Test-RDPStatus

# -----------------------------------------------------------------------------------
# Module Export
# -----------------------------------------------------------------------------------

# Export the functions and aliases
Export-ModuleMember -Function Get-RDPSessions, Stop-RDPSession, Test-RDPStatus
Export-ModuleMember -Alias Terminate-RDPSession, Get-RDPStatus
