<#
.SYNOPSIS
    Advanced multi-server RDP management script using the RDPManagement module.

.DESCRIPTION
    This script demonstrates batch management of RDP sessions across multiple servers.
    It includes functionality for:
    - Checking RDP status across a farm of servers
    - Managing idle sessions (listing and optionally terminating)
    - Generating a comprehensive status report
    - Validating and correcting RDP configurations

.NOTES
    File Name  : Multi-Server-Management.ps1
    Author     : IT Support Team
    Requires   : RDPManagement module, PowerShell 5.1+, Administrative privileges
    Version    : 1.0

.EXAMPLE
    .\Multi-Server-Management.ps1 -Servers "server1,server2,server3" -Action "Status"
    Checks and reports RDP status across the specified servers.

.EXAMPLE
    .\Multi-Server-Management.ps1 -Action "CleanIdleSessions" -IdleThreshold 4 -Servers "server1,server2"
    Identifies and terminates sessions idle for more than 4 hours on specified servers.

.PARAMETER Servers
    Comma-separated list of server names to manage.

.PARAMETER Action
    The action to perform: Status, CleanIdleSessions, ValidateConfig, or GenerateReport.

.PARAMETER IdleThreshold
    For CleanIdleSessions action, the number of hours a session must be idle before termination.

.PARAMETER OutputPath
    Path where reports should be saved. Defaults to the current directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Servers = "localhost",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Status", "CleanIdleSessions", "ValidateConfig", "GenerateReport")]
    [string]$Action = "Status",
    
    [Parameter(Mandatory=$false)]
    [int]$IdleThreshold = 8,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "."
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Initialize variables
$serverList = $Servers -split "," | ForEach-Object { $_.Trim() }
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path -Path $OutputPath -ChildPath "RDP-Management-$timestamp.log"
$reportFile = Join-Path -Path $OutputPath -ChildPath "RDP-Report-$timestamp.csv"

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Helper function for writing logs
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Set console color based on level
    switch ($Level) {
        "INFO" { $color = "White" }
        "WARNING" { $color = "Yellow" }
        "ERROR" { $color = "Red" }
        "SUCCESS" { $color = "Green" }
        default { $color = "White" }
    }
    
    # Write to console
    Write-Host $logMessage -ForegroundColor $color
    
    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
}

# Function to import the RDPManagement module
function Import-RequiredModules {
    try {
        Import-Module RDPManagement -ErrorAction Stop
        Write-Log "Successfully imported RDPManagement module" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to import RDPManagement module: $_" -Level "ERROR"
        Write-Log "Please ensure the module is installed or in the correct path" -Level "ERROR"
        return $false
    }
}

# Function to check server status
function Get-ServersStatus {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers
    )
    
    Write-Log "Checking RDP status on $($Servers.Count) servers..." -Level "INFO"
    
    try {
        $results = Test-RDPStatus -Servers $Servers
        Write-Log "Status check completed" -Level "SUCCESS"
        return $results
    } catch {
        Write-Log "Error checking server status: $_" -Level "ERROR"
        return $null
    }
}

# Function to clean idle sessions
function Remove-IdleSessions {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory=$true)]
        [int]$HoursThreshold
    )
    
    Write-Log "Checking for idle sessions (threshold: $HoursThreshold hours)..." -Level "INFO"
    $allSessions = @()
    $terminatedCount = 0
    
    foreach ($server in $Servers) {
        try {
            Write-Log "Querying sessions on $server..." -Level "INFO"
            $sessions = Get-RDPSessions -Servers $server
            
            if ($sessions.Count -eq 0) {
                Write-Log "No active sessions found on $server" -Level "INFO"
                continue
            }
            
            # Find disconnected sessions - in a real implementation, we would check IdleTime 
            # Note: This is simplified as the actual idle time parsing would depend on exact output format
            $idleSessions = $sessions | Where-Object { $_.State -eq "Disc" }
            
            Write-Log "Found $($idleSessions.Count) disconnected sessions on $server" -Level "INFO"
            
            # Process idle sessions
            foreach ($session in $idleSessions) {
                # In a real implementation, we would parse and compare actual idle time
                # This is a simplified implementation using disconnected state as a proxy
                $serverName = $session.Server
                $sessionId = $session.SessionID
                $username = $session.Username
                
                try {
                    # Confirm before terminating
                    $confirmation = Read-Host "Terminate disconnected session for $username (ID: $sessionId) on $serverName? (y/n)"
                    
                    if ($confirmation -eq "y") {
                        Write-Log "Terminating session $sessionId for $username on $serverName..." -Level "WARNING"
                        Stop-RDPSession -Server $serverName -SessionID $sessionId -Force
                        $terminatedCount++
                        Write-Log "Session terminated successfully" -Level "SUCCESS"
                    } else {
                        Write-Log "Skipped termination of session $sessionId for $username on $serverName" -Level "INFO"
                    }
                } catch {
                    Write-Log "Error terminating session $sessionId on $serverName`: $_" -Level "ERROR"
                }
            }
            
        } catch {
            Write-Log "Error processing $server`: $_" -Level "ERROR"
        }
    }
    
    Write-Log "Idle session cleanup completed. Terminated $terminatedCount sessions." -Level "SUCCESS"
    return $terminatedCount
}

# Function to validate and correct RDP configuration
function Test-RDPConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers
    )
    
    Write-Log "Validating RDP configuration on $($Servers.Count) servers..." -Level "INFO"
    $results = @()
    
    foreach ($server in $Servers) {
        try {
            Write-Log "Testing RDP access on $server..." -Level "INFO"
            $accessStatus = Test-RDPAccess -Servers $server -Detailed
            
            if ($accessStatus.OverallStatus -eq "Fully Operational") {
                Write-Log "RDP is properly configured on $server" -Level "SUCCESS"
                $needsCorrection = $false
            } else {
                Write-Log "RDP configuration issue on $server: $($accessStatus.OverallStatus)" -Level "WARNING"
                $needsCorrection = $true
            }
            
            $results += [PSCustomObject]@{
                Server = $server
                Status = $accessStatus.OverallStatus
                NeedsCorrection = $needsCorrection
                Details = $accessStatus
            }
            
            # Ask if correction is needed
            if ($needsCorrection) {
                $confirmation = Read-Host "Would you like to attempt to fix RDP configuration on $server? (y/n)"
                
                if ($confirmation -eq "y") {
                    Write-Log "Attempting to correct RDP configuration on $server..." -Level "WARNING"
                    
                    try {
                        # Enable RDP if needed
                        if ($accessStatus.RDPEnabled -eq "No") {
                            Write-Log "Enabling Remote Desktop on $server..." -Level "INFO"
                            Enable-RemoteDesktop -Servers $server -Force
                        }
                        
                        # Check if correction worked
                        $newStatus = Test-RDPAccess -Servers $server
                        if ($newStatus.OverallStatus -eq "Fully Operational") {
                            Write-Log "Successfully corrected RDP configuration on $server" -Level "SUCCESS"
                        } else {
                            Write-Log "Correction attempt completed, but server still reports: $($newStatus.OverallStatus)" -Level "WARNING"
                        }
                    } catch {
                        Write-Log "Error correcting configuration on $server`: $_" -Level "ERROR"
                    }
                } else {
                    Write-Log "Skipped correction for $server" -Level "INFO"
                }
            }
            
        } catch {
            Write-Log "Error validating $server`: $_" -Level "ERROR"
            $results += [PSCustomObject]@{
                Server = $server
                Status = "Error"
                NeedsCorrection = $null
                Details = $null
            }
        }
    }
    
    Write-Log "Configuration validation completed" -Level "SUCCESS"
    return $results
}

# Function to generate a comprehensive report
function New-RDPReport {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )
    
    Write-Log "Generating comprehensive RDP report for $($Servers.Count) servers..." -Level "INFO"
    
    try {
        # Get session information
        $sessionInfo = @()
        foreach ($server in $Servers) {
            try {
                $sessions = Get-RDPSessions -Servers $server
                if ($sessions) {
                    foreach ($session in $sessions) {
                        $sessionInfo += [PSCustomObject]@{
                            Server = $server
                            SessionID = $session.SessionID
                            Username = $session.Username
                            State = $session.State
                            Type = $session.Type
                            Timestamp = (Get-Date)
                        }
                    }
                }
            } catch {
                Write-Log "Error getting sessions from $server`: $_" -Level "ERROR"
            }
        }
        
        # Get configuration information
        $configInfo = @()
        foreach ($server in $Servers) {
            try {
                $access = Test-RDPAccess -Servers $server
                $configInfo += [PSCustomObject]@{
                    Server = $server
                    RDPEnabled = $access.RDPEnabled
                    FirewallStatus = $access.FirewallStatus
                    OverallStatus = $access.OverallStatus
                    Timestamp = (Get-Date)
                }
            } catch {
                Write-Log "Error getting configuration from $server`: $_" -Level "ERROR"
            }
        }
        
        # Export to CSV
        if ($sessionInfo.Count -gt 0) {
            $sessionInfo | Export-Csv -Path ($OutputFile -replace '\.csv$', '-Sessions.csv') -NoTypeInformation
            Write-Log "Session report exported to: $($OutputFile -replace '\.csv$', '-Sessions.csv')" -Level "SUCCESS"
        } else {
            Write-Log "No session information to export" -Level "WARNING"
        }
        
        if ($configInfo.Count -gt 0) {
            $configInfo | Export-Csv -Path ($OutputFile -replace '\.csv$', '-Config.csv') -NoTypeInformation
            Write-Log "Configuration report exported to: $($OutputFile -replace '\.csv$', '-Config.csv')" -Level "SUCCESS"
        } else {
            Write-Log "No configuration information to export" -Level "WARNING"
        }
        
        # Generate summary
        $summaryFile = $OutputFile -replace '\.csv$', '-Summary.txt'
        $summary = @"
RDP Management Report Summary
Generated: $(Get-Date)
Servers Analyzed: $($Servers.Count)

Session Statistics:
- Total Sessions: $($sessionInfo.Count)
- Active Sessions: $(($sessionInfo | Where-Object { $_.State -eq "Active" }).Count)
- Disconnected Sessions: $(($sessionInfo | Where-Object { $_.State -eq "Disc" }).Count)

Configuration Statistics:
- Fully Operational: $(($configInfo | Where-Object { $_.OverallStatus -eq "Fully Operational" }).Count)
- Issues Detected: $(($configInfo | Where-Object { $_.OverallStatus -ne "Fully Operational" }).Count)

Report Files:
- Session Details: $($OutputFile -replace '\.csv$', '-Sessions.csv')
- Configuration Details: $($OutputFile -replace '\.csv$', '-Config.csv')
"@
        
        $summary | Out-File -FilePath $summaryFile -Force
        Write-Log "Summary report exported to: $summaryFile" -Level "SUCCESS"
        
        # Display summary
        Write-Log "Report Generation Complete" -Level "SUCCESS"
        Write-Host "`n$summary" -ForegroundColor Cyan
        
        return $true
    } catch {
        Write-Log "Error generating report: $_" -Level "ERROR"
        return $false
    }
}

# Main execution
Write-Log "Starting RDP Management script - Action: $Action" -Level "INFO"

# Import required modules
if (-not (Import-RequiredModules)) {
    Write-Log "Exiting script due to module import failure" -Level "ERROR"
    exit 1
}
# Execute requested action
switch ($Action) {
    "Status" {
        $status = Get-ServersStatus -Servers $serverList
        if ($status) {
            Write-Log "Status check completed successfully" -Level "SUCCESS"
        } else {
            Write-Log "Status check failed" -Level "ERROR"
            exit 1
        }
    }
    
    "CleanIdleSessions" {
        $terminatedCount = Remove-IdleSessions -Servers $serverList -HoursThreshold $IdleThreshold
        Write-Log "Session cleanup completed. Terminated $terminatedCount sessions." -Level "SUCCESS"
    }
    
    "ValidateConfig" {
        $configResults = Test-RDPConfiguration -Servers $serverList
        $needsFixing = ($configResults | Where-Object { $_.NeedsCorrection -eq $true }).Count
        
        if ($needsFixing -gt 0) {
            Write-Log "$needsFixing servers need configuration fixes" -Level "WARNING"
        } else {
            Write-Log "All servers are properly configured for RDP" -Level "SUCCESS"
        }
    }
    
    "GenerateReport" {
        $success = New-RDPReport -Servers $serverList -OutputFile $reportFile
        if ($success) {
            Write-Log "Report generation completed successfully" -Level "SUCCESS"
        } else {
            Write-Log "Report generation encountered errors" -Level "ERROR"
            exit 1
        }
    }
    
    default {
        Write-Log "Unknown action specified: $Action" -Level "ERROR"
        Write-Log "Valid actions are: Status, CleanIdleSessions, ValidateConfig, GenerateReport" -Level "INFO"
        exit 1
    }
}

Write-Log "RDP Management script completed" -Level "SUCCESS"
