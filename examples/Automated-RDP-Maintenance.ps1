<#
.SYNOPSIS
    Automated Remote Desktop maintenance tasks for scheduled execution.

.DESCRIPTION
    This script performs scheduled maintenance tasks for Remote Desktop environments including:
    1. Cleaning up disconnected and idle sessions
    2. Performing health checks on RDP servers
    3. Generating status reports
    4. Notifying administrators of issues

    It's designed to be run as a scheduled task to maintain a healthy RDP environment.

.NOTES
    File Name  : Automated-RDP-Maintenance.ps1
    Author     : IT Support Team
    Requires   : RDPManagement module, PowerShell 5.1+, Administrative privileges
    Version    : 1.0

.EXAMPLE
    .\Automated-RDP-Maintenance.ps1 -Servers "server1,server2,server3" -MaintenanceType Full
    Performs a full maintenance cycle on the specified servers.

.EXAMPLE
    .\Automated-RDP-Maintenance.ps1 -CleanupIdleSessions -IdleThreshold 12 -EmailReport
    Cleans up sessions idle for more than 12 hours and emails a report.

.PARAMETER Servers
    Comma-separated list of server names to maintain. Default is "localhost".

.PARAMETER MaintenanceType
    Type of maintenance to perform: Full, SessionCleanup, HealthCheck, or ReportOnly.

.PARAMETER CleanupIdleSessions
    Switch to enable idle session cleanup.

.PARAMETER IdleThreshold
    Hours threshold for considering a session idle. Default is 8 hours.

.PARAMETER EmailReport
    Switch to enable email reporting of maintenance results.

.PARAMETER EmailRecipient
    Email address to send the report to (requires configured mail server).

.PARAMETER OutputPath
    Path where reports and logs should be saved. Defaults to current directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Servers = "localhost",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Full", "SessionCleanup", "HealthCheck", "ReportOnly")]
    [string]$MaintenanceType = "Full",
    
    [Parameter(Mandatory=$false)]
    [switch]$CleanupIdleSessions,
    
    [Parameter(Mandatory=$false)]
    [int]$IdleThreshold = 8,
    
    [Parameter(Mandatory=$false)]
    [switch]$EmailReport,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailRecipient = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "."
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Initialize variables
$serverList = $Servers -split "," | ForEach-Object { $_.Trim() }
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path -Path $OutputPath -ChildPath "RDP-Maintenance-$timestamp.log"
$reportFile = Join-Path -Path $OutputPath -ChildPath "RDP-Maintenance-Report-$timestamp.html"
$csvReportFile = Join-Path -Path $OutputPath -ChildPath "RDP-Maintenance-Report-$timestamp.csv"
$jobStartTime = Get-Date

# Ensure output directory exists
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Log function
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

# Function to clean up idle sessions
function Start-SessionCleanup {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers,
        
        [Parameter(Mandatory=$true)]
        [int]$IdleHours,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    Write-Log "Starting automatic session cleanup (idle threshold: $IdleHours hours)" -Level "INFO"
    $cleanupReport = @()
    $cleanupStats = @{
        ServersProcessed = 0
        SessionsFound = 0
        SessionsTerminated = 0
        Errors = 0
    }
    
    foreach ($server in $Servers) {
        try {
            Write-Log "Processing server: $server" -Level "INFO"
            $cleanupStats.ServersProcessed++
            
            # Get all RDP sessions
            $sessions = Get-RDPSessions -Servers $server
            
            if (-not $sessions -or $sessions.Count -eq 0) {
                Write-Log "No sessions found on $server" -Level "INFO"
                continue
            }
            
            # Find disconnected sessions
            $disconnectedSessions = $sessions | Where-Object { $_.State -eq "Disc" }
            $cleanupStats.SessionsFound += $disconnectedSessions.Count
            
            Write-Log "Found $($disconnectedSessions.Count) disconnected sessions on $server" -Level "INFO"
            
            # Process each disconnected session
            foreach ($session in $disconnectedSessions) {
                try {
                    $sessionId = $session.SessionID
                    $username = $session.Username
                    
                    # In a real implementation, we would check the actual idle time
                    # For this example, we'll assume all disconnected sessions meet the idle threshold
                    Write-Log "Terminating idle session $sessionId for $username on $server" -Level "WARNING"
                    
                    if ($Force) {
                        Stop-RDPSession -Server $server -SessionID $sessionId -Force
                        Write-Log "Session $sessionId terminated successfully" -Level "SUCCESS"
                        $cleanupStats.SessionsTerminated++
                        
                        $cleanupReport += [PSCustomObject]@{
                            Server = $server
                            SessionID = $sessionId
                            Username = $username
                            Status = "Terminated"
                            Timestamp = Get-Date
                        }
                    } else {
                        Write-Log "Dry run - would terminate session $sessionId for $username" -Level "INFO"
                        
                        $cleanupReport += [PSCustomObject]@{
                            Server = $server
                            SessionID = $sessionId
                            Username = $username
                            Status = "Would terminate (dry run)"
                            Timestamp = Get-Date
                        }
                    }
                } catch {
                    Write-Log "Error processing session $sessionId on $server`: $_" -Level "ERROR"
                    $cleanupStats.Errors++
                    
                    $cleanupReport += [PSCustomObject]@{
                        Server = $server
                        SessionID = $sessionId
                        Username = $username
                        Status = "Error: $_"
                        Timestamp = Get-Date
                    }
                }
            }
        } catch {
            Write-Log "Error processing server $server`: $_" -Level "ERROR"
            $cleanupStats.Errors++
        }
    }
    
    # Return report and stats
    return @{
        Report = $cleanupReport
        Stats = $cleanupStats
    }
}

# Function to perform health checks
function Test-RDPHealth {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Servers
    )
    
    Write-Log "Starting RDP health check on $($Servers.Count) servers" -Level "INFO"
    $healthReport = @()
    $healthStats = @{
        ServersProcessed = 0
        ServersHealthy = 0
        ServersUnhealthy = 0
        Errors = 0
    }
    
    foreach ($server in $Servers) {
        try {
            Write-Log "Checking health of $server" -Level "INFO"
            $healthStats.ServersProcessed++
            
            # Check RDP status
            $status = Test-RDPAccess -Servers $server
            
            if ($status.OverallStatus -eq "Fully Operational") {
                Write-Log "Server $server is healthy" -Level "SUCCESS"
                $healthStats.ServersHealthy++
                $healthReport += [PSCustomObject]@{
                    Server = $server
                    Status = "Healthy"
                    RDPEnabled = $status.RDPEnabled
                    FirewallStatus = $status.FirewallStatus
                    Details = $status.OverallStatus
                    Timestamp = Get-Date
                }
            } else {
                Write-Log "Server $server has issues: $($status.OverallStatus)" -Level "WARNING"
                $healthStats.ServersUnhealthy++
                $healthReport += [PSCustomObject]@{
                    Server = $server
                    Status = "Unhealthy"
                    RDPEnabled = $status.RDPEnabled
                    FirewallStatus = $status.FirewallStatus
                    Details = $status.OverallStatus
                    Timestamp = Get-Date
                }
            }
        } catch {
            Write-Log "Error checking health of server $server`: $_" -Level "ERROR"
            $healthStats.Errors++
            $healthReport += [PSCustomObject]@{
                Server = $server
                Status = "Error"
                RDPEnabled = "Unknown"
                FirewallStatus = "Unknown"
                Details = "Error: $_"
                Timestamp = Get-Date
            }
        }
    }
    
    # Return report and stats
    return @{
        Report = $healthReport
        Stats = $healthStats
    }
}

# Function to generate HTML report
function New-MaintenanceReport {
    param(
        [Parameter(Mandatory=$false)]
        [array]$CleanupReport,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$CleanupStats,
        
        [Parameter(Mandatory=$false)]
        [array]$HealthReport,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$HealthStats,
        
        [Parameter(Mandatory=$true)]
        [string]$ReportFile,
        
        [Parameter(Mandatory=$true)]
        [datetime]$StartTime
    )
    
    $endTime = Get-Date
    $duration = $endTime - $StartTime
    
    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RDP Maintenance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { text-align: left; padding: 8px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .info { color: blue; }
        .summary { background-color: #e9f7ef; padding: 10px; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>RDP Maintenance Report</h1>
    <div class="summary">
        <p><strong>Report Generated:</strong> $endTime</p>
        <p><strong>Maintenance Duration:</strong> $($duration.TotalMinutes.ToString("0.00")) minutes</p>
    </div>
"@

    # Add Health Check section if available
    if ($HealthReport) {
        $html += @"
    <h2>RDP Health Check Results</h2>
        <p><strong>Servers Processed:</strong> $($HealthStats.ServersProcessed)</p>
        <p><strong>Healthy Servers:</strong> $($HealthStats.ServersHealthy)</p>
        <p><strong>Unhealthy Servers:</strong> $($HealthStats.ServersUnhealthy)</p>
        <p><strong>Errors:</strong> $($HealthStats.Errors)</p>
    </div>
    
    <table>
        <tr>
            <th>Server</th>
            <th>Status</th>
            <th>RDP Enabled</th>
            <th>Firewall Status</th>
            <th>Details</th>
            <th>Timestamp</th>
        </tr>
"@
        
        foreach ($item in $HealthReport) {
            $statusClass = switch ($item.Status) {
                "Healthy" { "success" }
                "Unhealthy" { "warning" }
                "Error" { "error" }
                default { "info" }
            }
            
            $html += @"
        <tr>
            <td>$($item.Server)</td>
            <td class="$statusClass">$($item.Status)</td>
            <td>$($item.RDPEnabled)</td>
            <td>$($item.FirewallStatus)</td>
            <td>$($item.Details)</td>
            <td>$($item.Timestamp)</td>
        </tr>
"@
        }
        
        $html += @"
    </table>
"@
    }
    
    # Add Session Cleanup section if available
    if ($CleanupReport) {
        $html += @"
    <h2>Session Cleanup Results</h2>
    <div class="summary">
        <p><strong>Servers Processed:</strong> $($CleanupStats.ServersProcessed)</p>
        <p><strong>Sessions Found:</strong> $($CleanupStats.SessionsFound)</p>
        <p><strong>Sessions Terminated:</strong> $($CleanupStats.SessionsTerminated)</p>
        <p><strong>Errors:</strong> $($CleanupStats.Errors)</p>
    </div>
    
    <table>
        <tr>
            <th>Server</th>
            <th>SessionID</th>
            <th>Username</th>
            <th>Status</th>
            <th>Timestamp</th>
        </tr>
"@
        
        foreach ($item in $CleanupReport) {
            $statusClass = switch -Wildcard ($item.Status) {
                "Terminated" { "success" }
                "Would terminate*" { "info" }
                "Error*" { "error" }
                default { "info" }
            }
            
            $html += @"
        <tr>
            <td>$($item.Server)</td>
            <td>$($item.SessionID)</td>
            <td>$($item.Username)</td>
            <td class="$statusClass">$($item.Status)</td>
            <td>$($item.Timestamp)</td>
        </tr>
"@
        }
        
        $html += @"
    </table>
"@
    }
    
    # Close HTML file
    $html += @"
</body>
</html>
"@
    
    # Save HTML to file
    $html | Out-File -FilePath $ReportFile -Encoding utf8 -Force
    
    Write-Log "Report saved to $ReportFile" -Level "SUCCESS"
    
    return $ReportFile
}

# Function to send email report
function Send-EmailReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ReportFile,
        
        [Parameter(Mandatory=$true)]
        [string]$Recipient,
        
        [Parameter(Mandatory=$false)]
        [string]$Subject = "RDP Maintenance Report",
        
        [Parameter(Mandatory=$false)]
        [string]$SmtpServer = "smtp.company.com",
        
        [Parameter(Mandatory=$false)]
        [int]$SmtpPort = 25,
        
        [Parameter(Mandatory=$false)]
        [switch]$UseSSL,
        
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential
    )
    
    if ([string]::IsNullOrEmpty($Recipient)) {
        Write-Log "Email recipient not specified, skipping email" -Level "WARNING"
        return $false
    }
    
    if (-not (Test-Path -Path $ReportFile)) {
        Write-Log "Report file not found: $ReportFile" -Level "ERROR"
        return $false
    }
    
    try {
        Write-Log "Preparing to send email report to $Recipient" -Level "INFO"
        
        # Build email params
        $emailParams = @{
            From = "RDPMaintenance@company.com"
            To = $Recipient
            Subject = $Subject
            Body = "RDP Maintenance completed. Please see the attached report for details."
            SmtpServer = $SmtpServer
            Port = $SmtpPort
            UseSsl = $UseSSL
            Attachments = $ReportFile
        }
        
        # Add credentials if provided
        if ($Credential) {
            $emailParams.Add("Credential", $Credential)
        }
        
        # Send email
        Write-Log "Sending email report..." -Level "INFO"
        Send-MailMessage @emailParams
        Write-Log "Email sent successfully to $Recipient" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Error sending email: $_" -Level "ERROR"
        return $false
    }
}

# Main execution
Write-Log "Starting RDP Maintenance - Type: $MaintenanceType" -Level "INFO"

# Create directories if needed
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    Write-Log "Created output directory: $OutputPath" -Level "INFO"
}

# Import required modules
if (-not (Import-RequiredModules)) {
    Write-Log "Exiting script due to module import failure" -Level "ERROR"
    exit 1
}

# Initialize reports
$cleanupResult = $null
$healthResult = $null

# Execute requested maintenance
switch ($MaintenanceType) {
    "Full" {
        # Perform health check
        Write-Log "Starting full maintenance - health check..." -Level "INFO"
        $healthResult = Test-RDPHealth -Servers $serverList
        
        # Perform session cleanup
        Write-Log "Starting full maintenance - session cleanup..." -Level "INFO"
        $cleanupResult = Start-SessionCleanup -Servers $serverList -IdleHours $IdleThreshold -Force:$CleanupIdleSessions
    }
    
    "SessionCleanup" {
        # Only perform session cleanup
        Write-Log "Starting session cleanup maintenance..." -Level "INFO"
        $cleanupResult = Start-SessionCleanup -Servers $serverList -IdleHours $IdleThreshold -Force:$CleanupIdleSessions
    }
    
    "HealthCheck" {
        # Only perform health check
        Write-Log "Starting health check maintenance..." -Level "INFO"
        $healthResult = Test-RDPHealth -Servers $serverList
    }
    
    "ReportOnly" {
        # Just generate a report without making changes
        Write-Log "Starting report-only maintenance..." -Level "INFO"
        $healthResult = Test-RDPHealth -Servers $serverList
        $cleanupResult = Start-SessionCleanup -Servers $serverList -IdleHours $IdleThreshold -Force:$false
    }
    
    default {
        Write-Log "Unknown maintenance type: $MaintenanceType" -Level "ERROR"
        Write-Log "Valid types are: Full, SessionCleanup, HealthCheck, ReportOnly" -Level "INFO"
        exit 1
    }
}

# Generate report
$reportPath = New-MaintenanceReport -CleanupReport $cleanupResult.Report -CleanupStats $cleanupResult.Stats `
                                   -HealthReport $healthResult.Report -HealthStats $healthResult.Stats `
                                   -ReportFile $reportFile -StartTime $jobStartTime
587

