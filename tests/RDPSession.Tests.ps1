<#
.SYNOPSIS
    Tests for RDP session management functionality in the RDPManagement module.

.DESCRIPTION
    This Pester test file validates the session listing, session termination, and
    idle session detection capabilities of the RDPManagement module.
    
.NOTES
    These tests use mocking to avoid making actual system changes.
#>

# Import the module - in a real test environment, you might need to adjust the path
BeforeAll {
    # Define mock data and functions

    # Sample session data
    $global:mockSessions = @'
SESSIONNAME       ID  STATE   TYPE        DEVICE
console            1  Active  wdcon
rdp-tcp#55         2  Active  rdpwd
rdp-tcp#14         3  Disc    rdpwd
'@

    # Sample empty session data
    $global:mockNoSessions = @'
SESSIONNAME       ID  STATE   TYPE        DEVICE
'@

    # Sample error message
    $global:mockError = "Error: The RPC server is unavailable."
    
    # Module path - replace with actual path in test environment
    $global:modulePath = (Get-Location).Path
    
    # Source the module files directly for testing without importing
    . "$modulePath\RDPSessionManagement.ps1"
}

Describe "Get-RDPSessions" {
    BeforeAll {
        # Mock the external commands used by Get-RDPSessions
        Mock Test-Connection { return $true } -ModuleName RDPSessionManagement
        
        # Define different query session mock behaviors
        Mock query { return $global:mockSessions } -ParameterFilter { $args[0] -eq "session" } -ModuleName RDPSessionManagement
        Mock query { return $global:mockNoSessions } -ParameterFilter { $args[0] -eq "session" -and $args[2] -eq "emptysrv" } -ModuleName RDPSessionManagement
        Mock query { return $global:mockError } -ParameterFilter { $args[0] -eq "session" -and $args[2] -eq "errorsrv" } -ModuleName RDPSessionManagement
    }

    Context "When listing sessions on a server with active sessions" {
        It "Should return session objects" {
            $sessions = Get-RDPSessions -Servers "testserver"
            $sessions | Should -Not -BeNullOrEmpty
            $sessions | Should -HaveCount 3  # Assuming 3 sessions in the mock data
        }
        
        It "Should correctly parse session details" {
            $sessions = Get-RDPSessions -Servers "testserver"
            $sessions[1].Username | Should -Be "rdp-tcp#55"
            $sessions[1].State | Should -Be "Active"
        }
    }
    
    Context "When listing sessions on a server with no sessions" {
        It "Should return an empty collection" {
            $sessions = Get-RDPSessions -Servers "emptysrv"
            $sessions | Should -BeNullOrEmpty
        }
    }
    
    Context "When encountering errors" {
        It "Should handle connection failures gracefully" {
            Mock Test-Connection { return $false } -ModuleName RDPSessionManagement
            $sessions = Get-RDPSessions -Servers "unreachable"
            $sessions | Should -BeNullOrEmpty
        }
        
        It "Should handle command errors gracefully" {
            $sessions = Get-RDPSessions -Servers "errorsrv"
            $sessions | Should -BeNullOrEmpty
        }
    }
    
    Context "When specifying multiple servers" {
        It "Should query each server" {
            $serverList = @("server1", "server2", "server3")
            $sessions = Get-RDPSessions -Servers $serverList
            Should -Invoke -CommandName query -Times 3 -ModuleName RDPSessionManagement
        }
    }
}

Describe "Stop-RDPSession" {
    BeforeAll {
        # Mock the external commands used by Stop-RDPSession
        Mock Test-Connection { return $true } -ModuleName RDPSessionManagement
        Mock logoff { return "Session 3 logged off." } -ParameterFilter { $args[0] -eq "3" } -ModuleName RDPSessionManagement
        Mock logoff { return "The system cannot find the session specified." } -ParameterFilter { $args[0] -eq "99" } -ModuleName RDPSessionManagement
    }
    
    Context "When terminating a valid session" {
        It "Should successfully terminate the session" {
            $result = Stop-RDPSession -Server "testserver" -SessionID "3" -Force
            $result | Should -Be $true
            Should -Invoke -CommandName logoff -Times 1 -ModuleName RDPSessionManagement
        }
    }
    
    Context "When trying to terminate a non-existent session" {
        It "Should return false and handle the error" {
            $result = Stop-RDPSession -Server "testserver" -SessionID "99" -Force
            $result | Should -Be $false
        }
    }
    
    Context "When the server is unreachable" {
        It "Should return false and handle the error" {
            Mock Test-Connection { return $false } -ModuleName RDPSessionManagement
            $result = Stop-RDPSession -Server "unreachable" -SessionID "3" -Force
            $result | Should -Be $false
        }
    }
    
    Context "When session ID validation fails" {
        It "Should return false for non-numeric session IDs" {
            $result = Stop-RDPSession -Server "testserver" -SessionID "abc" -Force
            $result | Should -Be $false
        }
    }
    
    Context "When user confirmation is required" {
        BeforeAll {
            # Mock Read-Host to simulate user input
            Mock Read-Host { return "y" } -ModuleName RDPSessionManagement
        }
        
        It "Should prompt for confirmation when not using Force" {
            $result = Stop-RDPSession -Server "testserver" -SessionID "3"
            $result | Should -Be $true
            Should -Invoke -CommandName Read-Host -Times 1 -ModuleName RDPSessionManagement
        }
        
        It "Should skip the confirmation when using Force" {
            $result = Stop-RDPSession -Server "testserver" -SessionID "3" -Force
            $result | Should -Be $true
            Should -Invoke -CommandName Read-Host -Times 0 -ModuleName RDPSessionManagement
        }
        
        It "Should abort when user says no" {
            Mock Read-Host { return "n" } -ModuleName RDPSessionManagement
            $result = Stop-RDPSession -Server "testserver" -SessionID "3"
            $result | Should -Be $false
        }
    }
}

Describe "Test-RDPStatus" {
    BeforeAll {
        # Mock the external commands used by Test-RDPStatus
        Mock Test-Connection { return $true } -ModuleName RDPSessionManagement
        Mock Get-ItemProperty { 
            return [PSCustomObject]@{ 
                fDenyTSConnections = 0
            } 
        } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPSessionManagement
        
        Mock Get-NetFirewallRule { 
            return [PSCustomObject]@{
                Name = "RemoteDesktop-UserMode-In-TCP"
                DisplayName = "Remote Desktop - User Mode (TCP-In)"
                Enabled = $true
                Direction = "Inbound"
            }
        } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPSessionManagement
        
        Mock Test-NetConnection { 
            return [PSCustomObject]@{
                ComputerName = "testserver"
                TcpTestSucceeded = $true
                RemotePort = 3389
            }
        } -ParameterFilter { $Port -eq 3389 } -ModuleName RDPSessionManagement
    }
    
    Context "When checking a properly configured server" {
        It "Should report the server as fully operational" {
            $status = Test-RDPStatus -Servers "testserver"
            $status.Status | Should -Be "Fully Operational"
            $status.RDP_Enabled | Should -Be "Yes"
            $status.Firewall_Open | Should -Be "Yes"
            $status.Port3389Open | Should -Be "Yes"
        }
    }
    
    Context "When RDP is disabled" {
        It "Should report RDP as disabled" {
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 1
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPSessionManagement
            
            $status = Test-RDPStatus -Servers "rdpdisabled"
            $status.RDP_Enabled | Should -Be "No"
            $status.Status | Should -Be "Firewall Open but RDP Disabled"
        }
    }
    
    Context "When firewall is closed" {
        It "Should report firewall as blocked" {
            Mock Get-NetFirewallRule { 
                return [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $false
                    Direction = "Inbound"
                }
            } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPSessionManagement
            
            $status = Test-RDPStatus -Servers "firewallclosed"
            $status.Firewall_Open | Should -Be "No"
            $status.Status | Should -Be "RDP Enabled but Firewall Blocked"
        }
    }
    
    Context "When port is not accessible" {
        It "Should report port as closed" {
            Mock Test-NetConnection { 
                return [PSCustomObject]@{
                    ComputerName = "portclosed"
                    TcpTestSucceeded = $false
                    RemotePort = 3389
                }
            } -ParameterFilter { $Port -eq 3389 } -ModuleName RDPSessionManagement
            
            $status = Test-RDPStatus -Servers "portclosed"
            $status.Port3389Open | Should -Be "No"
        }
    }
    
    Context "When server is unreachable" {
        It "Should handle unreachable servers gracefully" {
            Mock Test-Connection { return $false } -ModuleName RDPSessionManagement
            
            $status = Test-RDPStatus -Servers "unreachable"
            $status.Reachable | Should -Be $false
            $status.Status | Should -Be "Unreachable"
        }
    }
    
    Context "When multiple servers are specified" {
        It "Should process each server and return multiple results" {
            $serverList = @("server1", "server2", "server3")
            $results = Test-RDPStatus -Servers $serverList
            $results | Should -HaveCount 3
        }
    }
}

