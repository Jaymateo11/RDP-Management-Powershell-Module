<#
.SYNOPSIS
    Tests for RDP access control functionality in the RDPManagement module.

.DESCRIPTION
    This Pester test file validates the RDP enabling, disabling, and firewall
    management capabilities of the RDPManagement module.
    
.NOTES
    These tests use mocking to avoid making actual system changes.
#>

# Import the module - in a real test environment, you might need to adjust the path
BeforeAll {
    # Module path - replace with actual path in test environment
    $global:modulePath = (Get-Location).Path
    
    # Source the module files directly for testing without importing
    . "$modulePath\RDPAccessControl.ps1"
    
    # Define common mocks
    function MockRegistryAccess {
        # Mock registry access for Terminal Server settings
        Mock Get-ItemProperty { 
            return [PSCustomObject]@{ 
                fDenyTSConnections = 1  # Default to disabled
            } 
        } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
        
        Mock Set-ItemProperty { } -ModuleName RDPAccessControl
        
        # Mock service management
        Mock Get-Service { 
            return [PSCustomObject]@{
                Name = "TermService"
                Status = "Stopped"
                StartType = "Manual"
            }
        } -ParameterFilter { $Name -eq "TermService" } -ModuleName RDPAccessControl
        
        Mock Set-Service { } -ModuleName RDPAccessControl
        Mock Start-Service { } -ModuleName RDPAccessControl
        
        # Mock firewall management
        Mock Get-NetFirewallRule { 
            return @(
                [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $false
                    Direction = "Inbound"
                },
                [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-UDP"
                    DisplayName = "Remote Desktop - User Mode (UDP-In)"
                    Enabled = $false
                    Direction = "Inbound"
                }
            )
        } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
        
        Mock Set-NetFirewallRule { } -ModuleName RDPAccessControl
        Mock New-NetFirewallRule { 
            return [PSCustomObject]@{
                Name = "RemoteDesktop-UserMode-In-TCP"
                DisplayName = "Remote Desktop - User Mode (TCP-In)"
                Enabled = $true
                Direction = "Inbound"
            }
        } -ModuleName RDPAccessControl
        
        # Mock connection tests
        Mock Test-Connection { return $true } -ModuleName RDPAccessControl
        Mock Test-NetConnection { 
            return [PSCustomObject]@{
                ComputerName = "testserver"
                TcpTestSucceeded = $true
                RemotePort = 3389
            }
        } -ModuleName RDPAccessControl
        
        # Mock PowerShell remoting
        Mock Invoke-Command { 
            # Return different results based on the computer name
            if ($ComputerName -eq "enabledserver") {
                return $true
            } elseif ($ComputerName -eq "disabledserver") {
                return $false
            } elseif ($ComputerName -eq "errorserver") {
                throw "Remote error"
            } else {
                return $true
            }
        } -ModuleName RDPAccessControl
    }
}

Describe "Enable-RemoteDesktop" {
    BeforeAll {
        # Set up mocks
        MockRegistryAccess
        
        # Mock administrator check
        $mockPrincipal = [PSCustomObject]@{
            IsInRole = { param($role) return $true }
        }
        Mock Get-CurrentPrincipal { return $mockPrincipal } -ModuleName RDPAccessControl
        
        # Mock confirmation
        Mock Read-Host { return "y" } -ModuleName RDPAccessControl
    }
    
    Context "When enabling RDP on a local server" {
        BeforeEach {
            # Reset mock counts
            Mock Set-ItemProperty { } -ModuleName RDPAccessControl
            Mock Set-NetFirewallRule { } -ModuleName RDPAccessControl
        }
        
        It "Should enable RDP by setting registry value" {
            $result = Enable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Set-ItemProperty -Times 1 -ParameterFilter { 
                $Path -like '*Terminal Server*' -and $Name -eq 'fDenyTSConnections' -and $Value -eq 0 
            } -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should enable firewall rules" {
            $result = Enable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Set-NetFirewallRule -Times 1 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should skip firewall configuration when requested" {
            $result = Enable-RemoteDesktop -Servers "localhost" -Force -SkipFirewall
            Should -Invoke -CommandName Set-NetFirewallRule -Times 0 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should create firewall rules if none exist" {
            Mock Get-NetFirewallRule { return $null } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
            $result = Enable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName New-NetFirewallRule -Times 1 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
    }
    
    Context "When enabling RDP on remote servers" {
        It "Should handle multiple servers" {
            $servers = @("server1", "server2", "server3")
            $results = Enable-RemoteDesktop -Servers $servers -Force
            $results | Should -HaveCount 3
            $results[0].Success | Should -Be $true
        }
        
        It "Should handle connection failures" {
            Mock Test-Connection { return $false } -ModuleName RDPAccessControl
            $result = Enable-RemoteDesktop -Servers "unreachableserver" -Force
            $result[0].Success | Should -Be $false
        }
        
        It "Should use PowerShell remoting for remote servers" {
            $result = Enable-RemoteDesktop -Servers "remoteserver" -Force
            Should -Invoke -CommandName Invoke-Command -Times 1 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should handle remote errors gracefully" {
            $result = Enable-RemoteDesktop -Servers "errorserver" -Force
            $result[0].Success | Should -Be $false
        }
    }
    
    Context "When permission checks are performed" {
        It "Should verify administrative privileges" {
            # Mock non-admin
            $nonAdminPrincipal = [PSCustomObject]@{
                IsInRole = { param($role) return $false }
            }
            Mock Get-CurrentPrincipal { return $nonAdminPrincipal } -ModuleName RDPAccessControl
            
            $result = Enable-RemoteDesktop -Servers "localhost" -Force
            $result | Should -BeNullOrEmpty
        }
    }
    
    Context "When user confirmation is required" {
        It "Should prompt for confirmation when not forced" {
            $result = Enable-RemoteDesktop -Servers "localhost"
            Should -Invoke -CommandName Read-Host -Times 1 -ModuleName RDPAccessControl
        }
        
        It "Should skip confirmation when using -Force" {
            $result = Enable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Read-Host -Times 0 -ModuleName RDPAccessControl
        }
        
        It "Should abort when user says no" {
            Mock Read-Host { return "n" } -ModuleName RDPAccessControl
            $result = Enable-RemoteDesktop -Servers "localhost"
            $result | Should -BeNullOrEmpty
        }
    }
}

Describe "Disable-RemoteDesktop" {
    BeforeAll {
        # Set up mocks
        MockRegistryAccess
        
        # Mock administrator check
        $mockPrincipal = [PSCustomObject]@{
            IsInRole = { param($role) return $true }
        }
        Mock Get-CurrentPrincipal { return $mockPrincipal } -ModuleName RDPAccessControl
        
        # Mock confirmation
        Mock Read-Host { return "y" } -ModuleName RDPAccessControl
        
        # Mock RDP enabled registry for verification
        Mock Get-ItemProperty { 
            return [PSCustomObject]@{ 
                fDenyTSConnections = 1  # Disabled after operation
            } 
        } -ParameterFilter { $Path -like '*Terminal Server*' -and $ErrorAction -eq 'SilentlyContinue' } -ModuleName RDPAccessControl
    }
    
    Context "When disabling RDP on a local server" {
        BeforeEach {
            # Reset mock counts
            Mock Set-ItemProperty { } -ModuleName RDPAccessControl
            Mock Set-NetFirewallRule { } -ModuleName RDPAccessControl
        }
        
        It "Should disable RDP by setting registry value" {
            $result = Disable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Set-ItemProperty -Times 1 -ParameterFilter { 
                $Path -like '*Terminal Server*' -and $Name -eq 'fDenyTSConnections' -and $Value -eq 1 
            } -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should disable firewall rules" {
            $result = Disable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Set-NetFirewallRule -Times 1 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
        
        It "Should keep firewall rules enabled when requested" {
            $result = Disable-RemoteDesktop -Servers "localhost" -Force -KeepFirewall
            Should -Invoke -CommandName Set-NetFirewallRule -Times 0 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
    }
    
    Context "When disabling RDP on remote servers" {
        It "Should handle multiple servers" {
            $servers = @("server1", "server2", "server3")
            $results = Disable-RemoteDesktop -Servers $servers -Force
            $results | Should -HaveCount 3
            $results[0].Success | Should -Be $true
        }
        
        It "Should handle connection failures" {
            Mock Test-Connection { return $false } -ModuleName RDPAccessControl
            $result = Disable-RemoteDesktop -Servers "unreachableserver" -Force
            $result[0].Success | Should -Be $false
        }
        
        It "Should use PowerShell remoting for remote servers" {
            $result = Disable-RemoteDesktop -Servers "remoteserver" -Force
            Should -Invoke -CommandName Invoke-Command -Times 1 -ModuleName RDPAccessControl
            $result[0].Success | Should -Be $true
        }
    }
    
    Context "When user confirmation is required" {
        It "Should prompt for confirmation when not forced" {
            $result = Disable-RemoteDesktop -Servers "localhost"
            Should -Invoke -CommandName Read-Host -Times 1 -ModuleName RDPAccessControl
        }
        
        It "Should skip confirmation when using -Force" {
            $result = Disable-RemoteDesktop -Servers "localhost" -Force
            Should -Invoke -CommandName Read-Host -Times 0 -ModuleName RDPAccessControl
        }
    }
}

Describe "Test-RDPAccess" {
    BeforeAll {
        # Set up mocks
        MockRegistryAccess
        
        # Mock for different server scenarios
        Mock Test-Connection { 
            return $ComputerName -ne "unreachable"
        } -ModuleName RDPAccessControl
        
        # Mock for RDP enabled/disabled
        Mock Get-ItemProperty { 
            if ($Path -like '*Terminal Server*') {
                return [PSCustomObject]@{ 
                    fDenyTSConnections = if ($Name -eq "TestEnabled") { 0 } else { 1 }
                }
            }
            return $null
        } -ModuleName RDPAccessControl
        
        # Mock port test
        Mock Test-NetConnection { 
            return [PSCustomObject]@{
                ComputerName = $ComputerName
                TcpTestSucceeded = $ComputerName -ne "portclosed"
                RemotePort = 3389
            }
        } -ModuleName RDPAccessControl
    }
    
    Context "When testing a fully operational server" {
        BeforeAll {
            # Mock RDP enabled
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 0  # Enabled
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
            
            # Mock firewall enabled
            Mock Get-NetFirewallRule { 
                return [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $true
                    Direction = "Inbound"
                }
            } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
        }
        
        It "Should report fully operational status" {
            $result = Test-RDPAccess -Servers "operationalserver"
            $result.OverallStatus | Should -Be "Fully Operational"
            $result.RDPEnabled | Should -Be "Yes"
            $result.FirewallStatus | Should -Be "Open"
            $result.Port3389Open | Should -Be "Yes"
        }
        
        It "Should collect detailed information when requested" {
            $result = Test-RDPAccess -Servers "operationalserver" -Detailed
            $result | Should -Not -BeNullOrEmpty
            $result.PSObject.Properties.Name | Should -Contain "TerminalServiceStatus"
        }
    }
    
    Context "When testing a server with configuration issues" {
        It "Should identify disabled RDP" {
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 1  # Disabled
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
            
            $result = Test-RDPAccess -Servers "rdpdisabledserver"
            $result.RDPEnabled | Should -Be "No"
            $result.OverallStatus | Should -Not -Be "Fully Operational"
        }
        
        It "Should identify firewall issues" {
            # RDP enabled but firewall disabled
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 0  # Enabled
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
            
            Mock Get-NetFirewallRule { 
                return [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $false
                }
            } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
            
            $result = Test-RDPAccess -Servers "firewalldisabledserver"
            $result.FirewallStatus | Should -Be "Blocked"
            $result.OverallStatus | Should -Be "RDP Enabled but Firewall Blocked"
        }
        
        It "Should identify port connectivity issues" {
            # All enabled but port blocked
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 0  # Enabled
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
            
            Mock Get-NetFirewallRule { 
                return [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $true
                    Direction = "Inbound"
                }
            } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
            
            Mock Test-NetConnection { 
                return [PSCustomObject]@{
                    ComputerName = $ComputerName
                    TcpTestSucceeded = $false
                    RemotePort = 3389
                }
            } -ModuleName RDPAccessControl
            
            $result = Test-RDPAccess -Servers "portblockedserver"
            $result.Port3389Open | Should -Be "No"
            $result.OverallStatus | Should -Be "Configured but Port Blocked"
        }
    }
    
    Context "When testing servers with user access" {
        BeforeAll {
            # All enabled for base case
            Mock Get-ItemProperty { 
                return [PSCustomObject]@{ 
                    fDenyTSConnections = 0  # Enabled
                } 
            } -ParameterFilter { $Path -like '*Terminal Server*' } -ModuleName RDPAccessControl
            
            Mock Get-NetFirewallRule { 
                return [PSCustomObject]@{
                    Name = "RemoteDesktop-UserMode-In-TCP"
                    DisplayName = "Remote Desktop - User Mode (TCP-In)"
                    Enabled = $true
                    Direction = "Inbound"
                }
            } -ParameterFilter { $DisplayGroup -eq "Remote Desktop" } -ModuleName RDPAccessControl
            
            # Mock local group retrieval
            Mock Get-LocalGroupMember { 
                return @(
                    [PSCustomObject]@{
                        Name = "DOMAIN\alloweduser"
                        SID = "S-1-5-21-123456789-123456789-123456789-1234"
                        PrincipalSource = "ActiveDirectory"
                    },
                    [PSCustomObject]@{
                        Name = "DOMAIN\admin"
                        SID = "S-1-5-21-123456789-123456789-123456789-1235"
                        PrincipalSource = "ActiveDirectory"
                    }
                )
            } -ParameterFilter { $Group -eq "Remote Desktop Users" } -ModuleName RDPAccessControl
            
            Mock Get-LocalGroupMember { 
                return @(
                    [PSCustomObject]@{
                        Name = "DOMAIN\admin"
                        SID = "S-1-5-21-123456789-123456789-123456789-1235"
                        PrincipalSource = "ActiveDirectory"
                    }
                )
            } -ParameterFilter { $Group -eq "Administrators" } -ModuleName RDPAccessControl
        }
        
        It "Should check RD Users group membership" {
            $result = Test-RDPAccess -Servers "server1" -TestUser "alloweduser"
            $result.UserAccess | Should -Be "Access Granted"
            $result.OverallStatus | Should -Be "Fully Operational - User Access Confirmed"
        }
        
        It "Should check Administrators group membership" {
            $result = Test-RDPAccess -Servers "server1" -TestUser "admin"
            $result.UserAccess | Should -Be "Access Granted"
            $result.OverallStatus | Should -Be "Fully Operational - User Access Confirmed"
        }
        
        It "Should identify users without access" {
            $result = Test-RDPAccess -Servers "server1" -TestUser "denieduser"
            $result.UserAccess | Should -Be "Access Unknown - User not found"
        }
        
        It "Should handle user check errors gracefully" {
            Mock Get-LocalGroupMember { 
                throw "Access denied"
            } -ModuleName RDPAccessControl
            
            $result = Test-RDPAccess -Servers "server1" -TestUser "anyuser"
            $result.UserAccess | Should -Match "Access Unknown - Error"
        }
    }
    
    Context "When testing multiple servers" {
        It "Should process each server" {
            $servers = @("server1", "server2", "server3")
            $results = Test-RDPAccess -Servers $servers
            $results | Should -HaveCount 3
        }
        
        It "Should handle connection failures gracefully" {
            $servers = @("server1", "unreachable", "server3")
            $results = Test-RDPAccess -Servers $servers
            
            $unreachableServer = $results | Where-Object { $_.Server -eq "unreachable" }
            $unreachableServer.Reachable | Should -Be $false
            $unreachableServer.OverallStatus | Should -Be "Unreachable"
            
            $reachableCount = ($results | Where-Object { $_.Reachable -eq $true }).Count
            $reachableCount | Should -Be 2
        }
    }
}
