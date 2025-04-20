# RDP Management PowerShell Module

A comprehensive PowerShell module for managing Remote Desktop Protocol (RDP) sessions, access controls, and user permissions in Windows environments.

## Features

* **Session Management**: List and terminate active RDP sessions across multiple servers
* **Access Control**: Enable/disable Remote Desktop and manage firewall rules
* **Permission Management**: Add/remove users to Remote Desktop Users groups
* **Reporting**: Generate comprehensive session and configuration reports

## Requirements

* PowerShell 5.1 or later
* Windows operating system
* Administrative privileges for most operations
* Windows Remote Management (WinRM) enabled for remote operations
* Network connectivity to target servers

## Installation

### Manual Installation

1. Download or clone this repository to your local machine
2. Copy the entire `RDPManagement` folder to one of the following locations:
   * `C:\Program Files\WindowsPowerShell\Modules\` (system-wide)
   * `C:\Users\<YourUsername>\Documents\WindowsPowerShell\Modules\` (current user)

3. Import the module in your PowerShell session:
```powershell
Import-Module RDPManagement
```

4. Verify the module is loaded:
```powershell
Get-Module RDPManagement
```

### Using PowerShellGet (if published to a repository)

```powershell
Install-Module -Name RDPManagement -Scope CurrentUser
```

## Usage Examples

### Session Management

#### List RDP Sessions
```powershell
# List sessions on local machine
Get-RDPSessions

# List sessions on multiple remote servers
Get-RDPSessions -Servers "server1", "server2", "server3"
```

#### Terminate a Session
```powershell
# Terminate a specific session on a server
Stop-RDPSession -Server "server1" -SessionID 3
```

#### Check RDP Status
```powershell
# Check RDP status on multiple servers
Test-RDPStatus -Servers "server1", "server2" 
```

### Access Control

#### Enable Remote Desktop
```powershell
# Enable RDP on local machine
Enable-RemoteDesktop

# Enable RDP on multiple servers without confirmation
Enable-RemoteDesktop -Servers "server1", "server2" -Force
```

#### Disable Remote Desktop
```powershell
# Disable RDP but keep firewall rules
Disable-RemoteDesktop -KeepFirewall

# Disable RDP on remote server
Disable-RemoteDesktop -Server "server1"
```

#### Test RDP Access
```powershell
# Basic access test
Test-RDPAccess

# Detailed test with user access check
Test-RDPAccess -Servers "server1", "server2" -Detailed -TestUser "username"
```

## Common Troubleshooting

### Permission Issues
* **Symptom**: "Access denied" errors
* **Solution**: Ensure you're running PowerShell as Administrator or have appropriate permissions
  ```powershell
  Start-Process powershell -Verb RunAs
  ```

### Remote Connection Issues
* **Symptom**: Unable to connect to remote servers
* **Solution**: Verify WinRM is enabled and properly configured
  ```powershell
  # Check WinRM configuration
  winrm quickconfig

  # Test WinRM connectivity
  Test-WSMan -ComputerName "server1"
  ```

### Firewall Problems
* **Symptom**: RDP is enabled but connections fail
* **Solution**: Verify firewall rules are properly configured
  ```powershell
  # Check RDP firewall rules
  Get-NetFirewallRule -DisplayGroup "Remote Desktop"
  ```

### Command Not Found
* **Symptom**: Module commands not recognized
* **Solution**: Ensure the module is properly imported
  ```powershell
  # Import the module
  Import-Module RDPManagement -Force
  
  # List available commands
  Get-Command -Module RDPManagement
  ```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

