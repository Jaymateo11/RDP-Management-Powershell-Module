# Changelog

All notable changes to the RDP Management PowerShell Module will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-04-20

### Added

- Initial release of the RDP Management PowerShell Module
- Session management capabilities:
  - `Get-RDPSessions`: Lists all active RDP sessions on specified server(s)
  - `Stop-RDPSession`: Terminates specific RDP session(s) by ID
  - `Test-RDPStatus`: Checks RDP connectivity and configuration status
- Access control features:
  - `Enable-RemoteDesktop`: Enables RDP and configures necessary firewall rules
  - `Disable-RemoteDesktop`: Disables RDP and updates firewall rules accordingly
  - `Test-RDPAccess`: Tests RDP connectivity and configuration status with detailed diagnostics
- Comprehensive documentation
- PowerShell module structure with proper exports
- Support for both single-server and multi-server operations
- Error handling and logging
- Parameter validation for all functions

### Changed

- Converted original Warp workflow scripts to proper PowerShell module format
- Enhanced error handling and user feedback
- Improved validation of administrative requirements

### Dependencies

- PowerShell 5.1 or later
- Administrative privileges for most operations

