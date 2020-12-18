#
# HW M4 P1 (DHCP Failover)
#

# Set local credentials
$Password = ConvertTo-SecureString -AsPlainText "Password1" -Force
$LocalUser = "Administrator" 
$LC = New-Object System.Management.Automation.PSCredential($LocalUser, $Password)

# Set domain credentials
$Domain = "WSAA.LAB"
$DomainUser = "$Domain\Administrator" 
$DC = New-Object System.Management.Automation.PSCredential($DomainUser, $Password)

# Clone VHDs
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW41-DC.vhdx
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW41-SRV1.vhdx
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW41-SRV2.vhdx

# Create VMs (add -MemoryMaximumBytes to Set-VM)
New-VM -Name HW41-DC -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW41-DC.vhdx -Generation 2 -SwitchName "Hyper-V Internal Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false
New-VM -Name HW41-SRV1 -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW41-SRV1.vhdx -Generation 2 -SwitchName "Hyper-V Internal Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false
New-VM -Name HW41-SRV2 -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW41-SRV2.vhdx -Generation 2 -SwitchName "Hyper-V Internal Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false

# Start VMs
Start-VM -Name HW41-DC, HW41-SRV1, HW41-SRV2

# Ensure that the Administrator password is set in each VM
pause

# Change OS name
Invoke-Command -VMName HW41-DC -Credential $LC -ScriptBlock { Rename-Computer -NewName HW41-DC -Restart  }
Invoke-Command -VMName HW41-SRV1 -Credential $LC -ScriptBlock { Rename-Computer -NewName HW41-SRV1 -Restart  }
Invoke-Command -VMName HW41-SRV2 -Credential $LC -ScriptBlock { Rename-Computer -NewName HW41-SRV2 -Restart  }

# Set network settings for the first NIC on each VM
Invoke-Command -VMName HW41-DC -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.66.2" -PrefixLength 24 -DefaultGateway 192.168.66.1 }
Invoke-Command -VMName HW41-SRV1 -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.66.3" -PrefixLength 24 -DefaultGateway 192.168.66.1 ; Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.66.2 }

# Install AD DS + DNS + DHCP on the DC
Invoke-Command -VMName HW41-DC -Credential $LC -ScriptBlock { Install-WindowsFeature AD-Domain-Services, DNS, DHCP -IncludeManagementTools }
Invoke-Command -VMName HW41-DC -Credential $LC -ScriptBlock { Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName $args[0] -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $args[1] } -ArgumentList $Domain, $Password

# Wait for the AD to be setup
pause

# Join the other server (SRV1) machine to the domain
Invoke-Command -VMName HW41-SRV1 -Credential $LC -ScriptBlock { Add-Computer -DomainName $args[0] -Credential $args[1] -Restart } -ArgumentList $Domain, $DC

# Wait for the VM to join to the domain
pause

# Install DHCP role on SERVER1
Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Install-WindowsFeature DHCP -IncludeManagementTools }

# Configure DHCP service on both DHCP servers (DC and SRV1)
Invoke-Command -VMName HW41-DC -Credential $DC -ScriptBlock { Add-DhcpServerSecurityGroup ; Restart-Service DHCPServer ; Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2 ; Add-DhcpServerInDC -DnsName hw41-dc.wsaa.lab -IPAddress 192.168.66.2 }
Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Restart-Service DHCPServer ; Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2 ; Add-DhcpServerInDC -DnsName hw41-srv1.wsaa.lab -IPAddress 192.168.66.3 }

# Create a DHCP scope (with 2 minutes lease time for demonstration purposes) on SRV1 and set some options
Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Add-DhcpServerv4Scope -Name "Homework" -StartRange 192.168.66.100 -EndRange 192.168.66.200 -SubnetMask 255.255.255.0 -LeaseDuration 0.0:2:0 }
Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Set-DhcpServerv4OptionValue -ScopeId 192.168.66.0 -DnsServer 192.168.66.2 -DnsDomain "wsaa.lab" -Router 192.168.66.1 }

# Create a failover relationship 
# An active-active relationship
#Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Add-DhcpServerv4Failover -Name "DHCP-FO-AA" -PartnerServer "hw41-dc.wsaa.lab" -ScopeId 192.168.66.0 -SharedSecret "Secret1" }

# An active-passive relationship
#Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Add-DhcpServerv4Failover -Name "DHCP-FO-AP" -PartnerServer "hw41-dc.wsaa.lab" -ServerRole Standby -ScopeId 192.168.66.0 }

# An active-active relationship with load balance amount of 50%
Invoke-Command -VMName HW41-SRV1 -Credential $DC -ScriptBlock { Add-DhcpServerv4Failover -Name "DHCP-FO-AA-LB" -PartnerServer "hw41-dc.wsaa.lab" -ScopeId 192.168.66.0 -LoadBalancePercent 50 -MaxClientLeadTime 00:01:00 -AutoStateTransition $False }

# Obtain address on SRV2 if it doesn't have one
# Use ipconfig /all to check from which server it took the address. It should be the SRV1 (192.168.66.3)
# Either stop the DHCP service on SRV1 or change the load balance percentage to 100% for the DC
# Release and renew the address on SRV2. Check again which DHCP server gave it


#
# HW M4 P2 (NAT)
#

# Set local credentials
$Password = ConvertTo-SecureString -AsPlainText "Password1" -Force
$LocalUser = "Administrator" 
$LC = New-Object System.Management.Automation.PSCredential($LocalUser, $Password)

# Set domain credentials
$Domain = "WSAA.LAB"
$DomainUser = "$Domain\Administrator" 
$DC = New-Object System.Management.Automation.PSCredential($DomainUser, $Password)

# Clone VHDs
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW42-RTR.vhdx
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW42-DC.vhdx
cp 'C:\BAK\WIN-SRV-2K19-ST\VHD\WIN-SRV-2K19-ST.vhdx' C:\HV\HW42-SRV.vhdx

# Create VMs (add -MemoryMaximumBytes to Set-VM)
New-VM -Name HW42-RTR -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW42-RTR.vhdx -Generation 2 -SwitchName "Hyper-V Internal Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false
New-VM -Name HW42-DC -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW42-DC.vhdx -Generation 2 -SwitchName "Private Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false
New-VM -Name HW42-SRV -MemoryStartupBytes 1536mb -VHDPath C:\HV\HW42-SRV.vhdx -Generation 2 -SwitchName "Private Switch" | Set-VM -CheckpointType Production -AutomaticCheckpointsEnabled $false

# Start VMs
Start-VM -Name HW42-RTR, HW42-DC, HW42-SRV

# Ensure that the Administrator password is set in each VM
pause

# Change OS name
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { Rename-Computer -NewName HW42-RTR -Restart  }
Invoke-Command -VMName HW42-DC -Credential $LC -ScriptBlock { Rename-Computer -NewName HW42-DC -Restart  }
Invoke-Command -VMName HW42-SRV -Credential $LC -ScriptBlock { Rename-Computer -NewName HW42-SRV -Restart  }

# Set network settings for the existing NICs on each VM
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.66.2" -PrefixLength 24 -DefaultGateway 192.168.66.1 ; Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 1.1.1.1 }
Invoke-Command -VMName HW42-DC -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.200.2" -PrefixLength 24 -DefaultGateway 192.168.200.1 }
Invoke-Command -VMName HW42-SRV -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "192.168.200.3" -PrefixLength 24 -DefaultGateway 192.168.200.1 ; Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.200.2 }

# Add a new NIC to HW42-RTR connected to the Private Switch
Add-VMNetworkAdapter -VMName HW42-RTR -SwitchName "Private Switch"

# Set the address of the second NIC
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress "192.168.200.1" -PrefixLength 24 }

# Install AD DS + DNS + DHCP on the DC
Invoke-Command -VMName HW42-DC -Credential $LC -ScriptBlock { Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools }
Invoke-Command -VMName HW42-DC -Credential $LC -ScriptBlock { Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "WinThreshold" -DomainName $args[0] -ForestMode "WinThreshold" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true -SafeModeAdministratorPassword $args[1] } -ArgumentList $Domain, $Password

# Wait for the AD to be setup
pause

# Add a DNS forwarder in DC
Invoke-Command -VMName HW42-DC -Credential $DC -ScriptBlock { Add-DnsServerForwarder -IPAddress 1.1.1.1 }

# Join the other server (SRV) machine to the domain
Invoke-Command -VMName HW42-SRV -Credential $LC -ScriptBlock { Add-Computer -DomainName $args[0] -Credential $args[1] -Restart } -ArgumentList $Domain, $DC

# Wait for the VM to join to the domain
pause

# Rename both NICs on the RTR
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { Rename-NetAdapter -Name "Ethernet" -NewName "External" ; Rename-NetAdapter -Name "Ethernet 2" -NewName "Internal" }

# Install additional roles and services on the RTR
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { Install-WindowsFeature Routing -IncludeManagementTools }

# Install the NAT functionality
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { Install-RemoteAccess -VpnType RoutingOnly }

# Configure NAT and interfaces
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { cmd.exe /c "netsh routing ip nat install" }
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { cmd.exe /c "netsh routing ip nat add interface External" }
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { cmd.exe /c "netsh routing ip nat set interface External mode=full" }
Invoke-Command -VMName HW42-RTR -Credential $LC -ScriptBlock { cmd.exe /c "netsh routing ip nat add interface Internal" }

# Log on to the SRV machine and test the Internet connectivity with either ping or Test-NetConnection