# Enable Firewall for SMB
Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" |
    Enable-NetFirewallRule

# Create Folder for Images Share
New-Item E:\Images -ItemType Directory

# Create new SMB File Share
New-SmbShare -Path E:\Images -Name Images -ChangeAccess adatum\administrator