# CreateLab

## Purpose

This Project is contains all script files that are required to spawn a new Active Directory Environment based on Windows Server 2016 oder Windows Server 2012 R2 based on Firstrun files and given sysprepped Master Images.

## Requirements

In order to use this toolbox basic PowerShell reading and writing skills are welcome. Additionally, you will need to create your own Master Images for desired platforms.

## How to Create a new Lab Environment

1. Create or download a masterdisk in .VHDX Format (for Windows Server 2012 R2 or Windows Server 2016)
2. Create PowerShell Data File in .\Configuration describing your desired configuration (See existing Files for reference).
3. Verify existence of config files for your VM in .\ConfigRepo. Otherwise create target config files (normally by cloning the existing ones).
4. Run Create-Lab.ps1 from a privileged PowerShell Session using the -ConfigurationData parameter with your newly created PSD1 file (see step 2.)
5. Wait for the script to finish

## What will the script create?

With minimal customization (see How to Create a new Lab Environment) Create-Lab.ps1 will spawn a new isolated AD Environment with one Domain Controller and two Member Servers.

## Known Issues and planned features

* Due to missing XML-capabilities in .Net Core, the scripts cannot be used on Windows Server 2016 Nano.
* Lab Creation on a remote Hypervisor is currently not enabled.
* Packaging in Module Form Factor is missing.

## Used Technologies

* PowerShell Desired State Configuration
* Unattend.xml Files
* Hyper-V