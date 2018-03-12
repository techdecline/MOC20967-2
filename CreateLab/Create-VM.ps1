#Requires -RunAsAdministrator

param (
    $vhdLocation = "G:\Hyper-V\VHD",
    $vmLocation = "G:\Hyper-V",
    $vmName = "DC1",
    $Organization='DEcLInE Lab',
    $Owner='Cornelius Schuchardt',
    $TimeZone='W. Europe Standard Time',
    $AdminPassword='Passw0rd',
    $Edition="WindowsServer2012R2ServerStandard",
	[int64]$MemoryBytes=2048MB,
    $NetworkSwitch="Private Switch",
	[switch]$JoinDomain,
	$DomainName="decline.lab",
	$DomainJoinPassword="Passw0rd",
	$DomainJoinAccount="Administrator",
	[switch]$StartVM,
	[switch]$CreateDifferencingDisk,
    $MasterDiskPath = "\\wdmycloud\Cornelius\Downloads\Images\Betriebssysteme\Windows Server 2012 R2 MSDN\Master.vhdx",

	[Parameter(Mandatory=$true)]
	[ValidateSet("W2012","W2016","W10")]
	[String]$OperatingSystem,

	[Parameter(Mandatory=$false)]
	[ValidateScript({Test-Path $_})]
	[String]$ConfigDataFile
)

## Function definition

function Get-ScriptDirectory {
    Split-Path -parent $PSCommandPath
}

function Get-FirstRunForVM {
	param ($VmName,$ScriptRoot)
	$configFile = Get-ChildItem (Join-Path -Path $ScriptRoot -ChildPath "ConfigRepo") -Filter $vmName*
	if ($configFile)
	{
		return $configFile.FullName
	}
	else
	{
		return $null
	}
}

## Start script execution

#$MasterDiskPath = $vhdLocation + "\Master.vhdx"
#$MasterDiskPath = "G:\Hyper-V\VHD\Master.vhdx"
$newVhdPath = $vhdLocation + "\" + $vmName + ".vhdx"
$scriptPath = Get-ScriptDirectory

if ($CreateDifferencingDisk)
{
	# Create new differencing disk from Win2012 Master and mount newly created disk
	New-VHD -Differencing -Path $newVhdPath -ParentPath $MasterDiskPath
}
else
{
	Copy-Item $MasterDiskPath -Destination $newVhdPath
}
Mount-diskimage $newVhdPath
$DriveLetter=(Get-DiskImage $newVhdPath | get-disk | get-partition | Where-Object {$_.Size -GT 1GB}).DriveLetter

# Evaluate OS Parameter for Template Selection
switch ($OperatingSystem) {
	"W2012" { $UnattendTemplate="Unattend-template_W2012.xml" }
	"W2016" { $UnattendTemplate="Unattend-template_W2016.xml" }
	"W10" 	{ $UnattendTemplate="Unattend-template_W10.xml" }
	Default {}
}

# Edit unattend.xml Template
$Unattendfile=New-Object XML
$Unattendfile.Load($scriptPath+"\"+$UnattendTemplate)
$Unattendfile.unattend.settings.component[0].ComputerName=$VMName
#$Unattendfile.unattend.settings.component[0].ProductKey=$ProductKey
$Unattendfile.unattend.settings.component[0].RegisteredOrganization=$Organization
$Unattendfile.unattend.settings.component[0].RegisteredOwner=$Owner
$Unattendfile.unattend.settings.component[0].TimeZone=$TimeZone
if ($JoinDomain)
{
	$Unattendfile.unattend.settings.component[1].Identification.Credentials.Domain=$DomainName
	$Unattendfile.unattend.settings.component[1].Identification.Credentials.Password=$DomainJoinPassword
	$Unattendfile.unattend.settings.component[1].Identification.Credentials.Username=$DomainJoinAccount
	$Unattendfile.unattend.settings.component[1].Identification.JoinDomain = $DomainName

	$Unattendfile.unattend.settings.Component[2].RegisteredOrganization=$Organization
	$Unattendfile.unattend.settings.Component[2].RegisteredOwner=$Owner
	$UnattendFile.unattend.settings.component[2].UserAccounts.AdministratorPassword.Value=$AdminPassword
	$UnattendFile.unattend.settings.component[2].autologon.password.value=$AdminPassword
}
else
{
	$xmlElement = ($UnattendFile.unattend.settings[0].component | Where-Object {$_.name -match "Join"})
	$UnattendFile.unattend.settings[0].RemoveChild($xmlElement)

	$Unattendfile.unattend.settings.Component[1].RegisteredOrganization=$Organization
	$Unattendfile.unattend.settings.Component[1].RegisteredOwner=$Owner
	$UnattendFile.unattend.settings.component[1].UserAccounts.AdministratorPassword.Value=$AdminPassword
	$UnattendFile.unattend.settings.component[1].autologon.password.value=$AdminPassword
}
$UnattendXML=$scriptPath+"\"+$VMName+".xml"
$Unattendfile.save($UnattendXML)

# Inject Unattend.xml in newly created disk
$DestinationUnattend = $DriveLetter + ":\Windows\System32\Sysprep\unattend.xml"
$ScriptFolder = $DriveLetter + ":\sys\"
$scriptDestination = $ScriptFolder + "firstRun.ps1"
$batDestination = $ScriptFolder + "firststart.cmd"
$sourceScriptPath = Get-FirstRunForVM -VmName $vmName -ScriptRoot $scriptPath
$firstRunBat = $scriptPath + "\firststart.cmd"

# Inject Config Data File in newly created disk
if ($ConfigDataFile)
{
	Copy-Item $ConfigDataFile -Destination ( Join-Path -Path $scriptFolder -ChildPath "ConfigDataFile.psd1" )
}

Copy-Item -Path $firstRunBat -Destination $batDestination
Copy-Item -Path $sourceScriptPath -Destination $ScriptDestination
Copy-Item -Path $Unattendxml -Destination $destinationUnattend

# Copy required PowerShell Modules
if ($OperatingSystem -ne "W10") {
	$moduleDestination = $DriveLetter + ":\Program Files\WindowsPowerShell\Modules"
	Get-ChildItem (Join-Path $scriptPath -ChildPath Modules) | ForEach-Object {Copy-Item $_.FullName -Destination $moduleDestination -Recurse}
}

# Prepare Registry
$RemoteReg=$DriveLetter+":\Windows\System32\config\Software"
REG LOAD 'HKLM\REMOTEPC' $RemoteReg
NEW-ITEMPROPERTY "HKLM:REMOTEPC\Microsoft\Windows\CurrentVersion\RunOnce\" -Name "PoshStart" -Value "C:\sys\firststart.cmd"
REG UNLOAD 'HKLM\REMOTEPC'

Dismount-DiskImage $newVhdPath

# Create new VM
#$vmPath = $vmLocation + "\" + $vmName
#New-Item $vmPath -ItemType Directory

$vmPath = $vmLocation
$vm = New-VM -Name $vmName -MemoryStartupBytes $MemoryBytes -VHDPath $newVhdPath -SwitchName $NetworkSwitch -Generation 2 -Path $vmPath
set-vm $vm -ProcessorCount 2
Set-VMFirmware $vm -EnableSecureBoot Off
if ($StartVM)
{
	Start-VM -Name $vmName
}

# Remove Unattend File
if ( Test-Path -Path $Unattendxml ) {
	Remove-Item $UnattendXML
}