param (
	[String]$ConfigurationData
)

function Get-ScriptDirectory {
    Split-Path -parent $PSCommandPath
}

# Import Configuration Data File
$configDataHash = Import-PowerShellDataFile -Path $ConfigurationData

$machineArr = $configDataHash.AllNodes.Where({$_.NodeName -ne "*"}) | ForEach-Object {$_.NodeName}
$scriptRoot = Get-ScriptDirectory
$vmCreationScript = $scriptRoot + "\Create-VM.ps1"

# Variable Declaration
$PrivateSwitchName = $configDataHash.AllNodes.switchname
$DomainName = $configDataHash.AllNodes.DomainName
$AdministratorPassword = $configDataHash.AllNodes.AdministratorPassword
$Edition = $configDataHash.AllNodes.Datacenter
#$MasterDiskPath = $configDataHash.AllNodes.MasterDiskPath
$vhdLocation = $configDataHash.AllNodes.VHDLocation
$vmLocation = $configDataHash.AllNodes.VMLocation
$domainJoinAccount = $configDataHash.AllNodes.DomainJoinAccount

# Create new internal switch
if (Get-VMSwitch $PrivateSwitchName -ErrorAction SilentlyContinue)
{
	# Placeholder
}
else {
	New-VMSwitch -Name $PrivateSwitchName -SwitchType Private
}

# Create Virtual Machines
foreach ($vmName in $machineArr)
{
	$MasterDiskPath = $configDataHash.AllNodes.Where({$_.NodeName -eq $vmName}).MasterDiskPath
	$OperatingSystem = $configDataHash.AllNodes.Where({$_.NodeName -eq $vmName}).OperatingSystem
	Write-Host "######## Creating VM: $vmName" -ForegroundColor DarkGreen
	if ($vmName -match "DC")
	{
		& $vmCreationScript -VmName $vmName -StartVM -NetworkSwitch $PrivateSwitchName -Edition $Edition -MasterDiskPath $MasterDiskPath -OperatingSystem $OperatingSystem `
			-VMLocation $vmLocation -VHDLocation $vhdLocation -ConfigDataFile $ConfigurationData
		Start-Sleep -Seconds 600

	}
	else
	{
		& $vmCreationScript -VmName $vmName -JoinDomain -StartVM -NetworkSwitch $PrivateSwitchName -Edition $Edition -MasterDiskPath $MasterDiskPath -OperatingSystem $OperatingSystem `
			-VMLocation $vmLocation -VHDLocation $vhdLocation -DomainJoinPassword $AdministratorPassword -DomainJoinAccount $domainJoinAccount -DomainName $DomainName
	}
}