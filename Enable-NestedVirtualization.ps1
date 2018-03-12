$vmName = "20697-2B-LON-CL4"

# 4GB RAM
Set-VMMemory -VMName $vmName -StartupBytes 4GB -DynamicMemoryEnabled $false

# vExtensions on CPU
Set-VMProcessor -VMName $vmName -ExposeVirtualizationExtensions $true

# MacAddress Spoofing
Get-VMNetworkAdapter -VMName $vmName | Set-VMNetworkAdapter -MacAddressSpoofing On