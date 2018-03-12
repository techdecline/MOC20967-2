@{
    AllNodes = @(
        @{
            NodeName = "*"
            DomainName = "Lab.com"
            AdministratorPassword = "Passw0rd"
            SwitchName = "Lab1"
            Edition = "Datacenter"
            VHDLocation = "C:\Lab"
            VMLocation = "C:\Lab"
            DomainJoinAccount = "Administrator"
        }
        @{
            NodeName = "Lab-DC1"
            MasterDiskPath = "C:\Temp\Master2016.vhdx"
            OperatingSystem = "W2016"
            },
        @{
            NodeName = "Lab-Server1"
            MasterDiskPath = "C:\Temp\Master2016.vhdx"
            OperatingSystem = "W2016"
            },
        @{
            NodeName = "Lab-Client1"
            MasterDiskPath = "C:\temp\Master_W10_1709_x64.vhdx"
            OperatingSystem = "W10"
            }
)
}