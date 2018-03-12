#Find-Module xActiveDirectory | Install-Module -SkipPublisherCheck -Force
#Find-Module xNetworking | Install-Module -SkipPublisherCheck -Force

param (
	[String]$ConfigurationData = "C:\sys\ConfigDataFile.psd1"
)


function New-SelfSignedCertificateEx
{
	[CmdletBinding(DefaultParameterSetName = 'Store')]
	param
	(
		[Parameter(Mandatory, Position = 0)]
		[string]$Subject,

		[Parameter(Position = 1)]
		[DateTime]$NotBefore = [DateTime]::Now.AddDays(-1),

		[Parameter(Position = 2)]
		[DateTime]$NotAfter = $NotBefore.AddDays(365),

		[string]$SerialNumber,

		[Alias('CSP')]
		[string]$ProviderName = 'Microsoft Enhanced Cryptographic Provider v1.0',

		[string]$AlgorithmName = 'RSA',

		[int]$KeyLength = 2048,

		[ValidateSet('Exchange', 'Signature')]
		[string]$KeySpec = 'Exchange',

		[Alias('EKU')]
		[Security.Cryptography.Oid[]]$EnhancedKeyUsage,

		[Alias('KU')]
		[Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,

		[Alias('SAN')]
		[String[]]$SubjectAlternativeName,

		[bool]$IsCA,

		[int]$PathLength = -1,

		[Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,

		[ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
		[string]$SignatureAlgorithm = 'SHA1',

		[string]$FriendlyName,

		[Parameter(ParameterSetName = 'Store')]
		[Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = 'CurrentUser',

		[Parameter(ParameterSetName = 'Store')]
		[Security.Cryptography.X509Certificates.StoreName]$StoreName = 'My',

		[Parameter(Mandatory = $true, ParameterSetName = 'File')]
		[Alias('OutFile', 'OutPath', 'Out')]
		[IO.FileInfo]$Path,

		[Parameter(Mandatory = $true, ParameterSetName = 'File')]
		[Security.SecureString]$Password,

		[switch]$AllowSMIME,

		[switch]$Exportable,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$PassThru
	)

	$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop;

	# Ensure we are running on a supported platform.
	if ([Environment]::OSVersion.Version.Major -lt 6)
	{
		throw (New-Object NotSupportedException -ArgumentList 'Windows XP and Windows Server 2003 are not supported!');
	}

	#region Constants

	#region Contexts
	New-Variable -Name UserContext -Value 0x1 -Option Constant;
	New-Variable -Name MachineContext -Value 0x2 -Option Constant;
	#endregion Contexts

	#region Encoding
	New-Variable -Name Base64Header -Value 0x0 -Option Constant;
	New-Variable -Name Base64 -Value 0x1 -Option Constant;
	New-Variable -Name Binary -Value 0x3 -Option Constant;
	New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant;
	#endregion Encoding

	#region SANs
	New-Variable -Name OtherName -Value 0x1 -Option Constant;
	New-Variable -Name RFC822Name -Value 0x2 -Option Constant;
	New-Variable -Name DNSName -Value 0x3 -Option Constant;
	New-Variable -Name DirectoryName -Value 0x5 -Option Constant;
	New-Variable -Name URL -Value 0x7 -Option Constant;
	New-Variable -Name IPAddress -Value 0x8 -Option Constant;
	New-Variable -Name RegisteredID -Value 0x9 -Option Constant;
	New-Variable -Name Guid -Value 0xa -Option Constant;
	New-Variable -Name UPN -Value 0xb -Option Constant;
	#endregion SANs

	#region Installation options
	New-Variable -Name AllowNone -Value 0x0 -Option Constant;
	New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant;
	New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant;
	New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant;
	#endregion Installation options

	#region PFX export options
	New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant;
	New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant;
	New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant;
	#endregion PFX export options

	#endregion Constants

	#region Subject processing
	# http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
	$subjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName;
	$subjectDN.Encode($Subject, 0x0);
	#endregion Subject processing

	#region Extensions

	# Array of extensions to add to the certificate.
	$extensionsToAdd = @();

	#region Enhanced Key Usages processing
	if ($EnhancedKeyUsage)
	{
		$oIDs = New-Object -ComObject X509Enrollment.CObjectIDs;
		$EnhancedKeyUsage | ForEach-Object {
			$oID = New-Object -ComObject X509Enrollment.CObjectID;
			$oID.InitializeFromValue($_.Value);

			# http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
			$oIDs.Add($oID);
		}

		# http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
		$eku = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage;
		$eku.InitializeEncode($oIDs);
		$extensionsToAdd += 'EKU';
	}
	#endregion Enhanced Key Usages processing

	#region Key Usages processing
	if ($KeyUsage -ne $null)
	{
		$ku = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage;
		$ku.InitializeEncode([int]$KeyUsage);
		$ku.Critical = $true;
		$extensionsToAdd += 'KU';
	}
	#endregion Key Usages processing

	#region Basic Constraints processing
	if ($PSBoundParameters.Keys.Contains('IsCA'))
	{
		# http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
		$basicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints;
		if (!$IsCA)
		{
			$PathLength = -1;
		}
		$basicConstraints.InitializeEncode($IsCA, $PathLength);
		$basicConstraints.Critical = $IsCA;
		$extensionsToAdd += 'BasicConstraints';
	}
	#endregion Basic Constraints processing

	#region SAN processing
	if ($SubjectAlternativeName)
	{
		$san = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames;
		$names = New-Object -ComObject X509Enrollment.CAlternativeNames;
		foreach ($altName in $SubjectAlternativeName)
		{
			$name = New-Object -ComObject X509Enrollment.CAlternativeName;
			if ($altName.Contains('@'))
			{
				$name.InitializeFromString($RFC822Name, $altName);
			}
			else
			{
				try
				{
					$bytes = [Net.IPAddress]::Parse($altName).GetAddressBytes();
					$name.InitializeFromRawData($IPAddress, $Base64, [Convert]::ToBase64String($bytes));
				}
				catch
				{
					try
					{
						$bytes = [Guid]::Parse($altName).ToByteArray();
						$name.InitializeFromRawData($Guid, $Base64, [Convert]::ToBase64String($bytes));
					}
					catch
					{
						try
						{
							$bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altName).RawData;
							$name.InitializeFromRawData($DirectoryName, $Base64, [Convert]::ToBase64String($bytes));
						}
						catch
						{
							$name.InitializeFromString($DNSName, $altName);
						}
					}
				}
			}
			$names.Add($name);
		}
		$san.InitializeEncode($names);
		$extensionsToAdd += 'SAN';
	}
	#endregion SAN processing

	#region Custom Extensions
	if ($CustomExtension)
	{
		$count = 0;
		foreach ($ext in $CustomExtension)
		{
			# http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
			$extension = New-Object -ComObject X509Enrollment.CX509Extension;
			$extensionOID = New-Object -ComObject X509Enrollment.CObjectId;
			$extensionOID.InitializeFromValue($ext.Oid.Value);
			$extensionValue = [Convert]::ToBase64String($ext.RawData);
			$extension.Initialize($extensionOID, $Base64, $extensionValue);
			$extension.Critical = $ext.Critical;
			New-Variable -Name ('ext' + $count) -Value $extension;
			$extensionsToAdd += ('ext' + $count);
			$count++;
		}
	}
	#endregion Custom Extensions

	#endregion Extensions

	#region Private Key
	# http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
	$privateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey;
	$privateKey.ProviderName = $ProviderName;
	$algorithmID = New-Object -ComObject X509Enrollment.CObjectId;
	$algorithmID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value);
	$privateKey.Algorithm = $algorithmID;

	# http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
	$privateKey.KeySpec = switch ($KeySpec) { 'Exchange' { 1 }; 'Signature' { 2 } }
	$privateKey.Length = $KeyLength;

	# Key will be stored in current user certificate store.
	switch ($PSCmdlet.ParameterSetName)
	{
		'Store'
		{
			$privateKey.MachineContext = if ($StoreLocation -eq 'LocalMachine') { $true }
			else { $false }
		}
		'File'
		{
			$privateKey.MachineContext = $false;
		}
	}

	$privateKey.ExportPolicy = if ($Exportable) { 1 }
	else { 0 }
	$privateKey.Create();
	#endregion Private Key

	#region Build certificate request template

	# http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
	$cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate;

	# Initialize private key in the proper store.
	if ($privateKey.MachineContext)
	{
		$cert.InitializeFromPrivateKey($MachineContext, $privateKey, '');
	}
	else
	{
		$cert.InitializeFromPrivateKey($UserContext, $privateKey, '');
	}

	$cert.Subject = $subjectDN;
	$cert.Issuer = $cert.Subject;
	$cert.NotBefore = $NotBefore;
	$cert.NotAfter = $NotAfter;

	#region Add extensions to the certificate
	foreach ($item in $extensionsToAdd)
	{
		$cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly));
	}
	#endregion Add extensions to the certificate

	if (![string]::IsNullOrEmpty($SerialNumber))
	{
		if ($SerialNumber -match '[^0-9a-fA-F]')
		{
			throw 'Invalid serial number specified.';
		}

		if ($SerialNumber.Length % 2)
		{
			$SerialNumber = '0' + $SerialNumber;
		}

		$bytes = $SerialNumber -split '(.{2})' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }
		$byteString = [Convert]::ToBase64String($bytes);
		$cert.SerialNumber.InvokeSet($byteString, 1);
	}

	if ($AllowSMIME)
	{
		$cert.SmimeCapabilities = $true;
	}

	$signatureOID = New-Object -ComObject X509Enrollment.CObjectId;
	$signatureOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value);
	$cert.SignatureInformation.HashAlgorithm = $signatureOID;
	#endregion Build certificate request template

	# Encode the certificate.
	$cert.Encode();

	#region Create certificate request and install certificate in the proper store
	# Interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
	$request = New-Object -ComObject X509Enrollment.CX509enrollment;
	$request.InitializeFromRequest($cert);
	$request.CertificateFriendlyName = $FriendlyName;
	$endCert = $request.CreateRequest($Base64);
	$request.InstallResponse($AllowUntrustedCertificate, $endCert, $Base64, '');
	#endregion Create certificate request and install certificate in the proper store

	#region Export to PFX if specified
	if ($PSCmdlet.ParameterSetName.Equals('File'))
	{
		$PFXString = $request.CreatePFX(
			[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
			$PFXExportEEOnly,
			$Base64
		)
		Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte;
	}
	#endregion Export to PFX if specified

	if ($PassThru.IsPresent)
	{
		@(Get-ChildItem -Path "Cert:\$StoreLocation\$StoreName").where({ $_.Subject -match $Subject })
	}

	$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue;
}

# A configuration to create a SingleDomainForest with one Domain Controller
Configuration SingleDomainForest
{
   param
    (
        [Parameter(Mandatory)]
        [pscredential]$safemodeAdministratorCred,
        [Parameter(Mandatory)]
        [pscredential]$domainCred,
        [Parameter(Mandatory=$false)]
        [pscredential]$DNSDelegationCred,
        [Parameter(Mandatory)]
        [pscredential]$NewADUserCred,
        [Parameter(Mandatory)]
        [String]$InterfaceAlias
    )

    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xDhcpServer

    Node $AllNodes.Where{$_.Role -eq "Primary DC"}.Nodename
    {
        xIPAddress PrimaryIpAddress
        {
            IPAddress = "192.168.0.1"
            PrefixLength = 24
            AddressFamily = "IPv4"
            InterfaceAlias = $InterfaceAlias
        }

        xRoute test
        {
            DestinationPrefix = "0.0.0.0/0"
            InterfaceAlias = $InterfaceAlias
            AddressFamily = "IPv4"
            Ensure = "Present"
            NextHop = "192.168.0.254"
        }

        WindowsFeature ADDSInstall
        {
            Ensure = "Present"
            Name = "AD-Domain-Services"
            DependsOn = "[xIPAddress]PrimaryIpAddress"
        }

		WindowsFeature ADDSMgmt
		{
			Ensure = "Present"
			Name = "RSAT-AD-Tools"
			IncludeAllSubFeature = $true
		}

        xADDomain FirstDS
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            SafemodeAdministratorPassword = $safemodeAdministratorCred
            DnsDelegationCredential = $DNSDelegationCred
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
        xWaitForADDomain DscForestWait
        {
            DomainName = $Node.DomainName
            DomainUserCredential = $domainCred
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[xADDomain]FirstDS"
        }

        xADUser Alice
        {
            DomainName = $Node.DomainName
            DomainAdministratorCredential = $domainCred
            PsDscRunAsCredential =  $domainCred
            UserName = "Alice"
            Password = $NewADUserCred
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        WindowsFeature DHCPServer
        {
            Ensure = "Present"
            Name = "DHCP"
        }

        WindowsFeature RSAT-DHCP
        {
            Ensure = "Present"
            Name = "RSAT-DHCP"
        }


        xDhcpServerAuthorization LocalServerActivation
        {
            Ensure = 'Present'
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xDhcpServerScope Scope
        {
            Ensure = 'Present'
            IPEndRange = '192.168.0.200'
            IPStartRange = '192.168.0.100'
            Name = 'Primary Scope'
            SubnetMask = '255.255.255.0'
            LeaseDuration = ((New-TimeSpan -Hours 8 ).ToString())
            State = 'Active'
            AddressFamily = 'IPv4'
            DependsOn = "[WindowsFeature]DHCPServer"
        }

        xDhcpServerOption Option
        {
            Ensure = 'Present'
            ScopeID = '192.168.0.0'
            DnsDomain = $Node.DomainName
            DnsServerIPAddress = '192.168.0.1'
            AddressFamily = 'IPv4'
            Router = '192.168.0.254'
            DependsOn = "[xDhcpServerScope]Scope"
        }
    }
}

# Generate Certificate
$signedCertParams = @{
	'Subject' = "CN=$env:COMPUTERNAME"
	'SAN' = $env:COMPUTERNAME
	'EnhancedKeyUsage' = 'Document Encryption'
	'KeyUsage' = 'KeyEncipherment', 'DataEncipherment'
	'FriendlyName' = 'DSC Encryption Certifificate'
	'StoreLocation' = 'LocalMachine'
	'StoreName' = 'My'
	'ProviderName' = 'Microsoft Enhanced Cryptographic Provider v1.0'
	'PassThru' = $true
	'KeyLength' = 2048
	'AlgorithmName' = 'RSA'
	'SignatureAlgorithm' = 'SHA256'
}
New-SelfSignedCertificateEx @signedCertParams -OutVariable cert

$thumbPrint = $cert.ThumbPrint
$certFile = Export-Certificate -FilePath C:\Sys\MyCert.cer -Cert $cert.pspath

# Configure LCM
[DSCLocalConfigurationManager()]
configuration PushClientConfigID
{
    param (
        [Parameter(Mandatory=$true)]
        [String]$ComputerName,

        [Parameter(Mandatory=$true)]
        [String]$CertId
    )
    Node $ComputerName
    {
        Settings
        {
            RefreshMode          = 'Push'
            RefreshFrequencyMins = 30
            RebootNodeIfNeeded   = $true
            ConfigurationMode = "ApplyAndMonitor"
            CertificateID = $CertId

        }
    }
}

$configDataHash = Import-PowerShellDataFile -Path $ConfigurationData

$cert = Get-ChildItem Cert:\LocalMachine\My
PushClientConfigID -OutputPath 'C:\Sys' -computerName $env:COMPUTERNAME -certid $cert.Thumbprint
Set-DscLocalConfigurationManager -Path c:\sys -Force -Verbose

# Configuration Data for AD
$ConfigData = @{
    AllNodes = @(
        @{
            Nodename = "$env:COMPUTERNAME"
            Role = "Primary DC"
            DomainName = $configDataHash.AllNodes.DomainName
            CertificateFile = $certFile.FullName
            Thumbprint = $thumbPrint
            RetryCount = 1
            RetryIntervalSec = 30
        }
    )
}

# Generate Password (Development only!)
$Credentials = New-Object System.Management.Automation.PSCredential "Administrator",(ConvertTo-SecureString -AsPlainText ($configDataHash.AllNodes.AdministratorPassword) -Force)
<#
SingleDomainForest -configurationData $ConfigData `
    -safemodeAdministratorCred (Get-Credential -Message "New Domain Safe Mode Admin Credentials") `
    -domainCred (Get-Credential -Message "New Domain Admin Credentials") `
    -NewADUserCred (Get-Credential -Message "New AD User Credentials") `
    -OutputPath C:\Sys
    #-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") `
#>

# Get Network Adapter Interface Alias
$interfaceAlias = (Get-NetIPAddress -AddressFamily IPv4).where{$_.IPAddress -like "169*"}.InterfaceAlias

SingleDomainForest -configurationData $ConfigData `
    -safemodeAdministratorCred $Credentials `
    -domainCred $Credentials `
    -NewADUserCred $Credentials `
    -InterfaceAlias $interfaceAlias `
    -OutputPath "C:\Sys\SingleDomainForest"
    #-DNSDelegationCred (Get-Credential -Message "Credentials to Setup DNS Delegation") `

Start-DscConfiguration -Wait -Force -Verbose -ComputerName "$env:COMPUTERNAME" -Path "C:\Sys\SingleDomainForest"