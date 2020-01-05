<#
    .SYNOPSIS
    Get Certificate data from one or more certificate athorities.
 
    .PARAMETER SearchPath
    Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)
 
    .PARAMETER ExcludeProperties
    Certificate properties to exclude in the output.

    Default excluded fields
        PSPath
        PSParentPath
        PSChildName
        EnhancedKeyUsageList
        PSDrive
        PSProvider
        PSIsContainer
        PrivateKey
        PublicKey
        RawData
        SendAsTrustedIssuer
        EnrollmentServerEndPoint
        Extensions
        EnrollmentPolicyEndPoint
        DnsNameList
        PolicyId
        Handle
        Archived

    Note: included fields will vary depending on cert type and properties included in the cert
 
    .EXAMPLE
    Get-LocalStoreCertificates.ps1
    Recurse all certificates in "Cert:\LocalMachine"
 
    .EXAMPLE
    Get-LocalStoreCertificates.ps1 -SearchPath "Cert:\LocalMachine\CA"
    Recurse all certificates in "Cert:\LocalMachine\CA"


    .EXAMPLE
    Get-LocalStoreCertificates.ps1 -SearchPath "Cert:\LocalMachine\CA" -ExcludeProperties = ('PSPath','PSDrive')
    Recurse all certificates in "Cert:\LocalMachine\CA" and only exclude the PSDrive and PSpath properties.


   #>
[CmdletBinding()]
Param (
        
    # Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)
    [String]
    $SearchPath = "Cert:\LocalMachine",

    # Certificate Fields to exclude in Export
    [String[]]
    $ExcludeProperties = ('PSPath',
                        'PSParentPath',
                        'PSChildName',
                        'EnhancedKeyUsageList',
                        'PSDrive',
                        'PSProvider',
                        'PSIsContainer',
                        'PrivateKey',
                        'PublicKey',
                        'RawData',
                        'SendAsTrustedIssuer',
                        'EnrollmentServerEndPoint',
                        'Extensions',
                        'EnrollmentPolicyEndPoint',
                        'DnsNameList',
                        'PolicyId','Handle','Archived')
) 

Get-ChildItem $SearchPath -Recurse | where { -not $_.PSIsContainer} | Select-Object * -ExcludeProperty @($ExcludeProperties)
