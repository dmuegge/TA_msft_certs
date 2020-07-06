# Derived from PKITools (David Jones) - https://www.powershellgallery.com/packages/PKITools/1.6
<#
    .Synopsis
    Get list of Certificates issued by Certificate Authorities

    .PARAMETER ExpireInDays
    Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years)

    .PARAMETER Properties
    Fields in the Certificate Authority Database to Export

    -Default Fields Exported
        Issued Common Name
        Certificate Expiration Date
        Certificate Effective Date
        Certificate Template
        Issued Email Address
        Issued Request ID
        Certificate Hash
        Request Disposition
        Request Disposition Message
        Requester Name
    

    -Available Fields
        Archived Key
        Attestation Challenge
        Binary Certificate
        Binary Precertificate
        Binary Public Key
        Binary Request
        Caller Name
        Certificate Effective Date
        Certificate Expiration Date
        Certificate Hash
        Certificate Template
        Effective Revocation Date
        Endorsment Certificate Hash
        Endorsement Key Hash
        Issued Binary Name
        Issued City
        Issued Common Name
        Issued Country/Region
        Issued Device Serial Number
        Issued Distinguished Name
        Issued Domain Coupon
        Issued Email Address
        Issued First Name
        Issued Initials
        Issued Last Name
        Issued Organization
        Issued Organization Unit
        Issued Request ID
        Issued Street Address
        Issued State
        Issued Subject Key Identifier
        Issued Title
        Issued Unstructured Address
        Issued Unstructured Name
        Issuer Name ID
        Key Recovery Agent Hashes
        Officer
        Old Certificate
        Public Key Algorithm
        Public Key Algorithm Parameters
        Public Key Length
        Publish expired Certificate in CRL
        Request Attributes
        Request Binary Name
        Request City
        Request Common Name
        Request Country/Region
        Request Device Serial Number
        Request Disposition
        Request Disposition Message
        Request Distinguished Name
        Request Domain Component
        Request Email Address
        Request First Name
        Request Flags
        Request ID
        Request Initials
        Request Last Name
        Request Organization
        Request Organization Unit
        Request Resolution Date
        Request State
        Request Status Code
        Request Street Address
        Request Submission Date
        Request Title
        Request Type
        Request Unstructured Address
        Request Unstructured Name
        Requestor Name
        Revocation Date
        Revocation Reason
        Serial Number
        Signer Application Policies
        Signer Policies
        Template Enrollment Flags
        Template General Flags
        Template Private Key Flags
        User Principal Name

    .PARAMETER CALocation
    Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)

    .PARAMETER CertificateTemplateOid
    Filter on Certificate Template OID (use Get-CertificateTemplateOID)

    .PARAMETER CommonName
    Filter by Issued Common Name

    .PARAMETER ShowIssuer
    Switch to include Issuer DN in output, default is True
    
    .EXAMPLE
    Get-CAIssuedCertificates.ps1
    This will collect all issued certificates from local CA  
        
    .EXAMPLE
    Get-CAIssuedCertificates.ps1 -CALocation "computername\CAName"

    Get-CAIssuedCertificates.ps1 -CALocation CASVR01\ORG-CA

    This will collect all issued certificates from the ORG-CA instance located on the CASVR01 server
        
    .OUTPUTS
    PSObject
#>
[CmdletBinding()]
Param (
        
    # Maximum number of days from now that a certificate will expire. (Default: 21900 = 60 years)
    [Int]
    $ExpireInDays = 21900,

    # Fields in the Certificate Authority Database to Export
    [String[]]
    $Properties = (
        'Issued Common Name', 
        'Certificate Expiration Date', 
        'Certificate Effective Date', 
        'Certificate Template', 
        'Issued Email Address',
        'Issued Request ID', 
        'Certificate Hash', 
        'Serial Number',
        'Request Disposition',
        'Request Disposition Message', 
        'Request Attributes',
        'Request ID',
        'Requester Name',
        'User Principal Name' ),


    [AllowNull()]
    # Certificate Authority location string "computername\CAName" (Default gets location strings from Current Domain)
    [String[]]
    $CAlocation,

    # Filter on Certificate Template OID (use Get-CertificateTemplateOID)
    [AllowNull()]
    [String]
    $CertificateTemplateOid,

    # Filter by Issued Common Name
    [AllowNull()]
    [String]
    $CommonName,

    # Show Issuer DN
    [Switch]
    $ShowIssuer=$True
) 

function Get-CertificatAuthority
{
<#
        .Synopsis
        Get list of Certificate Authorities from Active directory
        .DESCRIPTION
        Queries Active Directory for Certificate Authorities with Enrollment Services enabled
        .EXAMPLE
        Get-CertificatAuthority 
        .EXAMPLE
        Get-CertificatAuthority -CaName 'MyCA'
        .EXAMPLE
        Get-CertificatAuthority -ComputerName 'CA01' -Domain 'Contoso.com'
        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
#>
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        # Name given when installing Active Directory Certificate Services 
        [string[]]
        $CAName = $null,

        # Name of the computer with Active Directory Certificate Services Installed
        [string[]]
        $ComputerName = $null,

        # Domain to Search
        [String]
        $Domain = (Get-Domain).Name 
    )
    Write-Verbose $Domain
    ## If the DN path does not exist error message set as valid object 
    $CaEnrolmentServices = Get-ADPKIEnrollmentServers $Domain 
    $CAList = $CaEnrolmentServices.Children

    if($CAName)
    {
        $CAList = $CAList | Where-Object -Property Name -In  -Value $CAName
    }
    if ($ComputerName)
    {
        # Make FQDN
        [Collections.ArrayList]$List = @() 
        foreach ($Computer in $ComputerName) 
        { 
            if ($Computer -like "*.$Domain") 
            {
                $null = $List.add($Computer)
            } 
            else 
            {
                $null = $List.add("$($Computer).$Domain")
            }
        } # end foreach
        $CAList = $CAList | Where-Object -Property DNSHostName -In -Value $List
    }
    
    $CAList
}

function Get-CaLocationString 
{
    <#
        .SYNOPSIS
        Gets the Certificate Authority Location String from active directory

        .DESCRIPTION
        Certificate Authority Location Strings are in the form of ComputerName\CAName This info is contained in Active Directory

        .PARAMETER CAName
        Name given when installing Active Directory Certificate Services

        .PARAMETER ComputerName
        Name of the computer with Active Directory Certificate Services Installed

        .PARAMETER Domain
        Domain to retreve data from

        .EXAMPLE
        get-CaLocationString -CAName MyCA
        Gets only the CA Location String for the CA named MyCA

        .EXAMPLE
        get-CaLocationString -ComputerName ca.contoso.com
        Gets only the CA Location String for server with the DNS name of ca.contoso.com

        .EXAMPLE
        get-CaLocationString -Domain contoso.com
        Gets all CA Location Strings for the domain contoso.com

        .NOTES
        Location string are used to connect to Certificate Authority database and extract data.

        .OUTPUTS
        [STRING[]]
    #>


    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        # Name given when installing Active Directory Certificate Services 
        [string[]]
        $CAName = $null,

        # Name of the computer with Active Directory Certificate Services Installed
        [string[]]
        $ComputerName = $null,

        # Domain to Search
        [String]
        $Domain = (Get-Domain).Name 
    )
    $CAList = Get-CertificatAuthority @PSBoundParameters
    foreach ($ca in $CAList) 
    {
        ('{0}\{1}' -f $($ca.dNSHostName), $($ca.name))
    }
}

function Get-Domain
{
    <#
            .Synopsis
            Return the current domain
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-Domain
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    Param
    ()
    Write-Verbose -Message 'Calling GetCurrentDomain()' 
    ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
}

function Get-ADPKIEnrollmentServers
{
    <#
            .Synopsis
            Return the Active Directory objects of the Certificate Authorites
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-PKIEnrollmentServers
    #>
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        [Parameter(Mandatory,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain
    )
    $QueryDN = 'LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=' + $Domain -replace '\.', ',DC=' 
    Write-Verbose -Message "Querying [$QueryDN]"
    $result = [ADSI]$QueryDN
    if (-not ($result.Name)) 
    {
        Throw "Unable to find any Certificate Authority Enrollment Services Servers on domain : $Domain" 
    }
    $result
}

function Get-ADCertificateTemplate
{
    <#
            .Synopsis
            Return the Active Directory objects of the Certificate Authorites
            .DESCRIPTION
            Use .net to get the current domain
            .EXAMPLE
            Get-PKIEnrollmentServers
    #>
    [CmdletBinding()]
    [OutputType([adsi])]
    Param
    (
        [Parameter(Mandatory,HelpMessage='Domain To Query',Position = 0)]
        [string]
        $Domain,
        [Parameter(Mandatory,HelpMessage='Template Name',Position = 1)]
        [string]
        $TemplateName
    )
    $QueryDN = "LDAP://CN=$TemplateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=" + $Domain -replace '\.', ',DC=' 
    Write-Verbose -Message "Querying [$QueryDN]"
    $result = [ADSI]$QueryDN
    if (-not ($result.Name)) 
    {
        Throw "Unable to find any Certificate Authority Enrollment Services Servers on domain : $Domain" 
    }
    $result
}

if(-not $CAlocation){

    $CAlocation =  (get-CaLocationString)
}

#Import state from Splunk
$State = Import-LocalStorage "CertLastID.xml" -DefaultValue (New-Object PSObject -Property @{ LastID = @{} })

foreach ($Location in $CAlocation) 
{
    $CaView = New-Object -ComObject CertificateAuthority.View
    $null = $CaView.OpenConnection($Location)
    $CaView.SetResultColumnCount($Properties.Count)
    
    #region SetOutput Colum
    foreach ($item in $Properties)
    {
        $index = $CaView.GetColumnIndex($false, $item)
        $CaView.SetResultColumn($index)
    }
    #endregion

    #region Filters
    $CVR_SEEK_EQ = 1
    $CVR_SEEK_LT = 2
    $CVR_SEEK_GT = 16
    
    #region filter expiration Date
    $index = $CaView.GetColumnIndex($false, 'Certificate Expiration Date')
    $now = Get-Date
    $expirationdate = $now.AddDays($ExpireInDays)
    if ($ExpireInDays -gt 0)
    { 
        $CaView.SetRestriction($index,$CVR_SEEK_GT,0,$now)
        $CaView.SetRestriction($index,$CVR_SEEK_LT,0,$expirationdate)
    }
    else 
    {
        $CaView.SetRestriction($index,$CVR_SEEK_LT,0,$now)
        $CaView.SetRestriction($index,$CVR_SEEK_GT,0,$expirationdate)
    }
    #endregion filter expiration date

    #region Filter Template
    if ($CertificateTemplateOid)
    {
        $index = $CaView.GetColumnIndex($false, 'Certificate Template')
        $CaView.SetRestriction($index,$CVR_SEEK_EQ,0,$CertificateTemplateOid)
    }
    #endregion

    #region Filter Issued Common Name
    if ($CommonName)
    {
        $index = $CaView.GetColumnIndex($false, 'Issued Common Name')
        $CaView.SetRestriction($index,$CVR_SEEK_EQ,0,$CommonName)
    }
    #endregion

    #region Filter Only issued certificates
    # 20 - issued certificates
    $CaView.SetRestriction($CaView.GetColumnIndex($false, 'Request Disposition'),$CVR_SEEK_EQ,0,20)
    #endregion

    #region filter last run
    $index = $CaView.GetColumnIndex($false, 'Request ID')
    if ($State.LastID["$Location"] -AND $State.LastID["$Location"] -gt 0)
    {
        $CaView.SetRestriction($index,$CVR_SEEK_GT,0,$State.LastId["$Location"])
    }
    #endregion last run

    #endregion

    #region output each retuned row
    $CV_OUT_BASE64HEADER = 0 
    $CV_OUT_BASE64 = 1 
    $RowObj = $CaView.OpenView()
    
    $IssuerDN = (Get-CertificatAuthority).cACertificateDN

    while ($RowObj.Next() -ne -1)
    {
        $Cert = New-Object -TypeName PsObject
        $ColObj = $RowObj.EnumCertViewColumn()
        $null = $ColObj.Next()
        do
        {
            $displayName = $ColObj.GetDisplayName()
            # format Binary Certificate in a savable format.
            if ($displayName -eq 'Binary Certificate')
            {
                $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "_") -Value $($ColObj.GetValue($CV_OUT_BASE64HEADER)) -Force
            }
            elseif ($displayName -eq 'Certificate Hash')
            {
                $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "_") -Value $($ColObj.GetValue($CV_OUT_BASE64)).Replace(' ','') -Force
            }
            else
            {
                $Cert | Add-Member -MemberType NoteProperty -Name $displayName.ToString().Replace(" ", "_") -Value $($ColObj.GetValue($CV_OUT_BASE64)) -Force
            }

        }
        until ($ColObj.Next() -eq -1)
        Clear-Variable -Name ColObj

        if($ShowIssuer){$Cert | Add-Member -MemberType NoteProperty -Name "Issuer" -Value $IssuerDN}

        $Cert

    }

    if($Cert.Request_ID)
    {
        $State.LastID["$Location"] = $Cert.Request_ID
    }
}

# Export state to splunk
$State | Export-LocalStorage "CertLastID.xml"
