# TA-microsoft-certificates
 Microsoft Certificates Add-On for Splunk®

##Introduction
The Microsoft Certificates add-on for Splunk® provides functionality to ingest certificate information from the certificate store on Windows servers and workstations. The add-on also allows the collection of certificate information for issued certificates from Microsoft Certificate Servers.  

##Prerequisites
PowerShell execution policy must allow the execution of scripts on servers where data will be collected.


##Installation
Install the add-on on all search heads, install on all Windows forwarders where certificate data is to be collected. 


##Configuration
The add-on is provided with two default inputs, which are disabled by default. It is recommended this inputs in this file be used as a template to configure inputs on forwarders as needed. See example inputs below:


`` [powershell://CertStore-CA-Issued] ``<br>
`` disabled = 1 ``<br>
`` script = . "$SplunkHome\etc\apps\TA-microsoft-certificates\bin\Get-CAIssuedCertificates.ps1" ``<br>
`` schedule = 0 15 * * 0-6 ``<br>
`` sourcetype = windows:certstore:ca:issued ``<br>
`` index = win_certstore_data ``<br>

The example input above will collect issued certificates information from the local CA.



``[powershell://CertStore-Local] ``<br>
``disabled = 1 ``<br>
``script = . "$SplunkHome\etc\apps\splunk-add-on-windows-certificates\bin\Get-LocalStoreCertificates.ps1" ``<br>
``schedule = 0 15 * * 0-6 ``<br>
``sourcetype = windows:certstore:local ``<br>
``index = win_certstore_data ``<br>

The example input above will collect certificate information from the local certificate store. The default is to recurse through all containers.




##Reference Material

Enabling PowerShell Execution Policy<br>
[about-execution-policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6)<br>
[set-executionpolicy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-6)

Also, for those who may be new to PowerShell
[getting-started-with-windows-powershell](https://docs.microsoft.com/en-us/powershell/scripting/getting-started/getting-started-with-windows-powershell?view=powershell-6)



##Change History
<table>
<tr><td>Version</td><td>Changes</td></tr>

<tr><td>0.1.0</td>
<td>Initial Release
</td></tr>

</table>


