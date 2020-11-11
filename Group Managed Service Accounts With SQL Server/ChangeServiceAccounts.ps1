
function fnGrantSQLStartupAccountsRights ($Local:SQLStartupAccount)
{
$ntrights="\\w12r2hv\SQLSetup\Scripts\CommonScripts\bin\ntrights.exe"  
$NetUser ="\\w12r2hv\SQLSetup\Scripts\CommonScripts\bin\NetUser.exe"  

Write-Host  `n
		try
	{
		$SeBatchLogonRight = $ntrights + " +r SeBatchLogonRight -u `"$Local:SQLStartupAccount`"" 
		invoke-expression $SeBatchLogonRight
		$SeLockMemoryPrivilege = $ntrights + " +r SeLockMemoryPrivilege -u `"$Local:SQLStartupAccount`""  
		invoke-expression $SeLockMemoryPrivilege
		$SeServiceLogonRight = $ntrights + " +r SeServiceLogonRight -u `"$Local:SQLStartupAccount`"" 
		invoke-expression $SeServiceLogonRight
		$MadeLocalAdministrator = "net localgroup administrators /add `"$Local:SQLStartupAccount`"" 
		$resultAdminExists=invoke-expression "net localgroup administrators"
		if (!($resultAdminExists -like $Local:SQLStartupAccount))
		{
			    invoke-expression $MadeLocalAdministrator 
		}
	}
	catch
	{
		$global:flgError=1
        $errorMsg=$_.exception.message
        if ($errorMsg -match "already a member of the group")
        {
        "already a member thus ignoring error" | write-PHLog -echo -Logtype Debug
        }
        else 
        {
        $errorMsg=$_.exception.message
        Write-Warning $errorMsg
		Write-ERROR "Error! while granting rights to sqlstartup account: $($Local:SQLStartupAccount) `n$errorMsg"
        }
	}

Write-Host  `n

}


<#
USE [master]
GO
CREATE LOGIN [SQLFEATURES\TestMSA8$] FROM WINDOWS WITH DEFAULT_DATABASE=[master]
GO
ALTER SERVER ROLE [sysadmin] ADD MEMBER [SQLFEATURES\TestMSA8$]
GO

#>



$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher")
$ADServiceAccount="W12R2S16S9"
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"
$DBSERVER  = gc env:computername

fnGrantSQLStartupAccountsRights  $SQLStartupAccount

Test-AdServiceAccount $ADServiceAccount

foreach ($servicename in $servicenames)
{
    $ServiceNameFmt="Name='$servicename'"
    $service=(Get-WmiObject win32_service -Filter $ServiceNameFmt -ComputerName $DBSERVER)

    if($service)
    {
                    "Setting login $SQLStartupAccount for service $Service " | write-host -ForegroundColor Green
                    $StopStatus = $service.StopService() 
                    If ($StopStatus.ReturnValue -eq "0") 
                    {"$DBSERVER -> Service Stopped Successfully" | write-Host} 
                    $ChangeStatus = $service.change($null,$null,$null,$null,$null,$null,$SQLStartupAccount,$null,$null,$null,$null) 
                    If ($ChangeStatus.ReturnValue -eq "0")  
                        {"$DBSERVER -> Sucessfully Changed User Name"  | write-Host} 
                    else
                        {"$DBSERVER -> Changed User Name failed" | write-Host} 
                    $StartStatus = $service.StartService() 
                    If ($ChangeStatus.ReturnValue -eq "0")  
                        {"$DBSERVER -> Service Started Successfully" | write-Host} 
                    else
                        {"$DBSERVER -> Service did not started Successfully" | write-Host} 
    }
}




exit 

# To install the AD module on Windows Server, run Install-WindowsFeature RSAT-AD-PowerShell
# To install the AD module on Windows 10 version 1809 or later, run Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
# To install the AD module on older versions of Windows 10, see https://aka.ms/rsat

# or below
Get-WindowsFeature AD-Domain-Services

Install-WindowsFeature AD-Domain-Services

Install-WindowsFeature RSAT-AD-PowerShell

# RESTART-COMOPUTER
Get-Module -ListAvailable *Active*
import-module activedirectory

$ADServiceAccount="TestMSA8"

Install-AdServiceAccount $ADServiceAccount

Test-AdServiceAccount $ADServiceAccount


