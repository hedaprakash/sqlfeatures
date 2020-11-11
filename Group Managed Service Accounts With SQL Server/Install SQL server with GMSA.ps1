#region DomainController
exit
# Connect to domain controller
$vmname="vW19ad"
[string] $Adminaccount="sqlfeatures\hvadmin"
[string] $AdminPassword="tttttt1!"
$secretAdminpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Adminaccount, $secretAdminpassword
get-pssession| remove-pssession 
#$session = New-PSSession -cn $vmname -Credential $credential #-Authentication Credssp
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

Get-KdsRootKey
# Add-KdsRootKey -EffectiveImmediately
# Remove KdsRootKey RDP to AD server
# dssite.msc
# View >> Show Service Nodes
Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
Get-KdsRootKey
# now wait for 10 hours

$ADGroupNameDesc="SQL CL02 Authorized Hosts"
$ADGroupName="SQLCL02Hosts"
$ADServiceAccount="vW19cl02"
$DNSHostName= $ADServiceAccount + ".sqlfeatures.local"
$ADGroupMembers =@("vW19db1$","vW19db2$","vW19db3$")

New-ADGroup -Name $ADGroupNameDesc -SamAccountName $ADGroupName  -GroupScope Global
Get-ADGroup $ADGroupName

Add-ADGroupMember -Identity $ADGroupName -Members $ADGroupMembers 
Get-ADGroupMember -Identity $ADGroupName 

New-ADServiceAccount -Name $ADServiceAccount -Path "CN = Managed Service Accounts, DC=sqlfeatures, DC=local" -DNSHostName $DNSHostName -PrincipalsAllowedToRetrieveManagedPassword $ADGroupName   -ManagedPasswordIntervalInDays 1
Get-ADServiceAccount -Identity $ADServiceAccount  -Properties * | FL DNSHostName,KerberosEncryptionType,SamAccountName,PrincipalsAllowedToRetrieveManagedPassword,ManagedPasswordIntervalInDays,PasswordLastSet

dsacls (Get-ADServiceAccount -Identity $ADServiceAccount).DistinguishedName /G "SELF:RPWP;servicePrincipalName" 

# remove AD account
# Get-ADServiceAccount -Identity $ADServiceAccount  | Remove-ADServiceAccount -Confirm:$false

#endregion DomainController

#region DB1withGMSA
exit
# Step 2 Install SQL server with GMSA
$vmname="vW19db1"
[string] $Adminaccount="sqlfeatures\hvadmin"
[string] $AdminPassword="tttttt1!"
$secretAdminpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Adminaccount, $secretAdminpassword
get-pssession| remove-pssession 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

# Optional steps
Install-WindowsFeature RSAT-AD-PowerShell
restart-computer -force 

# Reconnect to VM after reboot 
Enter-PSSession -vmName $vmname -Credential $credential 

# different service names could use GSMA accounts
$ADServiceAccount="vW19cl02"
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"
Test-ADServiceAccount -Identity $ADServiceAccount | Format-List
Install-ADServiceAccount –identity  $ADServiceAccount
# Get-ADServiceAccount –identity $ADServiceAccount
# Remove-ADServiceAccount –identity $ADServiceAccount

# function to grant rights to sql startup account
function fnGrantSQLStartupAccountsRights ($Local:SQLStartupAccount)
{
# https://ss64.com/nt/ntrights.html
$ntrights="D:\SQLBinaries\SQLTools\Bin\ntrights.exe"  

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

fnGrantSQLStartupAccountsRights  $SQLStartupAccount


# Install SQL server 2019 with CU8 using GMSA account
D:\SQLBinaries\SQL2019\ENT\Setup.exe  /SECURITYMODE=SQL /FILESTREAMLEVEL=3 /FILESTREAMSHARENAME=AdvCloudFS   /QUIET=True /ACTION=install   /INSTANCENAME=MSSQLSERVER `
/INDICATEPROGRESS=True  /SQLSVCACCOUNT=$SQLStartupAccount /SQLSVCACCOUNT=$SQLStartupAccount /AGTSVCACCOUNT=$SQLStartupAccount /ISSVCACCOUNT=$SQLStartupAccount /FTSVCACCOUNT=$SQLStartupAccount `
/AGTSVCSTARTUPTYPE=Automatic   /UPDATESOURCE= D:\SQLBinaries\SQL2019\SPs\CU8  /UpdateEnabled=True   /IACCEPTSQLSERVERLICENSETERMS  /SQLSYSADMINACCOUNTS="sqlfeatures\hvadmin" `
/INSTANCEDIR="C:\SQLData" /SQLBACKUPDIR="C:\SQLBackup" /SQLUSERDBLOGDIR="C:\SQLLogs" /SQLTEMPDBLOGDIR="C:\MSSQL\SQLTempDBLog" /SQLUSERDBDIR="C:\SQLData" /SQLTEMPDBDIR="C:\MSSQL\SQLTempDBData" `
/FEATURES="SQLENGINE,REPLICATION,FULLTEXT,DQ,DQC,CONN,IS,BC,SDK,SNAC_SDK,MDS"  /SAPWD="qqqqqq1!"

# cls; cat "C:\Program Files\Microsoft SQL Server\150\Setup Bootstrap\Log\summary.txt"


# Validate Service accounts
$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher","ClusSvc")
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize
# $servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'"  -ComputerName "vW19db1","vW19db2","vW19db3" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize



Install-Package NuGet -Force
Install-Module -Name SqlServer -Force
$qGetSQLServiceStartUpAccount="SELECT @@Servername AS server,servicename,startup_type_desc, service_account,status_desc FROM sys.dm_server_services WHERE status_desc='Running'"
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount

Add-WindowsFeature -Name Failover-Clustering –IncludeManagementTools
Restart-Computer  -force 


#endregion DB1withGMSA

#region DB2withGMSA
exit
$vmname="vW19db2"
[string] $Adminaccount="sqlfeatures\hvadmin"
[string] $AdminPassword="tttttt1!"
$secretAdminpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Adminaccount, $secretAdminpassword
get-pssession| remove-pssession 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

# Optional steps
Install-WindowsFeature RSAT-AD-PowerShell
restart-computer -force 

# Reconnect to VM after reboot 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

# different service names could use GSMA accounts
$ADServiceAccount="vW19cl02"
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"
Test-ADServiceAccount -Identity $ADServiceAccount | Format-List
Install-ADServiceAccount –identity  $ADServiceAccount
# Remove-ADServiceAccount –identity $ADServiceAccount

# function to grant rights to sql startup account
function fnGrantSQLStartupAccountsRights ($Local:SQLStartupAccount)
{
# https://ss64.com/nt/ntrights.html
$ntrights="D:\SQLBinaries\SQLTools\Bin\ntrights.exe"  

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

# different service names could use GSMA accounts
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"

fnGrantSQLStartupAccountsRights  $SQLStartupAccount


# Install SQL server 2019 with GMSA
D:\SQLBinaries\SQL2019\ENT\Setup.exe  /SECURITYMODE=SQL /FILESTREAMLEVEL=3 /FILESTREAMSHARENAME=AdvCloudFS   /QUIET=True /ACTION=install   /INSTANCENAME=MSSQLSERVER `
/INDICATEPROGRESS=True  /SQLSVCACCOUNT=$SQLStartupAccount /SQLSVCACCOUNT=$SQLStartupAccount /AGTSVCACCOUNT=$SQLStartupAccount /ISSVCACCOUNT=$SQLStartupAccount /FTSVCACCOUNT=$SQLStartupAccount `
/AGTSVCSTARTUPTYPE=Automatic   /UPDATESOURCE= D:\SQLBinaries\SQL2019\SPs\CU8  /UpdateEnabled=True   /IACCEPTSQLSERVERLICENSETERMS  /SQLSYSADMINACCOUNTS="sqlfeatures\hvadmin" `
/INSTANCEDIR="C:\SQLData" /SQLBACKUPDIR="C:\SQLBackup" /SQLUSERDBLOGDIR="C:\SQLLogs" /SQLTEMPDBLOGDIR="C:\MSSQL\SQLTempDBLog" /SQLUSERDBDIR="C:\SQLData" /SQLTEMPDBDIR="C:\MSSQL\SQLTempDBData" `
/FEATURES="SQLENGINE,REPLICATION,FULLTEXT,DQ,DQC,CONN,IS,BC,SDK,SNAC_SDK,MDS"  /SAPWD="qqqqqq1!"

# Validate Service accounts
$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher","ClusSvc")
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize
# $servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'"  -ComputerName "vW19db1","vW19db2","vW19db3" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize



Install-Package NuGet -Force
Install-Module -Name SqlServer -Force
$qGetSQLServiceStartUpAccount="SELECT @@Servername AS server,servicename,startup_type_desc, service_account,status_desc FROM sys.dm_server_services WHERE status_desc='Running'"
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount


Add-WindowsFeature -Name Failover-Clustering –IncludeManagementTools
Restart-Computer  -force 

#endregion DB2withGMSA

#region DB3withNormalDomainAccount
exit
$vmname="vW19db3"
[string] $Adminaccount="sqlfeatures\hvadmin"
[string] $AdminPassword="tttttt1!"
$secretAdminpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Adminaccount, $secretAdminpassword
get-pssession| remove-pssession 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

# Optional steps
Install-WindowsFeature RSAT-AD-PowerShell
restart-computer -force 


# Reconnect to VM after reboot 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

# different service names could use GSMA accounts
$ADServiceAccount="vW19cl02"
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"
Test-ADServiceAccount -Identity $ADServiceAccount | Format-List
Install-ADServiceAccount –identity  $ADServiceAccount
# Remove-ADServiceAccount –identity $ADServiceAccount


# function to grant rights to sql startup account
function fnGrantSQLStartupAccountsRights ($Local:SQLStartupAccount)
{
# https://ss64.com/nt/ntrights.html
$ntrights="D:\SQLBinaries\SQLTools\Bin\ntrights.exe"  

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


fnGrantSQLStartupAccountsRights  $SQLStartupAccount


# Install SQL server 2019 with CU8 using domain account
D:\SQLBinaries\SQL2019\ENT\Setup.exe  /SECURITYMODE=SQL /FILESTREAMLEVEL=3 /FILESTREAMSHARENAME=AdvCloudFS   /QUIET=True /ACTION=install   `
/INSTANCENAME=MSSQLSERVER /INDICATEPROGRESS=True  /SQLSVCACCOUNT="sqlfeatures\hvadmin" /SQLSVCACCOUNT="sqlfeatures\hvadmin" /AGTSVCACCOUNT="sqlfeatures\hvadmin" `
/ISSVCACCOUNT="sqlfeatures\hvadmin" /FTSVCACCOUNT="sqlfeatures\hvadmin" /AGTSVCSTARTUPTYPE=Automatic   `
/UPDATESOURCE= D:\SQLBinaries\SQL2019\SPs\CU8  /UpdateEnabled=True   /IACCEPTSQLSERVERLICENSETERMS  /SQLSYSADMINACCOUNTS="sqlfeatures\hvadmin" `
/INSTANCEDIR="C:\SQLData" /SQLBACKUPDIR="C:\SQLBackup" /SQLUSERDBLOGDIR="C:\SQLLogs" /SQLTEMPDBLOGDIR="C:\MSSQL\SQLTempDBLog" `
/SQLUSERDBDIR="C:\SQLData" /SQLTEMPDBDIR="C:\MSSQL\SQLTempDBData" /FEATURES="SQLENGINE,REPLICATION,FULLTEXT,DQ,DQC,CONN,IS,BC,SDK,SNAC_SDK,MDS" `
/SQLSVCPASSWORD="tttttt1!" /AGTSVCPASSWORD="tttttt1!" /ISSVCPASSWORD="tttttt1!" /FTSVCPASSWORD="tttttt1!" /SAPWD="tttttt1!"

Install-Package NuGet -Force
Install-Module -Name SqlServer -Force
$qGetSQLServiceStartUpAccount="SELECT @@Servername AS server,servicename,startup_type_desc, service_account,status_desc FROM sys.dm_server_services WHERE status_desc='Running'"
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount


# Validate Service accounts
$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher","ClusSvc")
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize
#$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'"  -ComputerName "vW19db1","vW19db2","vW19db3" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize



# Update Services to use GMSA account
foreach ($servicename in $servicenames)
{
    $ServiceNameFmt="Name='$servicename'"
    $service=(Get-WmiObject win32_service -Filter $ServiceNameFmt )

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

# Validate Service accounts
$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher","ClusSvc")
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize
# $servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'"  -ComputerName "vW19db1","vW19db2","vW19db3" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize

Add-WindowsFeature -Name Failover-Clustering –IncludeManagementTools
Restart-Computer  -force 


# Access shared locations
# Create a backup share on a network file server and take backups there
# \\VW19APP\sqlbackups
# Validate backups are getting created to this folder

#endregion DB3withNormalDomainAccount


exit

# ALTER AUTHORIZATION ON ENDPOINT::mirroring_endpoint TO [MyDemoSQL\gMSsqlservice$];

# Access shared locations
# Create a backup share on a network file server and take backups there
# \\VW19APP\sqlbackups
# Validate backups are getting created to this folder
