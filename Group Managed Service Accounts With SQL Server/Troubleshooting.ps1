exit

$vmname="vW19db1"
[string] $Adminaccount="sqlfeatures\hvadmin"
[string] $AdminPassword="tttttt1!"
$secretAdminpassword = ConvertTo-SecureString $AdminPassword -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist $Adminaccount, $secretAdminpassword
get-pssession| remove-pssession 
Enter-PSSession -vmName $vmname -Credential $credential #-Authentication Credssp

$ADServiceAccount="vW19cl02"
Test-ADServiceAccount -Identity $ADServiceAccount | Format-List
Install-ADServiceAccount –identity  $ADServiceAccount
restart-computer -force 


# different service names could use GSMA accounts
$ADServiceAccount="vW19cl02"
$SQLStartupAccount = "SQLFEATURES\$($ADServiceAccount)$"


$qGetSQLServiceStartUpAccount="SELECT @@Servername AS server,servicename,startup_type_desc, service_account,status_desc FROM sys.dm_server_services WHERE status_desc='Running'"
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount -ServerInstance 'vW19db1' | ft -AutoSize
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount -ServerInstance 'vW19db2' | ft -AutoSize
Invoke-Sqlcmd -Query $qGetSQLServiceStartUpAccount -ServerInstance 'vW19db3' | ft -AutoSize

# Validate Service accounts
$servicenames=@("MSSQLSERVER","SQLSERVERAGENT","SQLServerReportingServices","MsDtsServer130","MsDtsServer140","MsDtsServer150","ReportServer","MSSQLFDLauncher","ClusSvc")
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize
$servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'"  -ComputerName "vW19db1","vW19db2","vW19db3" | select PSComputerName, name, startmode, State,startname} | ft -AutoSize

# $servicenames| foreach {Get-WmiObject -Class win32_service -Filter "Name='$_'" | restart-service -force }

# Get-WmiObject -Class win32_service -Filter "Name='clussvc'"  -ComputerName "vW19db1","vW19db2","vW19db3" | gm 

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

restart-computer -force 
