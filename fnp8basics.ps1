#See main_example() voor de echte code

clear-host

Set-ExecutionPolicy unrestricted -scope currentuser
# SSL uit/trust
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

function main_example() {

    $dllFullFileName="$psscriptroot\FileNet.Api.dll"

    $tmpUser =  "<adminuser>"
    $password = "<adminpassword>" 


    $Using = (
     "FileNet.Api.Authentication",
     "FileNet.Api.Core",
     "FileNet.Api.Util",
     "FileNet.Api.Constants",
     "FileNet.Api.Admin"
    )

    try 
    {
        #$asmFileNet=Add-Type -Path $dllFullFileName -ReferencedAssemblies $Using
        $asmFileNet=[System.Reflection.Assembly]::LoadFrom($dllFullFileName)
    } 
      catch [System.Reflection.ReflectionTypeLoadException]
    {
       Write-Host "INFO: Multiple warnings when loading which can be ignored"
       #Write-Host "It seems to load more then needed"
       #Write-Host "Make sure WSE 3.0 is installed from MSI"
       Write-Host "Message: $($_.Exception.Message)"
       Write-Host "StackTrace: $($_.Exception.StackTrace)"
       Write-Host "LoaderExceptions: $($_.Exception.LoaderExceptions)"
    }  

    $cred=get-FNP8Credentials $tmpUser

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.password)
    $passWord = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    Authenticate-User $cred.UserName $passWord

    #$credentials = new-UsernameCredentials($tmpUser, $password)
    #$credentials = new-object System.Management.Automation.PSCredential($tmpUser, $password)
    
    $uri="https://localhost:9443/wsi/FNCEWS40MTOM/"
    $global:FNP8_Connection=get-Connection $uri
    $global:FNP8_Domain=get-Domain $FNP8_Connection
}

#Create a new filenet user credentials object which is used in FNP8 clientcontext

function new-UsernameCredentials($userName, $passWord){
    return new-object FileNet.Api.Authentication.UserNameCredentials($userName, $passWord)
}

function get-Connection($uri){
    $conn = [FileNet.Api.Core.Factory+Connection]::GetConnection($uri)
    return $conn 
}

function Authenticate-User($userName, $passWord){
    $creds=new-UserNameCredentials $userName $passWord
    $result=[FileNet.Api.Util.ClientContext]::SetProcessCredentials($creds)
}

function get-Domain($conn){
    write-host "connection " $conn
    [FileNet.Api.Core.IDomain] $domain = [FileNet.Api.Core.Factory+Domain]::FetchInstance($conn, $null, $null)
    return $domain
}

function get-FNP8Credentials()
{
param($forUser)
    if (test-path $env:homedrive) {
        $homeDir=$env:homedrive + $env:homepath
        If ($homeDir[-1] -notmatch "\\") { $homeDir+="\\" } 

        $tmpUser=$forUser
        if ($tmpUser -eq $null) { $tmpUser=$env:username}
        
        $pwdFNP8File=$homeDir + "FNP8" + $tmpUser + "DefaultPWD.sec"

        write-host "Credentials in " $pwdFNP8File
        write-host "*** Delete that file for resetting password or when you feel its time to clean ***"

        #ask it at least every 2 hours

        if (test-path $pwdFNP8File) {
            if (((gci $pwdFNP8File).LastWriteTime | new-timespan).hours -gt 2) {
                write-host "removing"
                remove-item $pwdFNP8File
            }
        }
  

        if (!(Test-Path -path $pwdFNP8File)) {
            write-host "asking again " $pwdFNP8File
            read-host -prompt ("Password for " + $tmpUser) -assecurestring | convertfrom-securestring | out-file $pwdFNP8File
        }

      
        $password = get-content $pwdFNP8File | convertto-securestring
       
        $credentials = new-object System.Management.Automation.PSCredential($tmpUser, $password)
    }
    return $credentials
}

#run the main function
main_example

#query mbv powershell
$FNP8_Domain.ObjectStores | select name, datecreated, datelastmodified, creator, lastmodifier | format-table

#stop de dos objectstore in een variable
$dos=$FNP8_Domain.ObjectStores.where({$_.name -eq "dos"})

#DUMP ALLE PROPERTIES DIE JE VIA ACCE KAN ZIEN OP HET SCHERM (KAN EVEN DUREN)
$dos

