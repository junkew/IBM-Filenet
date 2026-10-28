#This script can be run on its own but will be useless as it needs some configuration
set-location $psscriptroot
$scriptRoot=(get-location).path
write-host "Loading FileNetApi.PS1 from $scriptRoot"

#region All kinds of loading libraries etc
#Load the forms assembly
Add-Type -AssemblyName System.Windows.Forms | Out-Null

$TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12 , Tls13' 
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

#Trust all certificates
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
#endregion

#https://www.ibm.com/docs/en/filenet-p8-platform/5.5.x?topic=started-getting-procedures
#$MTOM="https://192.168.134.186:443/wsi/FNCEWS40MTOM/"

#$FNP8_EnvironmentMTOMURIs =@{
#    DEV = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
#    TST = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
#    ACC = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
#    PRD = "https://{server}:{port}/wsi/FNCEWS40MTOM/" 
#}

#$MTOM=$FNP8_EnvironmentMTOMURIs["DEV"]
$FileNetApiDllName=$scriptroot + "\FileNet.Api.dll"
write-host "Using $FileNetApiDllName"

#region credentials
# reset with 
# remove-item "${env:homedrive}${env:HOMEPATH}\FNP8Cred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
function get-FNP8Credential() {
    #https://ss64.com/ps/convertto-securestring.html
    #$FNP8_username=read-host -prompt "your username: "
    #$FNP8_passWordSec=read-host -prompt "your password: " -AsSecureString 
    $FNP8_CredentialFile = "${env:homedrive}${env:HOMEPATH}\FNP8Cred_${env:USERNAME}_${env:COMPUTERNAME}.xml"
    if (test-path $FNP8_CredentialFile) {
        write-host 'Using credentials from file: ' $fnp8_Credentialfile
        write-host "Reset userid / password: remove-item $fnp8_Credentialfile"
        $FNP8_Credential = Import-CliXml -Path $FNP8_CredentialFile
    } else {
        $FNP8_Credential = Get-Credential
        $FNP8_Credential | Export-CliXml -Path $FNP8_CredentialFile
    } 
    #To get password back as plaintext
    #[System.Net.NetworkCredential]::new("", $FNP8_Credential.Password).Password
    return $FNP8_Credential
}
$FNP8_Credential=get-FNP8Credential
#endregion credentials

#region stringvariables
#script variable for nice names to have allways some readable information for those objects with only GUID
$scriptBlockNiceName={
    $tmpNiceName=$null
    if ($tmpNiceName -eq $null) {$tmpNiceName=$this.name}
    if ($tmpNiceName -eq $null) {$tmpNiceName=$this.displayname}
    if ($tmpNiceName -eq $null) {$tmpNiceName=$this.descriptivetext}
    if ($tmpNiceName -eq $null) {$tmpNiceName=$this.documenttitle}
    if ($tmpNiceName -eq $null) {
        if ($this.containers.count -ne 0) {
            $tmpNiceName=$this.containers[0].containmentname
        }
    }
    if ($tmpNiceName -eq $this.id)  {
        if ($this.containers.count -ne 0) {
            $tmpNiceName=$this.containers[0].containmentname
        }
    }
    if ($tmpNiceName -eq $this.id)  {
        if ($this.containers.count -ne 0) { $tmpNiceName=$this.containers[0].containmentname}
        else {
            if ($this.annotatedobject -ne $null) { $tmpNiceName=$this.annotatedobject.name }
        }                      
    }
 
    if ($tmpNiceName -eq $null) {$tmpNiceName="*** No NICE NAME ***"}
    $tmpNiceName
}

$typeData=get-typedata FileNet.Apiimpl.Core.ClassDescriptionImpl
if ($typeData.members.count -eq 0) {
    Update-TypeData -TypeName FileNet.Apiimpl.Core.ClassDescriptionImpl -MemberType ScriptProperty -MemberName "NiceName" -Value $scriptBlockNiceName | out-null
}

#endregion
#$FNP8_username=$env:username
#$FNP8_passWordSec=convertto-securestring "P@ssW0rD!" -asplaintext -force
#$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($FNP8_passWordSec)
#$passWord = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
#$FileNetApiCredentials = new-object -type System.Management.Automation.PSCredential -argumentlist $tmpUser, $password
#$FileNetApiCredentials = new-object -type System.Management.Automation.PSCredential -argumentlist $fnp8_credential.UserName, $fnp8_credential.password
function get-FNETApiDLL {
    if (-not (test-path $FileNetApiDllName)) {
        write-host "*** Installing FileNet.Api.Dll ***"
      #$FNetApiServer="https://:9443"

      $FNetApiLink="$FNetApiServer/clientDownload?command=download&filePath=/FileNet/Download/dap551.000.002.083/FileNet.Api.dll"
       $tCred=get-FNP8Credentials
       Invoke-WebRequest -o -Uri $FNetApiLink -OutFile 'FileNet.Api.dll' -UseBasicParsing -Credential $tCred
    }
    if (-not (test-path $FileNetApiDllName)) {
      write-error "FileNet.Api.Dll not installed in same folder as this script"
    }
}
get-FNETApiDll

$Using = (
    "FileNet.Api.Authentication",
    "FileNet.Api.Core",
    "FileNet.Api.Util",
    "FileNet.Api.Constants",
    "FileNet.Api.Admin"
)

try 
{
#$asmFileNet=Add-Type -Path $FileNetApiDllName -ReferencedAssemblies $Using
    $asmFileNet=[System.Reflection.Assembly]::LoadFrom($FileNetApiDllName)
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

#Create a new filenet user credentials object which is used in FNP8 clientcontext
function new-UsernameCredentials($FNP8_username, $passWord){
    return new-object FileNet.Api.Authentication.UserNameCredentials($FNP8_username, $passWord)
}

function get-Connection($uri){
    #$c=new-object filenet.api.util.ConfigurationParameters
    #$c.setparameter([FileNet.Api.Constants.ConfigurationParameter]::WSI_TRANSPORT_PREFER_WCF, $true)
    #TODO: $conn = [FileNet.Api.Core.Factory+Connection]::GetConnection($uri,$c) 
    $conn=[FileNet.Api.Core.Factory+Connection]::GetConnection($uri)
    return $conn
} 
function Authenticate-User($FNP8_username,$plainPassWord){
    $creds=new-UserNameCredentials $FNP8_username $plainPassWord
    $result=[FileNet.Api.Util.ClientContext]::SetProcessCredentials($creds)
}
function get-Domain($conn){
    write-host "connection " $conn
    try {
        [FileNet.Api.Core.IDomain]$domain=[FileNet.Api.Core.Factory+Domain]::FetchInstance($conn,$null,$null)
   } catch {
   Write-Host "INFO: Multiple warnings when loading which can be ignored"
   #Write-Host "It seems to load more then needed"
   #Write-Host "Make sure WSE 3.0 is installed from MSI"
   Write-Host "Message: $($_.Exception.Message)"
   Write-Host "Message: $($_.Exception.ToString())"
   Write-Host "StackTrace: $($_.Exception.StackTrace)"
   Write-Host "LoaderExceptions: $($_.Exception.LoaderExceptions)"
   }
    return $domain
} 

function get-ObjectStore($name){
    foreach($os in $FNP8_domain.ObjectStores)
    {
      if ($os.symbolicname -eq$name) { return $os } 
    }
} 

function set-objectStore($osSymbolicName) {
    write-host "Working with objectstore $osSymbolicName"
    $global:FNP8_OS=get-objectstore $osSymbolicName
}

#region function helpers
function new-sqlObject(){
    try 
    {
        return new-object FileNet.Api.Query.SearchSQL 
    }
    catch {
        write-error "Most likely you have not loaded the API and are not connected to a FNP8 backend."
    }
 
}
function new-searchscope() {
    param(
        [Parameter(Mandatory=$false)]$os
    )
    if ($os -eq $null) { 
        if ($global:FNP8_OS -eq $null) { 
            throw "**** First connect to backend with connectto-env ***"
        }
        $os=$global:FNP8_OS
    }
    
 
    return new-object FileNet.Api.Query.SearchScope($os)
}
function get-objects() {
<#
.SYNOPSIS
 
Get all objects of a certain SearchObject SQL query (transforms based on id with fetchinstance to object)
 
.DESCRIPTION
 
.PARAMETER FNP8Env
 
.INPUTS
 
None. You cannot pipe objects to this function
 
.OUTPUTS
 
url 
 
.EXAMPLE
 
get-objects("Classdefinition") | select-object id,  name, displayname, symbolicname, owner | format-table
get-objects("Classdefinition") | select-object id,  name, displayname, symbolicname, owner | out-gridview
get-objects("Classdefinition") | select-object id,  name, displayname, symbolicname, owner | format-table -AutoSize -wrap 
 
get-objects("cmStorageDevice") | select-object owner, id
get-objects("Choicelist") | select-object owner, id
 
.LINK
 
.LINK
 
#>
                  
 
    param(
        [Parameter(Mandatory=$false)]$SymbolicTableName,
        [Parameter(Mandatory=$false)]$dateTime
    )
    if ($SymbolicTableName -eq $null) { 
    }
 
        #$table='CmStorageDevice'
 
        $table="$SymbolicTableName"
 
        $tmpSqlString="SELECT [this], ID FROM [$table]"
        if ($dateTime -ne $null) {
           $tmpSqlString+= " WHERE DateLastModified>=$dateTime"
        }
 
        $tmpSqlString+= ' OPTIONS(TIMELIMIT 180)'
 
        try
        {
            $sqlObject=new-sqlObject
           # write-host $tmpSqlString
            $sqlObject.SetQueryString($tmpSqlString)
            $searchScope = new-SearchScope
          #  write-host $sqlObject.tostring()
 
            $global:rowSet = $searchScope.FetchRows($sqlObject, $null, $null, $true)
#            $global:psRowset=get-psrowset($global:rowSet) 
 
            
            #$global:psRowset | out-gridview -Title ($key + " edited since "+$dateTime) 
            $tmp=$sqlObject.tostring() -match 'FROM \[(.*?)\]'
            $classSymbolicName = $matches[1]
            #        write-host $sqlObject.tostring()
            # write-host $classSymbolicName
           # write-host "hello"
            foreach($st in $global:Rowset) 
            {            
                $FNP8_OS.FetchObject($classSymbolicName, $st.Properties.GetIdValue("Id"), $null)
            }
        }
        catch
        {
            write-host "TABLE NOT EXISTING: " $tmpSqlString
          #  write-warning "TABLE NOT EXISTING: `r`n" $tmpSqlString
        }
    
}
function get-FNP8ObjectstOfInterest() {
#Document gives to many results
#IndexJob and Event also many
#Then a lot of objects are having 0
#Last line some Cm tables are not existing probably not defined during an install
    $excludeObjects=@("Document", 
                      "IndexJob", "Event",
                      "Link","DocumentLifecycleAction","SecurityPolicy","CmRole","CmHoldRelationship","CmAuditProcessingBookmark","CmRecoveryBin",
                      "CmThumbnail","CmVerityIndexRequest","CmHold","CmRecoveryItem","CmTextSearchIndexRequest","SecurityPropagationQueueItem",
                      "PublishRequest","CmTask","CmTextIndexingPreprocessorAction","CmSweepResult","CmContentConversionAction","AsyncUpgradeQueueItem","CmStorageDevice","CmTaskRelationship",
                      "CmContentConversionSettings","CmAuditDispositionPolicy","ReplicationJournalEntry","CmSweepAction","CmSweepRelationship","EventQueueItem","InstanceSubscription","ComponentRelationship","CmRoleMembershipAction","CmSweepPolicy",
                      "CmAbstractPersistable","CmAbstractSequential","CmAbstractQueueEntry","CmAbstractDependent","CmAbstractSearchResult","VersionSeries")

#So these are mainly of interest based on initial insights
# CmSearchFunctionDefinition 3, IndexArea 1,DocumentLifecyclePolicy 2, CustomObject 22,ClassDefinition 269
# PropertyTemplate 169, ChoiceList 9, DocumentClassificationQueueItem 105,StoragePolicy 1,DocumentClassificationAction 1
# CmSweep 10,Annotation 13,StorageArea 1,EventAction 12,ClassSubscription 11,CmChangePreprocessorAction 1,Folder 152,ReferentialContainmentRelationship 873

    foreach($o in $FNP8_OS.RootClassDefinitions) {
        if (-not $excludeObjects.contains($o.symbolicname)) {
            $listOfObjects=get-objects($o.Symbolicname)
            #write-host $o.symbolicname, $listOfObjects.Count
            $listOfObjects
        }
    }
}

function get-contentAsString($contentElement) {
    try {
        $rs=$contentElement.AccessContentStream()
    } catch {
        $rs=$null
    }

    if ($rs -ne $null) {
        [byte[]]$buff = new-object byte[] $contentElement.ContentSize
        $rs.Read($buff,0,$contentElement.ContentSize) | out-null
    } else 
    {
        # Define the string to convert
        $stringToConvert = "** READING ERROR, rights issue? **"

        # Create an instance of the ASCII encoding
        $asciiEncoding = [System.Text.Encoding]::ASCII

        # Convert the string to a byte array
        $buff = $asciiEncoding.GetBytes($stringToConvert)
    }

    return ([System.Text.Encoding]::UTF8.GetString($buff))
}

#endregion
#function to give some insight per storagearea
function get-objectStorageInfo() {
    $allinfo=@()
    foreach($os in $fnp8_domain.objectstores) {
        $allInfo+= ($os.storageareas | select {$os.symbolicname}, displayname, contentelementcount, contentelementkbytes, contentelementscreated, contentelementsdeleted)
    }

    $allInfo | format-table
}

$templateFuncGetMTOMURIS = @'
function global:get-MTOMURIs() {
    write-host "Returning endpoints"
    $FNP8_EnvironmentMTOMURIs =@{
        DEV = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
        TST = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
        ACC = "https://{server}:{port}/wsi/FNCEWS40MTOM/"
        PRD = "https://{server}:{port}/wsi/FNCEWS40MTOM/" 
    }
    return $FNP8_EnvironmentMTOMURIs
}
'@
function New-FNP8DynamicFunctionsForObjectStore() {
    Foreach ($os in $FNP8_Domain.ObjectStores) {

       # creates a new function dynamically
       $Name = $os.symbolicname
       $Code = { 
            write-host "switching to" $name
            Set-Variable FNP8_OS -Scope global -value (get-objectstore $name)
       }
       $code=$ExecutionContext.InvokeCommand.ExpandString($code)

       # create new function in function: drive and set scope to "script:"
       if ((test-path function:$name) -eq $true) { $null = remove-Item function:$name }
       $null = New-Item -Path function: -Name "script:$Name" -Value $Code
    }
}

function New-FNP8DynamicFunctionsForEnvironments() {
    Foreach ($fnp8env in $FNP8_EnvironmentMTOMURIs.keys) {

       # creates a new function dynamically
       $Name = $fnp8env
       $Code = { 
            write-host "switching to" $name
            new-FNP8Connection $name
       }
       $code=$ExecutionContext.InvokeCommand.ExpandString($code)

       # create new function in function: drive and set scope to "script:"
       if ((test-path function:$name) -eq $true) { $null = remove-Item function:$name }
       $null = New-Item -Path function: -Name "script:$Name" -Value $Code
    }
}

function New-FNP8DynamicFunctions
{
    New-FNP8DynamicFunctionsForObjectStore
    New-FNP8DynamicFunctionsForEnvironments 
}

function new-FNP8Connection($fnp8env) {
   #$uri="https://:9443/wsi/FNCEWS40MTOM/“
    #$FNP8_uri=$FNP8_EnvironmentMTOMURIs["DEV"]
    write-host "Switching environment to $fnp8env"
    $global:fnp8env=$fnp8env

    $FNP8_uri=$FNP8_EnvironmentMTOMURIs[$fnp8env]

    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($fnp8_credential.password)
    $plainPassWord = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    authenticate-user $fnp8_credential.username $plainPassword

    $global:FNP8_Connection=get-Connection $FNP8_uri
    $global:FNP8_Domain=get-Domain $FNP8_Connection
    set-objectstore ($FNP8_Domain.objectstores.GetList()[0].symbolicname)
}

#This will load all the stuff, call from your main script (one time normally)
function initialize-fnp8lib($fnp8env) {
    write-host "initialize-fnp8tool $fnp8env"
    if ((gci function: | where name -eq 'get-MTOMURIs') -eq $null) {
        write-host 'Implement in your main script '
        $templateFuncGetMTOMURIS
        return
    }

    $global:FNP8_EnvironmentMTOMURIs = get-MTOMURIs

    new-FNP8Connection $fnp8Env

 

    #And add a function to switch for each objectstore name
    New-FNP8DynamicFunctions
}




