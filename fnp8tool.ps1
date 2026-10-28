Clear-Host
set-location $psscriptroot
#remove-item $env:USERPROFILE\fnp8cred*.xml

$scriptRoot=(get-location).path
write-host "FNP8Tool script root $scriptroot"
#load the helper generic library
. $scriptroot\lib\FileNetApi.ps1

#Below functions will be called from the generic library, you can customize
function global:get-workfolder() {
    (get-item $scriptRoot).Parent.parent.fullname + '\' + $env:username
}

function global:set-workFolder() {
    $workfolder=get-workfolder
    if (!(test-path $workfolder)) {new-item -ItemType directory -path $workfolder}
    set-location $workfolder
}

function global:get-MTOMURIs() {
    write-host "Returning endpoints"
    $FNP8_EnvironmentMTOMURIs = @{
        DEV = "https://10.178.137.19:9443/wsi/FNCEWS40MTOM/"
        TST = "https://10.178.137.19:9443/wsi/FNCEWS40MTOM/"
        TST2 = "https://10.178.137.19:9443/wsi/FNCEWS40MTOM/"
        ACC = "https://10.178.137.19:9443/wsi/FNCEWS40MTOM/"
        PRD = "https://10.178.137.19:9443/wsi/FNCEWS40MTOM/" 
    }
    return $FNP8_EnvironmentMTOMURIs
}
#This is specific depending on the host you are connecting, the citrix jump server is either O, T, A, P
#should return the key into your MTOM uri's hashtable
function get-contextEnvironment() {
    if (Test-Path variable:global:fnp8env) {return $global:fnp8env}
    return "TST"
    #$tEnv=[System.NET.DNS]::GetHostByName($null).hostname.split('.')[1]
    #
    #if ($tEnv -eq 'O-DC') { return 'DEV'}
    #if ($tEnv -eq 'T-DC') { return 'TST'}
    #if ($tEnv -eq 'A-DC') { return 'ACC'}
    #if ($tEnv -eq 'P-DC') { return 'PRD'}
    ##default
    #return 'DEV'
}
 
#And now call the main routine to load the generic library

initialize-fnp8lib (get-contextEnvironment) 
#And go to your workfolder
set-workfolder
