. $psscriptroot\..\FNP8Tool.ps1
$scriptWorkfolder=get-workfolder

write-host 'Type in het blauwe gedeelte'
write-host '  get-permissions ($ooi | sort classname)<enter>'


function get-permissions($allObjects) {

   foreach ($o in $allObjects) {
        foreach($p in $o.permissions) {
            [pscustomobject]@{ className=$o.getClassName();
                                 name             = $o.name;
                                 symbolicname     = $o.symbolicname;
                                 accessmask       = $p.accessmask;
                                 accesstype       = $p.accesstype;
                                 granteename      = $p.granteename;
                                 granteetype      = $p.granteetype;
                                 permissionsource = $p.permissionsource;
                                 inheritabledepth = $p.inheritabledepth
                                 }
        }
             #   $t.permissions  | select accessmask, accesstype, granteename, granteetype, permissionsource, inheritabledepth | format-table
            
   }
}

$ooi=get-FNP8ObjectstOfInterest
#$ooi | convertto-csv -NoTypeInformation | out-file permissions.csv -encoding utf8

