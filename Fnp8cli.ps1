# ====================================================================
# SCRIPT: FNP8_PowerTool_Master.ps1
# STATUS: Geconsolideerd - Inclusief CPE Router, Closures & Parsing
# ====================================================================

#region 1. Bootstrapping & Configuration
function Get-FNP8ScriptDirectory {
    if (-not [string]::IsNullOrEmpty($PSScriptRoot)) { return $PSScriptRoot }
    if (Test-Path (Join-Path $PWD.Path "fnp8_config.json")) { return $PWD.Path }
    $docsPath = [Environment]::GetFolderPath("MyDocuments")
    $fallbackPath = Join-Path $docsPath "FNP8Tool2"
    if (Test-Path (Join-Path $fallbackPath "fnp8_config.json")) {
        Write-Host "[INFO] Onopgeslagen script gedetecteerd. Werkmap automatisch ingesteld op: $fallbackPath" -ForegroundColor DarkGray
        return $fallbackPath
    }
    return $PWD.Path
}

function Get-FNP8Configuration {
    param([string]$ConfigFile = "fnp8_config.json")
    
    $scriptDir = Get-FNP8ScriptDirectory
    $fullPath = Join-Path -Path $scriptDir -ChildPath $ConfigFile

    try {
        if (Test-Path $fullPath) {
            $rawConfig = Get-Content $fullPath -Raw | ConvertFrom-Json
            $global:FNP8Config = $rawConfig
            
            # --- DE JSON _DEFAULT_ FIX ---
            if ($rawConfig._DEFAULT_) {
                $envName = $rawConfig._DEFAULT_
                Write-Host "  -> Default environment gedetecteerd: $envName" -ForegroundColor DarkGray
                
                # Als het environment blok (bijv "DEV") bestaat, kopieer de instellingen naar de root
                if ($null -ne $rawConfig.$envName) {
                    foreach ($prop in $rawConfig.$envName.psobject.properties) {
                        $global:FNP8Config | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value -Force
                    }
                }
            }
            Write-Host "[OK] Configuratie geladen uit $fullPath" -ForegroundColor Green
        } else {
            Write-Warning "Configuratiebestand niet gevonden op: $fullPath"
        }
    } catch { Write-Warning "Fout bij inlezen JSON configuratie: $($_.Exception.Message)" }
}

function Get-FNP8Credentials {
    param( [string]$UserEnv = "FN_USER", [string]$PassEnv = "FN_PASS", [string]$UriEnv  = "FN_URI" )
    
    $user = [Environment]::GetEnvironmentVariable($UserEnv, "User")
    if (-not $user) { $user = [Environment]::GetEnvironmentVariable($UserEnv, "Process") }
    
    $pass = [Environment]::GetEnvironmentVariable($PassEnv, "User")
    if (-not $pass) { $pass = [Environment]::GetEnvironmentVariable($PassEnv, "Process") }
    
    $uri = [Environment]::GetEnvironmentVariable($UriEnv, "User")
    if (-not $uri) { $uri = [Environment]::GetEnvironmentVariable($UriEnv, "Process") }
    
    if (-not $user -or -not $pass) { Write-Warning "Credentials niet gevonden in Windows Environment."; return $null }
    
    if ($uri) {
        if (-not $global:FNP8Config) { $global:FNP8Config = [PSCustomObject]@{} }
        $global:FNP8Config | Add-Member -MemberType NoteProperty -Name "ConnectionUrl" -Value $uri -Force
    }
    return @{ Username = $user; Password = $pass }
}

function Import-FNP8Library {
    param([string]$DllName = "FileNet.Api.dll")
    $scriptDir = Get-FNP8ScriptDirectory
    $path = if ($global:FNP8Config -and $global:FNP8Config.DllPath) { $global:FNP8Config.DllPath } else { Join-Path -Path $scriptDir -ChildPath $DllName }

    try {
        if (-not (Test-Path $path)) { throw "Bestand niet gevonden op $path" }
        Unblock-File -Path $path -ErrorAction SilentlyContinue
        
        $isLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.ManifestModule.Name -eq $DllName }
        if ($isLoaded) { Write-Host "  OK: FileNet API DLL is al actief in deze sessie." -ForegroundColor DarkGray } 
        else {
            [System.Reflection.Assembly]::LoadFrom($path) | Out-Null
            Write-Host "  OK: FileNet API DLL geladen via Reflectie ($path)" -ForegroundColor Green
        }
    } catch {
        Write-Warning "CRITISCHE FOUT: Kan de FileNet.Api.dll niet laden. Script stopt."
        throw $_
    }
}
#endregion

#region 2. Core Initialisation & Extensions
function Initialize-FNP8Core {
    Write-Host "Initialiseren van FileNet Core & Type Extensions..." -ForegroundColor DarkGray
    
    # 1. De logica om de "Beste" naam van een object te bepalen
    $niceNameScript = {
        if ($null -ne $this.psobject.Properties['DocumentTitle'] -and $this.DocumentTitle) { return $this.DocumentTitle }
        if ($null -ne $this.psobject.Properties['Name'] -and $this.Name) { return $this.Name }
        if ($null -ne $this.psobject.Properties['FolderName'] -and $this.FolderName) { return $this.FolderName }
        if ($null -ne $this.psobject.Properties['DisplayName'] -and $this.DisplayName) { return $this.DisplayName }
        if ($null -ne $this.psobject.Properties['AddOnName'] -and $this.AddOnName) { return $this.AddOnName }
        if ($null -ne $this.psobject.Properties['SymbolicName'] -and $this.SymbolicName) { return $this.SymbolicName }
        return "<Geen Naam>"
    }

    # 2. De lijst met native classes én onze eigen virtuele tags
    $targetTypes = @(
        "FileNet.Api.Core.IIndependentlyPersistableObject",
        "FileNet.Api.Core.IRepositoryObject",
        "FileNet.Api.Core.Document",
        "FileNet.Api.Core.CustomObject",
        "FNP8.Type.Default",
        "FNP8.Type.AO",
        "FNP8.Type.ClassDef",
        "FNP8.Type.Folder",
        "FNP8.Type.PT"
    )

    # 3. Koppel de ScriptProperty aan alle types
    foreach ($type in $targetTypes) {
        try {
            Update-TypeData -TypeName $type -MemberType ScriptProperty -MemberName "NiceName" -Value $niceNameScript -Force -ErrorAction Stop
        } catch {}
    }
}
#endregion

#region 3. Connection & Dynamic Context
function Connect-FNP8Environment {
    param([string]$ConnectionUri)
    
    $creds = Get-FNP8Credentials
    if (-not $creds) { throw "Kan niet verbinden zonder credentials." }
    
    $uri = if ($ConnectionUri) { $ConnectionUri } elseif ($global:FNP8Config) { $global:FNP8Config.ConnectionUrl } else { $null }
    if (-not $uri) { throw "Geen Connection URL gevonden." }

    Write-Host "`nVerbinden met FileNet P8 via: $uri" -ForegroundColor Cyan
    
    try {
        $conn = [FileNet.Api.Core.Factory+Connection]::GetConnection($uri)
        $fnp8Creds = New-Object FileNet.Api.Authentication.UsernameCredentials($creds.Username, $creds.Password)
        [void][FileNet.Api.Util.ClientContext]::SetProcessCredentials($fnp8Creds)
        
        $global:fnp8domain = [FileNet.Api.Core.Factory+Domain]::FetchInstance($conn, $null, $null)
        Write-Host "Succesvol verbonden met domein: $($global:fnp8domain.Name)" -ForegroundColor Green
        
        Invoke-FNP8DynamicDiscovery
    } catch { Write-Error "Connectie mislukt: $($_.Exception.Message)" }
}

function Set-FNP8ObjectStoreContext {
    param([Parameter(Mandatory=$true)][string]$ObjectStoreSymbolicName)
    try {
        $global:FNP8OS = [FileNet.Api.Core.Factory+ObjectStore]::FetchInstance($global:fnp8domain, $ObjectStoreSymbolicName, $null)
        Write-Host "`n[CONTEXT] Actieve ObjectStore is nu: $($global:FNP8OS.DisplayName)" -ForegroundColor Green
        Set-CPEDefaultView -Quiet
    } catch { Write-Warning "Kon niet verbinden met ObjectStore: $ObjectStoreSymbolicName" }
}

function Invoke-FNP8DynamicDiscovery {
    if (-not $global:fnp8domain) { return }
    Write-Host "Genereren van dynamische navigatie-commando's (Closures)..." -ForegroundColor DarkGray
    
    foreach ($os in $global:fnp8domain.ObjectStores) {
        $osSymbolic = $os.SymbolicName
        $cleanName = $osSymbolic -replace '\s', ''

        $scriptBlock = {
            Set-FNP8ObjectStoreContext -ObjectStoreSymbolicName $osSymbolic
        }.GetNewClosure()

        $functionPath = "function:global:$cleanName"
        New-Item -Path $functionPath -Value $scriptBlock -Force | Out-Null
        Write-Host "  -> Shorthand klaar: $cleanName" -ForegroundColor DarkGray
    }
}
#endregion

#region 4. Display Management
function Set-FNP8ConsoleWidth {
    param([int]$Width = 2048)
    try { $buffer = $Host.UI.RawUI.BufferSize; $buffer.Width = $Width; $Host.UI.RawUI.BufferSize = $buffer } catch {}
}

function Set-CPEDefaultView {
    param([switch]$Quiet)

    $viewMap = @{
        "FNP8.Type.AO"         = @("AddOnName", "Installer", "InstallationDate", "InstallationStatus")
        "FNP8.Type.ClassDef"   = @("DisplayName", "SymbolicName", "IsHidden", "Id")
        "FNP8.Type.ClassDescr" = @("DisplayName", "SymbolicName", "AllowsInstances", "Id")
        "FNP8.Type.Folder"     = @("FolderName", "PathName", "DateCreated", "Id")
        "FNP8.Type.PT"         = @("DisplayName", "SymbolicName", "DataType", "Id")
        "FNP8.Type.Permission" = @("GranteeName", "AccessType", "AccessMask", "InheritableDepth")
        "FNP8.Type.Default"    = @("NiceName", "Creator", "DateCreated", "Id") 
    }

    foreach ($type in $viewMap.Keys) {
        Update-TypeData -TypeName $type -DefaultDisplayPropertySet $viewMap[$type] -Force -ErrorAction SilentlyContinue
    }
    if (-not $Quiet) { Write-Host "FNP8 Type formattering geladen in het geheugen." -ForegroundColor Yellow }
}

function Format-FNP8Output {
    param($Data, [string]$Tag)
    if (-not $Data) { return }
    $arr = @()
    foreach ($item in $Data) {
        if ($item -and $item.psobject) {
            $customType = "FNP8.Type.$Tag"
            if (-not $item.psobject.TypeNames.Contains($customType)) { $item.psobject.TypeNames.Insert(0, $customType) }
        }
        $arr += $item
    }
    return $arr
}
#endregion

#region 5. Core Engine (SQL & Objects)
function Invoke-FNP8SQL {
    param([Parameter(Mandatory=$true)][string]$Query)
    if (-not $global:FNP8OS) { throw "Geen actieve ObjectStore." }
    try {
        $searchSQL = New-Object FileNet.Api.Query.SearchSQL($Query)
        $searchScope = New-Object FileNet.Api.Query.SearchScope($global:FNP8OS)
        return $searchScope.FetchRows($searchSQL, $null, $null, $null)
    } catch { Write-Warning "SQL Fout: $($_.Exception.Message)"; return $null }
}

function Get-FNP8Objects {
    param([string]$ClassName, [string]$Where = "", [int]$Limit = 500)
    if (-not $global:FNP8OS) { Write-Warning "Geen ObjectStore geselecteerd!"; return $null }
    
    $sql = "SELECT TOP $Limit * FROM [$ClassName]"
    if ($Where) { $sql += " WHERE $Where" }
    
    try {
        $searchSQL = New-Object FileNet.Api.Query.SearchSQL($sql.Trim())
        $scope = New-Object FileNet.Api.Query.SearchScope($global:FNP8OS)
        $objects = $scope.FetchObjects($searchSQL, $null, $null, $null)
        
        $result = @()
        foreach ($obj in $objects) { $result += $obj }
        return $result

    } catch { 
        Write-Warning "Fout bij ophalen van [$ClassName]: $($_.Exception.Message)"
        return $null 
    }
}
#endregion

#region 6. Metadata & Infrastructure
function Get-FNP8Addons {
    if (-not $global:FNP8OS) { return $null }
    return $global:FNP8OS.AddOnInstallationRecords | Sort-Object DateInstalled -Descending
}

function Get-FNP8LocalProperties {
    param([Parameter(Mandatory=$true)]$ClassDef)
    $parentProps = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $ClassDef.SuperclassDefinition) {
        foreach ($p in $ClassDef.SuperclassDefinition.PropertyDefinitions) { [void]$parentProps.Add($p.SymbolicName) }
    }
    return $ClassDef.PropertyDefinitions | Where-Object { -not $parentProps.Contains($_.SymbolicName) } | ForEach-Object {
        [pscustomobject]@{
            SymbolicName = $_.SymbolicName; DataType = $_.DataType.ToString(); IsLocal = $true
            AddOn = try { $_.PropertyTemplate.InstalledByAddon.DisplayName } catch { "System" }
        }
    }
}

function Get-FNP8StorageStatus {
    if (-not $global:FNP8OS) { return }
    $global:FNP8OS.StorageAreas | ForEach-Object {
        [PSCustomObject]@{ Naam=$_.DisplayName; Status=$_.ResourceStatus.ToString(); IsFull=$_.IsFull; Path=try{$_.RootDirectoryPath}catch{"N/A"} }
    }
}

function Get-FNP8FolderContent {
    param([string]$Path = "/")
    $folder = [FileNet.Api.Core.Factory+Folder]::FetchInstance($global:FNP8OS, $Path, $null)
    $items = @()
    foreach ($sub in $folder.SubFolders) { $items += [PSCustomObject]@{ Type="[DIR]"; Name=$sub.FolderName; Date=$sub.DateCreated; Id=$sub.Id } }
    foreach ($doc in $folder.ContainedDocuments) { $items += [PSCustomObject]@{ Type="DOC"; Name=$doc.NiceName; Date=$doc.DateCreated; Id=$doc.Id } }
    $items | Sort-Object Type, Name | Format-Table -AutoSize
}

function Get-FNP8FolderHierarchy {
    param([string]$StartPath = "/", [int]$MaxDepth = 3, [int]$CurrentDepth = 0)
    if ($CurrentDepth -eq 0) { Write-Host "`n📁 Mapstructuur genereren (Max Diepte: $MaxDepth)...`n" -ForegroundColor Cyan }
    $indent = "  " * $CurrentDepth
    try {
        $folder = [FileNet.Api.Core.Factory+Folder]::FetchInstance($global:FNP8OS, $StartPath, $null)
        Write-Output "$indent- **$($folder.FolderName)** `($($folder.PathName)`)"
        if ($CurrentDepth -lt $MaxDepth) {
            $subFolders = $folder.SubFolders | Sort-Object FolderName
            foreach ($sub in $subFolders) {
                Get-FNP8FolderHierarchy -StartPath $sub.PathName -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
            }
        }
    } catch { Write-Output "$indent- ⚠️ Fout bij lezen van $StartPath" }
}

function Get-FNP8ClassHierarchy {
    param([string]$RootClass = "Document", [int]$CurrentDepth = 0)
    if ($CurrentDepth -eq 0) { Write-Host "`n📄 Class Hierarchy genereren voor [$RootClass]...`n" -ForegroundColor Cyan }
    $indent = "  " * $CurrentDepth
    try {
        $classDef = [FileNet.Api.Core.Factory+ClassDefinition]::FetchInstance($global:FNP8OS, $RootClass, $null)
        Write-Output "$indent- **$($classDef.DisplayName)** `($($classDef.SymbolicName)`)"
        $subClasses = $classDef.ImmediateSubclassDefinitions | Sort-Object DisplayName
        foreach ($sub in $subClasses) {
            Get-FNP8ClassHierarchy -RootClass $sub.SymbolicName -CurrentDepth ($CurrentDepth + 1)
        }
    } catch { Write-Output "$indent- ⚠️ Fout bij lezen van $RootClass" }
}

function Get-FNP8ContentText {
    param($Document)
    try {
        if (-not $Document.ContentElementsPresent -or $Document.ContentElements.Count -eq 0) {
            Write-Warning "Dit object heeft geen content elementen."
            return $null
        }
        $contentMap = [ordered]@{}
        $index = 0
        foreach ($ce in $Document.ContentElements) {
            $mime = if ($ce.ContentType) { $ce.ContentType } else { "text/plain" }
            $name = if ($ce.RetrievalName) { $ce.RetrievalName } else { "Element_$index" }
            
            $stream = $ce.AccessContentStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $text = $reader.ReadToEnd()
            $reader.Close()
            $stream.Close()

            $contentMap["[$index] $name ($mime)"] = $text
            $index++
        }
        return $contentMap
    } catch {
        Write-Warning "Fout bij het uitlezen van de content stream: $($_.Exception.Message)"
        return $null
    }
}
#endregion

#region 7. Template Parser & Exporter
function Get-FNP8XmlFilterExpression {
    param([System.Xml.XmlNode]$Node, [int]$Depth = 0)
    $opMap = @{ "eq"="="; "neq"="<>"; "gt"=">"; "gte"=">="; "lt"="<"; "lte" ="<="; "like"="LIKE"; "in"="IN" }
    $parts = @()
    foreach ($child in $Node.ChildNodes) {
        if ($child.LocalName -match "and|or") {
            $sub = Get-FNP8XmlFilterExpression -Node $child -Depth ($Depth + 1)
            if ($sub) { $parts += "($sub)" }
        } elseif ($opMap.ContainsKey($child.LocalName)) {
            $propNode = $child.SelectSingleNode(".//*[local-name()='whereprop']")
            $litNode  = $child.SelectSingleNode(".//*[local-name()='literal']")
            if ($propNode) {
                $symName = $propNode.Attributes["symname"].Value
                $vis = if ($propNode.Attributes["editproperty"]) { $propNode.Attributes["editproperty"].Value } else { "default" }
                $val = if ($litNode) { $litNode.InnerText.Trim() } else { "?" }
                $parts += "$symName [$vis] $($opMap[$child.LocalName]) '$val'"
            }
        }
    }
    return $parts -join " $($Node.LocalName.ToUpper()) "
}

function Get-FNP8TemplateConfig {
    param($TemplateId)
    try {
        $doc = [FileNet.Api.Core.Factory+Document]::FetchInstance($global:FNP8OS, [FileNet.Api.Util.Id]::new($TemplateId), $null)
        $raw = (New-Object System.IO.StreamReader($doc.AccessContentStream(0))).ReadToEnd()
        $res = [PSCustomObject]@{ Id=$TemplateId; Name=$doc.NiceName; Type="Unknown"; IsLegacyLocked=$false; Fields=@(); Expr=""; RawContent=$raw }
        
        $trimmed = $raw.Trim()
        if ($trimmed.StartsWith("{")) {
            $res.Type = "ICN (JSON)"
            $matches = [regex]::Matches($raw, "binding\s*:\s*['""]Properties\.([^'""]+)['""]")
            $res.Fields = $matches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        } elseif ($trimmed.StartsWith("<")) {
            $res.Type = "Workplace (XML)"; [xml]$xml = $raw
            $prod = $xml.SelectSingleNode("//*[local-name()='product']")
            if ($prod -and $prod.Attributes["name"].Value -eq "Search Designer") { $res.IsLegacyLocked = $true }
            $res.Fields = $xml.SelectNodes("//*[local-name()='selectprop']") | ForEach-Object { "$($_.Attributes['symname'].Value) ($($_.Attributes['name'].Value))" }
            $where = $xml.SelectSingleNode("//*[local-name()='where']")
            if ($where) { $res.Expr = Get-FNP8XmlFilterExpression -Node $where }
        }
        return $res
    } catch { return $null }
}

function Export-FNP8Templates {
    param ([string]$ExportFolder = "FNP8_Templates_Export")
    if (-not $global:FNP8OS) { throw "Geen actieve ObjectStore." }
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
    $baseDir = Join-Path -Path $scriptDir -ChildPath "$ExportFolder\$($global:FNP8OS.SymbolicName)"
    
    $types = @( @{ Name="EntryTemplates"; Q="SELECT Id, DocumentTitle FROM EntryTemplate" }, @{ Name="SearchTemplates"; Q="SELECT Id, DocumentTitle FROM StoredSearch" } )
    foreach ($tt in $types) {
        Write-Host "`n---> Exporting: $($tt.Name)" -ForegroundColor Cyan
        $results = @(Invoke-FNP8SQL -Query $tt.Q)
        foreach ($tmpl in $results) {
            $safeName = ($tmpl.DocumentTitle -replace '[\\/:*?"<>|]', '_').Trim()
            $subDir = Join-Path $baseDir (Join-Path $tt.Name $safeName)
            New-Item -ItemType Directory -Path $subDir -Force | Out-Null
            
            $config = Get-FNP8TemplateConfig -TemplateId $tmpl.Id.ToString()
            if ($config) {
                $ext = if ($config.Type -match "JSON") { ".json" } else { ".xml" }
                $formatted = $config.RawContent
                try {
                    if ($ext -eq ".json") { $formatted = ($config.RawContent | ConvertFrom-Json | ConvertTo-Json -Depth 100) }
                    else { [xml]$xmlDoc = $config.RawContent; $sw = New-Object System.IO.StringWriter; $xw = New-Object System.Xml.XmlTextWriter($sw); $xw.Formatting = 1; $xmlDoc.Save($xw); $formatted = $sw.ToString() }
                } catch { }
                $formatted | Out-File (Join-Path $subDir "$safeName$ext") -Encoding UTF8
                
                $info = @"
=== TEMPLATE ANALYSE ===
Naam:       $($config.Name)
Type:       $($config.Type)
LegacyLock: $($config.IsLegacyLocked)
Expressie:  $($config.Expr)
Velden:     $($config.Fields -join ", ")
"@
                $info | Out-File (Join-Path $subDir "info.txt") -Encoding UTF8
            }
        }
    }
}
#endregion

#region 8. Reporting & Audit
function New-FNP8Report {
    param($Title = "FNP8 Dossier", $File = "Report.html")
    $global:FNP8Buffer = New-Object System.Collections.Generic.List[string]
    $global:FNP8Buffer.Add("<html><head><style>body{font-family:'Segoe UI';margin:30px}h2{background:#1f618d;color:white;padding:10px}table{width:100%;border-collapse:collapse;margin-bottom:30px}th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:12px;word-break:break-word}tr:nth-child(even){background:#f2f2f2}</style></head><body><h1>$Title</h1>")
}

function Add-FNP8ReportSection {
    param($Title, [Parameter(ValueFromPipeline=$true)]$Data, $Props = "*")
    begin { $items = New-Object System.Collections.Generic.List[PSObject] }
    process { if ($_ -ne $null) { $items.Add($_) } elseif ($null -ne $Data) { if ($Data -is [array]) { $Data | ForEach-Object { $items.Add($_) } } else { $items.Add($Data) } } }
    end {
        if ($items.Count -eq 0) { return }
        $cols = if ($Props -eq "*") { $items[0].psobject.Properties.Name } else { $Props }
        $sb = New-Object System.Text.StringBuilder
        $null = $sb.Append("<h2>$Title ($($items.Count) items)</h2><table><tr>")
        foreach ($c in $cols) { $null = $sb.Append("<th>$c</th>") }
        $null = $sb.Append("</tr>")
        foreach ($i in $items) {
            $null = $sb.Append("<tr>")
            foreach ($c in $cols) { $val = $i.$c; $txt = if ($null -eq $val) { "-" } else { $val.ToString() }; $null = $sb.Append("<td>$([System.Net.WebUtility]::HtmlEncode($txt))</td>") }
            $null = $sb.Append("</tr>")
        }
        $global:FNP8Buffer.Add($sb.Append("</table>").ToString())
    }
}

function Save-FNP8Report { param($File = "Report.html") $global:FNP8Buffer.Add("</body></html>"); $global:FNP8Buffer | Out-File $File -Encoding utf8; Write-Host "Report: $File" -ForegroundColor Green }

function Invoke-FNP8FullAudit {
    $file = "Dossier_$($global:FNP8OS.SymbolicName)_$(Get-Date -Format 'yyyyMMdd').html"
    New-FNP8Report -Title "Dossier: $($global:FNP8OS.DisplayName)" -File $file
    Write-Host "Bezig met audit..." -ForegroundColor Yellow
    
    Get-FNP8Addons | Add-FNP8ReportSection -Title "Add-ons"
    Get-FNP8Objects -ClassName "ChoiceList" | Select NiceName, Id, AccessSummary | Add-FNP8ReportSection -Title "Choice Lists"
    
    $templates = Get-FNP8Objects -ClassName "EntryTemplate" -Limit 50
    $tInfo = foreach ($t in $templates) { 
        $c = Get-FNP8TemplateConfig -TemplateId $t.Id.ToString()
        [pscustomobject]@{ Naam=$t.NiceName; Type=$c.Type; LegacyLocked=$c.IsLegacyLocked; Velden=($c.Fields -join ", "); Expressie=$c.Expr }
    }
    $tInfo | Add-FNP8ReportSection -Title "Template Deep Analysis"
    
    Save-FNP8Report -File $file
}
#endregion

#region 9. The CPE Router & Shorthands
function Get-CPEResourceData {
    param([string]$Resource, [string]$Action, [int]$Limit)
    
    switch ($Resource) {
        { $_ -eq 'HELP' } { return $null } # Voorkomt foutmeldingen bij HELP command
        { $_ -in 'Addons', 'AO' }               { return Get-FNP8Addons }
        { $_ -in 'PropertyTemplates', 'PT' }    { return $global:FNP8OS.PropertyTemplates }
        { $_ -in 'StorageArea', 'SA' }          { return $global:FNP8OS.StorageAreas }
        { $_ -in 'ClassDescriptions', 'ClassDescr' } { return $global:FNP8OS.ClassDescriptions }
        
        { $_ -in 'Folder', 'FLDR' } { 
            if ($Action -eq 'HIERARCHY') { Get-FNP8FolderHierarchy; return $null }
            return Get-FNP8Objects "Folder" "" $Limit 
        }
        { $_ -in 'ClassDefinition', 'ClassDef' } {
            if ($Action -eq 'HIERARCHY') { 
                Get-FNP8ClassHierarchy "Document"
                Get-FNP8ClassHierarchy "Folder"
                Get-FNP8ClassHierarchy "CustomObject"
                return $null 
            }
            return Get-FNP8Objects "ClassDefinition" "" $Limit
        }
        
        { $_ -in 'ChoiceList', 'CL' }           { return Get-FNP8Objects "ChoiceList" "" $Limit }
        { $_ -in 'CustomObject', 'CO' }         { return Get-FNP8Objects "CustomObject" "" $Limit }
        { $_ -in 'Document', 'DOCS' }           { return Get-FNP8Objects "Document" "" $Limit }
        { $_ -in 'EntryTemplate', 'ET' }        { return Get-FNP8Objects "EntryTemplate" "" $Limit }
        { $_ -in 'Event', 'EVENT' }             { return Get-FNP8Objects "Event" "" $Limit }
        { $_ -in 'IndexArea', 'IA' }            { return Get-FNP8Objects "IndexArea" "" $Limit }
        { $_ -in 'SecurityPolicy', 'SPL' }      { return Get-FNP8Objects "SecurityPolicy" "" $Limit }
        { $_ -in 'SearchTemplates', 'ST' }      { return Get-FNP8Objects "StoredSearch" "" $Limit }
        { $_ -in 'StoragePolicy', 'STPL' }      { return Get-FNP8Objects "StoragePolicy" "" $Limit }
        { $_ -in 'SOLUTION' } { 
            $whereClause = "[DocumentTitle] = 'Solution Definition' AND [IsCurrentVersion] = True AND THIS INSUBFOLDER '/IBM Case Manager/Solutions'"
            try {
                $solData = Get-FNP8Objects "Document" $whereClause $Limit
                if ($solData) { 
                    foreach ($sol in $solData) {
                        $solName = "Onbekende Oplossing"
                        try {
                            $folders = $sol.FoldersFiledIn
                            if ($null -ne $folders) {
                                foreach ($f in $folders) {
                                    if ($f.PathName -match "/IBM Case Manager/Solutions/([^/]+)") {
                                        $solName = $matches[1]
                                        break
                                    }
                                }
                            }
                        } catch {}
                        $sol | Add-Member -MemberType NoteProperty -Name "NiceName" -Value $solName -Force
                    }
                    Write-Host "    [*] $($solData.Count) Oplossingen gevonden en dynamisch hernoemd." -ForegroundColor DarkGray
                    return $solData 
                }
            } catch { Write-Warning "Fout bij SQL query in Solutions map: $($_.Exception.Message)" }
            Write-Warning "Geen 'Solution Definition' documenten gevonden in '/IBM Case Manager/Solutions'."
            return $null
        }
        default { Write-Warning "Onbekende CPE parameter: $Resource"; return $null }
    }
}

function Show-CPEDetails {
    param($Object, [string]$Action, [bool]$ExportToDisk = $false)
    
    # 1. BAW SPECIFIEKE ACTIES
    if ($Action -in @("MERMAID", "CASES", "TASKS")) {
        Write-Host "`n--- BAW $Action EXTRACTIE: $($Object.NiceName) ---" -ForegroundColor Cyan
        
        $contentMap = Get-FNP8BAWContentText -Document $Object
        $foundDef = $false

        if ($contentMap) {
            foreach ($key in $contentMap.Keys) {
                if ($key -match "\.sdf|\.xml" -or $contentMap[$key] -match "caseType") {
                    $foundDef = $true
                    $cleanXml = $contentMap[$key] -replace 'xmlns(:\w+)?="[^"]+"', '' -replace '<([a-zA-Z0-9]+):', '<' -replace '</([a-zA-Z0-9]+):', '</'
                    [xml]$xml = $cleanXml
                    
                    switch ($Action) {
                        "MERMAID" {
                            $mermaidStr = Convert-BAWSolutionToMermaid -XmlString $contentMap[$key] -SolutionName $Object.NiceName
                            if ($mermaidStr) { Write-Host "`n$mermaidStr" -ForegroundColor White } 
                            else { Write-Warning "Kon structuur niet omzetten naar Mermaid." }
                        }
                        "CASES" {
                            $xml.SelectNodes("//caseType") | Select-Object displayName, name, caseIdentifierPrefix | Format-Table -AutoSize
                        }
                        "TASKS" {
                            $xml.SelectNodes("//task") | Where-Object { $_.hidden -ne 'true' } | Select-Object @{N='Case';E={$_.ParentNode.ParentNode.displayName}}, displayName, launchMode | Format-Table -AutoSize
                        }
                    }
                    break # Stop na de eerste gelukte generatie
                }
            }
        }
        if (-not $foundDef) { Write-Warning "Geen BAW definities gevonden in de bestanden van dit object." }
        return
    }

    # 2. STANDAARD ACTIES (Permissies, Content, Detail)
    if ($Action -eq "PERMISSIONS") {
        Write-Host "`n--- PERMISSIES VOOR: $($Object.NiceName) ---" -ForegroundColor Cyan
        try {
            $perms = $Object.Permissions
            if (-not $perms) { Write-Warning "Geen permissie-lijst gevonden."; return }
            $permArray = @(); foreach ($p in $perms) { $permArray += $p }
            Format-FNP8Output -Data $permArray -Tag "Permission" | Out-Default
        } catch { Write-Warning "Fout bij ophalen permissies." }
        return
    }
    
    if ($Action -eq "CONTENT") {
        Write-Host "`n--- CONTENT ELEMENTS VAN: $($Object.NiceName) ---" -ForegroundColor Cyan
        
        $isStoredSearch = ($Object.psobject.TypeNames -match "StoredSearch") -or ($Object.ClassName -eq "StoredSearch")
        if ($isStoredSearch) {
            $count = if ($Object.ContentElementsPresent) { $Object.ContentElements.Count } else { 0 }
            if ($count -ne 2) { Write-Warning "Let op: Normaal 2 content elementen verwacht. Dit object heeft er $count." } 
            else { Write-Host " [V] Object bevat 2 content elementen." -ForegroundColor Green }
        }

        $contentMap = Get-FNP8ContentText -Document $Object
        if ($contentMap) {
            $baseExportDir = Join-Path (Get-FNP8ScriptDirectory) "FNP8_ContentExport"
            $exportDir = $baseExportDir

            if ($ExportToDisk) {
                try {
                    $folders = $Object.FoldersFiledIn
                    $folderArray = @()
                    if ($null -ne $folders) { foreach ($f in $folders) { $folderArray += $f } }
                    
                    if ($folderArray.Count -gt 0) {
                        $cleanFolderName = $folderArray[0].FolderName -replace '[\\/:*?"<>|]', '_'
                        $exportDir = Join-Path $baseExportDir $cleanFolderName
                        Write-Host "    [*] Gevonden in map: $($folderArray[0].FolderName) -> Submap geselecteerd." -ForegroundColor DarkGray
                    }
                } catch { Write-Host "    [!] Kon FoldersFiledIn niet uitlezen, export gaat naar root map." -ForegroundColor DarkGray }

                if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
                Write-Host "    [+] Doelmap: $exportDir" -ForegroundColor DarkMagenta
            }

            foreach ($key in $contentMap.Keys) {
                Write-Host "`n[ Bestand: $key ]" -ForegroundColor Yellow
                Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray
                
                $text = $contentMap[$key]
                if ($text.Length -gt 2000) { Write-Host ($text.Substring(0, 2000) + "`n... (REST VAN BESTAND AFGEKAPT) ...") }
                else { Write-Host $text }
                
                Write-Host "--------------------------------------------------------" -ForegroundColor DarkGray

                if ($isStoredSearch) {
                    if ($key -match "file0|content" -or $text -match "<storedsearch") {
                        Write-Host "    [*] Engine XML gedetecteerd. Start XSD validatie..." -ForegroundColor Cyan
                        Test-FNP8SearchXmlString -XmlString $text | Out-Null
                    } elseif ($key -match "file1|uicontent") {
                        Write-Host "    [*] UI-configuratiebestand gedetecteerd. Geen validatie." -ForegroundColor DarkGray
                    }
                }

                if ($ExportToDisk) {
                    $safeName = ($Object.NiceName -replace '[\\/:*?"<>|]', '_') -replace '\s+', '_'
                    $safeExt  = if ($key -match "JSON|file1") { ".json" } else { ".xml" }
                    $safeKey  = ($key -replace '\[\d+\]\s| \(.+\)', '') -replace '[\\/:*?"<>|]', '_'
                    
                    $outPath = Join-Path $exportDir "${safeName}_${safeKey}${safeExt}"
                    $text | Out-File $outPath -Encoding UTF8
                    Write-Host "    [V] Geëxporteerd: $outPath" -ForegroundColor Magenta
                }
            }
        }
        return
    }

    Write-Host "`n--- DETAILWEERGAVE: $($Object.NiceName) ---" -ForegroundColor Cyan
    $safeProps = [ordered]@{}
    try { $safeProps["[NiceName]"] = $Object.NiceName } catch {}
    foreach ($prop in $Object.psobject.Properties) {
        if ($prop.Name -in @("NiceName", "PSStandardMembers", "Properties", "ClassDescription")) { continue }
        try { $val = $prop.Value; if ($null -ne $val) { $safeProps[$prop.Name] = $val } } catch {}
    }
    [PSCustomObject]$safeProps | Format-List | Out-Default
}

function Invoke-CPECommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet(
            'Addons', 'AO', 'ChoiceList', 'CL', 'ClassDefinition', 'ClassDef', 
            'ClassDescriptions', 'ClassDescr', 'CustomObject', 'CO', 'Document', 'DOCS', 
            'EntryTemplate', 'ET', 'Event', 'EVENT', 'Folder', 'FLDR', 'PropertyTemplates', 'PT', 
            'IndexArea', 'IA', 'SecurityPolicy', 'SPL', 'SearchTemplates', 'ST', 
            'StorageArea', 'SA', 'StoragePolicy', 'STPL', 'SOLUTION', 'HELP'
        )]
        [string]$Resource,
        
        [Parameter(ValueFromRemainingArguments=$true)]
        [string[]]$Arguments
    )

    if ($Resource -eq 'HELP') {
        Write-Host "`n[ Syntax / Gebruik ]" -ForegroundColor Yellow
        Write-Host "  ET                    -> Snelle weergave"
        Write-Host "  ET `"Mijn Template`"    -> Zoek op naam (of deel van naam/ID)"
        Write-Host "  ET 0                  -> Detailweergave (Item 0)"
        Write-Host "  ST 4..6 CONTENT       -> Toon XML/JSON content van items 4, 5 én 6"
        Write-Host "  ST 0 EXPORT           -> Toon én bewaar bestanden op schijf"
        Write-Host "  SOLUTION 0 MERMAID    -> Genereer een Mermaid architectuurdiagram"
        Write-Host "  SOLUTION 0 CASES      -> Toon alle BAW Case Types"
        Write-Host "  SOLUTION 0 TASKS      -> Toon alle actieve BAW Taken"
        Write-Host "  PER ET 0              -> Toon alle PERMISSIES van EntryTemplate 0"
        Write-Host "`nTyp 'CPE HELP' voor dit overzicht.`n" -ForegroundColor DarkGray
        return
    }

    $Action = "LIST"
    $Limit = 500
    $Indices = @()
    $SearchFilter = ""
    $ExportToDisk = $false
    
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $arg = $Arguments[$i]
        $argUp = $arg.ToUpper()
        
        if ($argUp -eq "HIERARCHY") { $Action = "HIERARCHY" }
        elseif ($argUp -eq "PER") { $Action = "PERMISSIONS" }
        elseif ($argUp -in @("CONTENT", "XML", "JSON")) { $Action = "CONTENT" }
        elseif ($argUp -in @("MERMAID", "CASES", "TASKS")) { $Action = $argUp } 
        elseif ($argUp -eq "EXPORT") { $Action = "CONTENT"; $ExportToDisk = $true }
        elseif ($argUp -eq "LIMIT" -and ($i + 1) -lt $Arguments.Count) { $Limit = [int]$Arguments[$i+1]; $i++ }
        elseif ($arg -match "^(\d+)\.\.(\d+)$") { 
            if ($Action -notin @("PERMISSIONS", "CONTENT", "MERMAID", "CASES", "TASKS")) { $Action = "DETAIL" }
            $Indices += [int]$matches[1]..[int]$matches[2]
        }
        elseif ($arg -match "^\d+$") {
            if ($Action -notin @("PERMISSIONS", "CONTENT", "MERMAID", "CASES", "TASKS")) { $Action = "DETAIL" }
            $Indices += [int]$arg
        }
        else {
            $SearchFilter += "$arg "
        }
    }
    $SearchFilter = $SearchFilter.Trim()

    $data = Get-CPEResourceData -Resource $Resource -Action $Action -Limit $Limit
    if ($Action -eq 'HIERARCHY') { return }
    if (-not $data) { Write-Host "Geen resultaten gevonden." -ForegroundColor DarkGray; return }
    $dataArray = @($data)

    if ($SearchFilter) {
        $dataArray = $dataArray | Where-Object {
            ($null -ne $_.NiceName -and $_.NiceName -match $SearchFilter) -or
            ($null -ne $_.psobject.Properties['SymbolicName'] -and $_.SymbolicName -match $SearchFilter) -or
            ($null -ne $_.psobject.Properties['Name'] -and $_.Name -match $SearchFilter) -or
            ($null -ne $_.Id -and $_.Id.ToString() -match $SearchFilter)
        }
        
        if ($dataArray.Count -eq 0) { 
            Write-Warning "Geen items gevonden met de zoekterm '$SearchFilter'." 
            return 
        }
        
        if ($Indices.Count -eq 0 -and $Action -in @("DETAIL", "CONTENT", "PERMISSIONS", "MERMAID", "CASES", "TASKS")) {
            Write-Host "Automatisch index [0] geselecteerd voor de match." -ForegroundColor DarkGray
            $Indices += 0
        }
    }

    if ($Action -in @("DETAIL", "PERMISSIONS", "CONTENT", "MERMAID", "CASES", "TASKS")) {
        if ($Indices.Count -eq 0) { Write-Warning "Geen index opgegeven."; return }
        foreach ($idx in $Indices) {
            if ($idx -ge 0 -and $idx -lt $dataArray.Count) {
                Show-CPEDetails -Object $dataArray[$idx] -Action $Action -ExportToDisk $ExportToDisk
            } else { Write-Warning "Index $idx bestaat niet." }
        }
        if ($ExportToDisk) {
            $baseDir = Join-Path (Get-FNP8ScriptDirectory) "FNP8_ContentExport"
            if (Test-Path $baseDir) {
                Write-Host "`n[*] Export afgerond. Map wordt geopend in Windows Verkenner..." -ForegroundColor Cyan
                Invoke-Item $baseDir
            }
        }
    } 
    else {
        Write-Host "Tonen van $($dataArray.Count) items. (Typ 'LIMIT <n>', of '<index>' voor details)" -ForegroundColor DarkGray
        $tag = switch ($Resource) {
            { $_ -in 'Addons', 'AO' }               { "AO" }
            { $_ -in 'ClassDefinition', 'ClassDef' }{ "ClassDef" }
            { $_ -in 'ClassDescriptions', 'ClassDescr' } { "ClassDescr" }
            { $_ -in 'Folder', 'FLDR' }             { "Folder" }
            { $_ -in 'PropertyTemplates', 'PT' }    { "PT" }
            default                                 { "Default" }
        }
        return Format-FNP8Output -Data $dataArray -Tag $tag
    }
}

Set-Alias -Name CPE -Value Invoke-CPECommand

# --- COMMAND-LINE SHORTHANDS ---
function HELP     { CPE HELP @args }
function AO       { CPE Addons @args }
function CL       { CPE ChoiceList @args }
function ClassDef { CPE ClassDefinition @args }
function ClassDescr { CPE ClassDescriptions @args }
function CO       { CPE CustomObject @args }
function DOCS     { CPE Document @args }
function ET       { CPE EntryTemplate @args }
function EVENT    { CPE Event @args }
function FLDR     { CPE Folder @args }
function PT       { CPE PropertyTemplates @args }
function IA       { CPE IndexArea @args }
function SPL      { CPE SecurityPolicy @args }
function ST       { CPE SearchTemplates @args }
function SA       { CPE StorageArea @args }
function STPL     { CPE StoragePolicy @args }
function SOLUTION { CPE SOLUTION @args }

function PER {
    if ($args.Count -lt 2) { Write-Warning "Gebruik: PER <Resource> <Index>"; return }
    $res = $args[0]; $idxArgs = $args[1..($args.Count-1)] -join " "
    CPE $res $idxArgs PER
}
#endregion

#region 10. Environment Compare (DTAP)
function Export-FNP8Snapshot {
    param(
        [ValidateSet("PT", "ClassDef")]
        [string]$Type = "PT",
        [string]$EnvName = "DEV"
    )
    
    if (-not $global:FNP8OS) { Write-Warning "Geen actieve ObjectStore."; return }
    
    $exportDir = Join-Path (Get-FNP8ScriptDirectory) "DTAP_Snapshots"
    if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir | Out-Null }
    
    $outFile = Join-Path $exportDir "Snapshot_${Type}_${EnvName}.json"
    Write-Host "`nGenereren van $Type snapshot voor $EnvName..." -ForegroundColor Cyan
    
    $exportData = @()
    if ($Type -eq "PT") {
        $items = $global:FNP8OS.PropertyTemplates
        foreach ($item in $items) {
            $exportData += [PSCustomObject]@{ SymbolicName = $item.SymbolicName; DisplayName  = $item.DisplayName; DataType = $item.DataType.ToString(); Id = $item.Id.ToString() }
        }
    }
    elseif ($Type -eq "ClassDef") {
        $items = Get-FNP8Objects "ClassDefinition" "" 5000
        foreach ($item in $items) {
            $exportData += [PSCustomObject]@{ SymbolicName = $item.SymbolicName; DisplayName  = $item.DisplayName; IsHidden = $item.IsHidden; Id = $item.Id.ToString() }
        }
    }
    
    $exportData = $exportData | Sort-Object SymbolicName
    $exportData | ConvertTo-Json -Depth 2 | Out-File $outFile -Encoding UTF8
    Write-Host "Snapshot succesvol opgeslagen: $outFile" -ForegroundColor Green
}
#endregion

#region 11. BAW (Business Automation Workflow) Extensions
function Get-FNP8BAWContentText {
    param($Document)
    
    $resultMap = [ordered]@{}
    Add-Type -AssemblyName System.IO.Compression | Out-Null
    
    try {
        if (-not $Document.ContentElementsPresent) { return $null }

        foreach ($ce in $Document.ContentElements) {
            $stream = $ce.AccessContentStream()
            $mime = if ($ce.ContentType) { $ce.ContentType } else { "text/plain" }
            $name = if ($ce.RetrievalName) { $ce.RetrievalName } else { "Element" }
            
            if ($mime -match "zip|compressed" -or $name -match "\.zip$") {
                Write-Host "    [*] ZIP archief gedetecteerd. Virtueel uitpakken gestart..." -ForegroundColor Cyan
                $archive = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Read)
                
                foreach ($entry in $archive.Entries) {
                    if ($entry.FullName -match "solution\.json$|\.xml$|\.sdf$") {
                        $reader = New-Object System.IO.StreamReader($entry.Open())
                        $resultMap["[ZIP] $($entry.FullName)"] = $reader.ReadToEnd()
                        $reader.Close()
                    }
                }
                $archive.Dispose()
            } 
            else {
                $reader = New-Object System.IO.StreamReader($stream)
                $resultMap[$name] = $reader.ReadToEnd()
                $reader.Close()
            }
            $stream.Close()
        }
        return $resultMap
    } catch {
        Write-Warning "Fout bij BAW Content Extractie: $($_.Exception.Message)"
        return $null
    }
}

function Convert-BAWSolutionToMermaid {
    param([string]$XmlString, [string]$SolutionName)
    
    try {
        $cleanXml = $XmlString -replace 'xmlns(:\w+)?="[^"]+"', '' -replace '<([a-zA-Z0-9]+):', '<' -replace '</([a-zA-Z0-9]+):', '</'
        $xml = [xml]$cleanXml

        $solName = if ($xml.solution.name) { $xml.solution.name } else { $SolutionName }
        $safeSolName = ($solName -replace '[^a-zA-Z0-9]', '')
        if ([string]::IsNullOrWhiteSpace($safeSolName)) { $safeSolName = "BAWSolution" }

        $lines = @(
            '```mermaid',
            "graph TD",
            "    %% Styling",
            "    classDef sol fill:#2c3e50,stroke:#34495e,stroke-width:2px,color:#fff;",
            "    classDef role fill:#2980b9,stroke:#2980b9,stroke-width:1px,color:#fff;",
            "    classDef doc fill:#27ae60,stroke:#27ae60,stroke-width:1px,color:#fff;",
            "    classDef case fill:#8e44ad,stroke:#8e44ad,stroke-width:1px,color:#fff;",
            "    classDef task fill:#f39c12,stroke:#f39c12,stroke-width:1px,color:#fff;",
            "",
            "    Root_$safeSolName(`"$solName`"):::sol"
        )

        $roles =$xml.SelectNodes("//role")
        if ($null -ne$roles -and $roles.Count -gt 0) {$lines += "    Root_$safeSolName --> Group_Roles_$safeSolName[[Rollen]]"
            foreach ($r in $roles) {$rName = if ($r.displayName) {$r.displayName } else { $r.name }$safeId = ($rName -replace '[^a-zA-Z0-9]', '') + (Get-Random -Maximum 9999)$lines += "    Group_Roles_$safeSolName --> Role_$safeId(`"$rName`"):::role"
            }
        }

        $docTypes =$xml.SelectNodes("//documentType")
        if ($null -ne$docTypes -and $docTypes.Count -gt 0) {$lines += "    Root_$safeSolName --> Group_Docs_$safeSolName[[Document Types]]"
            foreach ($d in $docTypes) {$dName = if ($d.displayName) {$d.displayName } elseif ($d.localName) {$d.localName } else { "Doc" }
                $safeId = ($dName -replace '[^a-zA-Z0-9]', '') + (Get-Random -Maximum 9999)$lines += "    Group_Docs_$safeSolName --> Doc_$safeId(`"$dName`"):::doc"
            }
        }

        $caseTypes =$xml.SelectNodes("//caseType")
        if ($null -ne$caseTypes -and $caseTypes.Count -gt 0) {$lines += "    Root_$safeSolName --> Group_Cases_$safeSolName[[Case Types]]"
            foreach ($c in $caseTypes) {$cName = if ($c.displayName) {$c.displayName } elseif ($c.name) {$c.name } else { "Case" }
                $safeCaseId = ($cName -replace '[^a-zA-Z0-9]', '') + (Get-Random -Maximum 9999)$lines += "    Group_Cases_$safeSolName --> Case_$safeCaseId(`"$cName`"):::case"
                
                $tasks =$c.SelectNodes(".//task")
                if ($null -ne$tasks) {
                    foreach ($t in$tasks) {
                        if ($t.hidden -eq 'true') { continue }$tName = if ($t.displayName) {$t.displayName } elseif ($t.name) {$t.name } else { "Taak" }
                        $safeTaskId = ($tName -replace '[^a-zA-Z0-9]', '') + (Get-Random -Maximum 9999)$lines += "    Case_$safeCaseId -.-> Task_$safeTaskId([`"$tName`"]):::task"
                    }
                }
            }
        }

        $lines += '```'
        return $lines -join "`n"
    } catch { 
        Write-Warning "Fout bij Mermaid generatie: $($_.Exception.Message)"
        return $null 
    }
}
#endregion

#region 50. Legacy Search Template Analysis & XSD
function Test-FNP8SearchXmlString {
    param ([Parameter(Mandatory=$true)][string]$XmlString)

    Write-Host "`n[*] Start strenge XSD validatie in het geheugen..." -ForegroundColor Cyan

    $xsdString = @"
<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="http://filenet.com/namespaces/wcm/apps/1.0" xmlns="http://filenet.com/namespaces/wcm/apps/1.0" elementFormDefault="qualified">
  <xs:group name="LogicalOperators">
    <xs:choice>
      <xs:element name="and" type="LogicBlock"/>
      <xs:element name="or" type="LogicBlock"/>
      <xs:element name="eq" type="ConditionBlock"/>
      <xs:element name="neq" type="ConditionBlock"/>
      <xs:element name="gte" type="ConditionBlock"/>
      <xs:element name="lte" type="ConditionBlock"/>
      <xs:element name="gt" type="ConditionBlock"/>
      <xs:element name="lt" type="ConditionBlock"/>
      <xs:element name="in" type="ConditionBlock"/>
    </xs:choice>
  </xs:group>
  <xs:complexType name="LogicBlock"><xs:sequence><xs:group ref="LogicalOperators" minOccurs="0" maxOccurs="unbounded"/></xs:sequence></xs:complexType>
  <xs:complexType name="ConditionBlock">
    <xs:sequence>
      <xs:element name="whereprop">
        <xs:complexType>
          <xs:sequence><xs:element name="propdesc" minOccurs="0"><xs:complexType><xs:attribute name="datatype" type="xs:string" use="required"/><xs:attribute name="haschoices" type="xs:string"/><xs:attribute name="hasmarkings" type="xs:string"/><xs:attribute name="symname" type="xs:string"/></xs:complexType></xs:element></xs:sequence>
          <xs:attribute name="editproperty" type="xs:string"/><xs:attribute name="name" type="xs:string"/><xs:attribute name="objecttype" type="xs:string"/><xs:attribute name="symname" type="xs:string" use="required"/><xs:attribute name="itemid" type="xs:string"/>
        </xs:complexType>
      </xs:element>
      <xs:element name="literal" type="xs:string" minOccurs="0"/>
    </xs:sequence>
  </xs:complexType>
  <xs:element name="storedsearch">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="version" minOccurs="1"><xs:complexType><xs:attribute name="dtd" type="xs:string"/><xs:attribute name="searchobject" type="xs:string"/></xs:complexType></xs:element>
        <xs:element name="product" minOccurs="1"><xs:complexType><xs:attribute name="name" type="xs:string" use="required"/><xs:attribute name="version" type="xs:string"/></xs:complexType></xs:element>
        <xs:element name="searchspec">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="searchtype" minOccurs="0"><xs:complexType><xs:sequence><xs:element name="template"><xs:complexType><xs:attribute name="showandorconditions" type="xs:string"/><xs:attribute name="showmaxrecords" type="xs:string"/><xs:attribute name="showoperators" type="xs:string"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element>
              <xs:element name="objectstores" minOccurs="0"><xs:complexType><xs:sequence><xs:element name="objectstore" minOccurs="1" maxOccurs="unbounded"><xs:complexType><xs:attribute name="id" type="xs:string"/><xs:attribute name="name" type="xs:string"/><xs:attribute name="repositoryId" type="xs:string"/></xs:complexType></xs:element></xs:sequence><xs:attribute name="mergeoption" type="xs:string"/></xs:complexType></xs:element>
              <xs:element name="searchcriteria">
                <xs:complexType><xs:sequence><xs:element name="folders" minOccurs="0" type="xs:string"/><xs:element name="searchclauses"><xs:complexType><xs:sequence><xs:element name="searchclause"><xs:complexType><xs:sequence>
                    <xs:element name="select" minOccurs="1"><xs:complexType><xs:sequence><xs:element name="selectprops"><xs:complexType><xs:sequence><xs:element name="selectprop" minOccurs="1" maxOccurs="unbounded"><xs:complexType><xs:attribute name="alignment" type="xs:string"/><xs:attribute name="itemid" type="xs:string"/><xs:attribute name="name" type="xs:string"/><xs:attribute name="objecttype" type="xs:string"/><xs:attribute name="sortlevel" type="xs:string"/><xs:attribute name="sortorder" type="xs:string"/><xs:attribute name="symname" type="xs:string"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element>
                    <xs:element name="from" minOccurs="1"><xs:complexType><xs:sequence><xs:element name="class"><xs:complexType><xs:attribute name="symname" type="xs:string" use="required"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element>
                    <xs:element name="where" type="LogicBlock" minOccurs="1"/>
                    <xs:element name="subclasses" minOccurs="0"><xs:complexType><xs:sequence><xs:element name="subclass" minOccurs="0" maxOccurs="unbounded"><xs:complexType><xs:attribute name="editproperty" type="xs:string"/><xs:attribute name="itemid" type="xs:string"/><xs:attribute name="name" type="xs:string"/><xs:attribute name="objecttype" type="xs:string"/><xs:attribute name="symname" type="xs:string"/><xs:attribute name="includesubclasses" type="xs:string"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element>
                  </xs:sequence><xs:attribute name="join" type="xs:string"/></xs:complexType></xs:element></xs:sequence></xs:complexType></xs:element>
                </xs:sequence></xs:complexType>
              </xs:element>
              <xs:element name="options" minOccurs="0" type="xs:string"/>
            </xs:sequence>
            <xs:attribute name="versionselection" type="xs:string"/>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
"@

    $isValid = $true; $validationErrors = @()
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.ValidationType = [System.Xml.ValidationType]::Schema
    $schemaReader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xsdString))
    $settings.Schemas.Add("http://filenet.com/namespaces/wcm/apps/1.0", $schemaReader) | Out-Null

    $validationEventHandler = [System.Xml.Schema.ValidationEventHandler] {
        param($sender, $e)
        $isValid = $false
        $validationErrors += "Regel $($e.Exception.LineNumber): $($e.Message)"
    }
    $settings.add_ValidationEventHandler($validationEventHandler)

    try {
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($XmlString), $settings)
        while ($reader.Read()) { }
        $reader.Close()
    } catch {
        $isValid = $false; $validationErrors += "Parse fout: $($_.Exception.Message)"
    }

    if ($isValid) { Write-Host "    [V] XML Validatie Geslaagd!" -ForegroundColor DarkGreen } 
    else {
        Write-Host "    [!] XML Validatie Gefaald!" -ForegroundColor Red
        foreach ($err in $validationErrors) { Write-Host "        -> $err" -ForegroundColor Yellow }
    }
    return $isValid
}
#endregion

# ==========================================
# LAUNCH SEQUENCE
# ==========================================
Clear-Host

# 1. Maak de console lekker breed voor de weergave
Set-FNP8ConsoleWidth -Width 2048

# 2. Config laden
Get-FNP8Configuration -ConfigFile "fnp8_config.json"

# 3. FileNet DLL inladen
Import-FNP8Library

# 4. Core initialiseren (NiceName + View tags koppelen)
Initialize-FNP8Core

# 5. Native View formattering laden
Set-CPEDefaultView -Quiet

# 6. Inloggen en ObjectStore closures bouwen
Connect-FNP8Environment

# 7. Toon het welkomstscherm!
CPE HELP
