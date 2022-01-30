#UNCLASSIFIED

# I rewrote a MS tool because I could and it works better
# Michael Calabrese
#
#Revision History
<# 
  v1.0 - 8/2/2021 - Michael Calabrese - Initial creation of form and functions

#>

$Inprogress_array=@(
"Active:
Scope Tab
WMI Filters Tab control

Long Term:
Delegation tab
Cross Domain/Credential Support(This may be halted)
Sites
File and Action Menus
Responsiveness
")

$DebugPreference = "Continue"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
    }

#####FUNCTIONS

function Get-LinkedOUPolicies {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory)]
        [String]$OU
        )    
    
    # Converts GpoLinks and GPO info into a datatable per OU
    $gpos=(Get-GPInheritance -Target $OU -Server $DC).GpoLinks
    [array]$PolicyArray=foreach($gpo in $gpos) {
        $details=Get-GPO -Guid $gpo.GpoId.Guid -Server $DC

        if ($details.WmiFilter.Name.Count -eq 0) { $wmifilter='None' }
        else { $wmifilter=$details.WmiFilter.Name }

        [pscustomobject]@{
            'Link Order'   = [int]$gpo.Order
            'GPO'          = $gpo.DisplayName
            'Enforced'     = [string]$gpo.Enforced
            'Link Enabled' = [string]$gpo.Enabled
            'GPO Status'   = $details.GpoStatus
            'WMI Filter'   = $wmifilter
            'Modified'     = $details.ModificationTime
            'Domain'       = $details.DomainName
        }
    }

    Return $PolicyArray
}

function Get-InheritedOUPolicies {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory)]
        [String]$OU
        )
    
    # Converts GpoLinks and GPO info into a datatable per OU
    $gpos=(Get-GPInheritance -Target $OU -Server $DC).InheritedGpoLinks
    [array]$PolicyArray=for($i=1;$i -le $gpos.Count;$i++) {
        $details=Get-GPO -Guid $gpos[$($i-1)].GpoId.Guid -Server $DC

        if($gpos[$($i-1)].Target -eq $domain.DistinguishedName) {$Location=$domain.DNSRoot}
        else{$Location=$gpos[$($i-1)].Target.split(',')[0] -replace 'OU=',''}

        if ($details.WmiFilter.Name.Count -eq 0) { $wmifilter='None' }
        else { $wmifilter=$details.WmiFilter.Name }

        [pscustomobject]@{
            'Link Order'   = $i
            'GPO'          = $gpos[$($i-1)].DisplayName
            'Location'     = $Location
            'GPO Status'   = $details.GpoStatus
            'WMI Filter'   = $wmifilter
        }
    }
    Return $PolicyArray
}

function Get-PolicyLinks {
    Param(
        [parameter(mandatory)]
        [string]$GPO
        )

    [xml]$report=Get-GPOReport -Name $GPO -ReportType Xml -Server $DC
    
    
    $PolicyDataTable= New-Object System.Data.DataTable
    $PolicyDataTable.Columns.Add('Location',[string]) | Out-Null
    $PolicyDataTable.Columns.Add('Enforced',[string]) | Out-Null
    $PolicyDataTable.Columns.Add('Link Enabled',[string]) | Out-Null
    $PolicyDataTable.Columns.Add('Path',[string]) | Out-Null
    
    foreach($link in $report.GPO.LinksTo) {
        if($link.SOMName -eq $domain.Name){$location=$domain.DNSRoot}
        else{$location=$link.SOMName}

        $polrow=$PolicyDataTable.NewRow()
        $polrow.'Location'     = $location
        $polrow.'Enforced'     = $link.NoOverride
        $polrow.'Link Enabled' = $link.Enabled
        $polrow.'Path'         = $link.SOMPath
        $PolicyDataTable.Rows.Add($polrow)
        }

    Update-DataGridView -DataGridView $script:linkdgv -Item $PolicyDataTable
}

function Get-PolicyACL {
    $perms=Get-GPPermission -Name $TVSelectedNodeText -All -Server $DC
    $applyperms=$perms | Where-Object {$_.Permission -match 'Apply'}

    $secDataTable= New-Object System.Data.DataTable
    $secDataTable.Columns.Add('Name',[string]) | Out-Null

    foreach($name in $applyperms){
        $namerow=$secDataTable.NewRow()
        $namerow.Name   = $Name.Trustee.Name
        $secDataTable.Rows.Add($namerow)
        }

    Update-DataGridView -DataGridView $script:secdgv -Item $secDataTable
}

function Backup-GPOLinks {
    # Checks for backup file and creates it if not there
    Start-Job -Name BackupGPOLinks -ScriptBlock {
        function Get-LinkedOUPolicies {
            [CmdletBinding()]
            Param(
                [parameter(Mandatory)]
                [String]$OU
                )    
    
            # Converts GpoLinks and GPO info into a datatable per OU
            $gpos=(Get-GPInheritance -Target $OU -Server $using:DC).GpoLinks
            [array]$PolicyArray=foreach($gpo in $gpos) {
                $details=Get-GPO -Guid $gpo.GpoId.Guid -Server $using:DC

                if ($details.WmiFilter.Name.Count -eq 0) { $wmifilter='None' }
                else { $wmifilter=$details.WmiFilter.Name }

                [pscustomobject]@{
                    'Link Order'   = [int]$gpo.Order
                    'GPO'          = $gpo.DisplayName
                    'Enforced'     = [string]$gpo.Enforced
                    'Link Enabled' = [string]$gpo.Enabled
                    'GPO Status'   = $details.GpoStatus
                    'WMI Filter'   = $wmifilter
                    'Modified'     = $details.ModificationTime
                    'Domain'       = $details.DomainName
                }
            }

            Return $PolicyArray
        }

        $backupfile="$using:backupdir\$($using:domain.Name)_GPLinks_$using:date.xml"
        if(!(Test-Path $backupfile)){
            $AllOUs=Get-ADOrganizationalUnit -Filter * -Server $using:DC
            $linkbackups=foreach($OU in $AllOUs){
                [pscustomobject]@{OU=$OU.DistinguishedName;'Linked Policies'=Get-LinkedOUPolicies $OU.DistinguishedName}
                }
            $linkbackups | Export-Clixml -Path $backupfile
            }
        }
}

function Write-Log {
    
    # This writes to the log in CMTrace format and writes to the console.
    [CmdletBinding()]
    Param(
        [parameter(Mandatory)]
        [String]$Message,

        [parameter(Mandatory)]
        [String]$Component,

        [parameter(Mandatory)]
        [ValidateSet("Info","Warning","Error")]
        [String]$Type
    )

    Switch ($Type) {
        "Info"      { [int]$Type = 1;Write-Console -Message $Message -Color Black -BackColor White }
        "Warning"   { [int]$Type = 2;Write-Console -Message $Message -Color Black -BackColor Yellow }
        "Error"     { [int]$Type = 3;Write-Console -Message $Message -Color Black -BackColor Orange }
    }

    #CMTrace formatted log line
    $content = "<![LOG[$Message -- $userid]LOG]!><time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" date=`"$(Get-Date -Format "M-d-yyyy")`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"

    Add-Content -Path "$logdir\$logname" -Value $content
}

function Write-Console {
    
    # This writes to the log in CMTrace format and writes to the console.

    Param(
        [parameter(Mandatory)]
        [String]$Message,

        [ValidateSet('Black','White')]
        [String]$Color,

        [ValidateSet('White','Yellow','Orange','Red')]
        [String]$BackColor
    )

    # Write to the console
    $statusbox.SelectionStart=$statusbox.TextLength
    $statusbox.SelectionLength=0
    $statusbox.SelectionColor=$Color
    $statusbox.SelectionBackColor=$BackColor
    $statusbox.AppendText("$Message`n")
    $statusbox.SelectionBackColor=$statusbox.BackColor
    $statusbox.SelectionColor=$statusbox.ForeColor
}

function Update-DataGridView{
    <#
    .SYNOPSIS
                This functions helps you load items into a DataGridView.

    .DESCRIPTION
                Use this function to dynamically load items into the DataGridView control.

    .PARAMETER  DataGridView
                The DataGridView control you want to add items to.

    .PARAMETER  Item
                The object or objects you wish to load into the DataGridView's items collection.
              
    .PARAMETER  DataMember
                Sets the name of the list or table in the data source for which the DataGridView is displaying data.

    .PARAMETER AutoSizeColumns
        Resizes DataGridView control's columns after loading the items.
    #>
    Param (
        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.DataGridView]$DataGridView,
        [ValidateNotNull()]
        [Parameter(Mandatory=$true)]
        $Item,
        [Parameter(Mandatory=$false)]
        [string]$DataMember,
        [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]$AutoSizeColumns = 'None'
    )
    $DataGridView.SuspendLayout()
    $DataGridView.DataMember = $DataMember
              
    if ($null -eq $Item) {
        $DataGridView.DataSource = $null
    }
    elseif ($Item -is [System.Data.DataSet] -and $Item.Tables.Count -gt 0) {
        $DataGridView.DataSource = $Item.Tables[0]
        }
    elseif ($Item -is [System.ComponentModel.IListSource] -or $Item -is [System.ComponentModel.IBindingList] -or $Item -is [System.ComponentModel.IBindingListView] ) {
        $DataGridView.DataSource = $Item
        }
    else {
        $array = New-Object System.Collections.ArrayList
                           
        if ($Item -is [System.Collections.IList]) {
            $array.AddRange($Item)
            }
        else {
            $array.Add($Item)
            }
        $DataGridView.DataSource = $array
        }
              
    if ($AutoSizeColumns -ne 'None') {
        $DataGridView.AutoResizeColumns($AutoSizeColumns)
        }
              
    $DataGridView.ResumeLayout()
}

function Update-GPODataTable{
    # This updates the dynamic GPO Table that shows when clicking the Group Policy Objects Node
    $Global:Policies=Get-GPO -All -Server $DC | Sort-Object DisplayName

    # Build the table framework
    $GPODataTable= New-Object System.Data.DataTable
    $GPODataTable.Columns.Add('Name',[string]) | Out-Null
    $GPODataTable.Columns.Add('GPO Status',[string]) | Out-Null
    $GPODataTable.Columns.Add('WMI Filter',[string]) | Out-Null
    $GPODataTable.Columns.Add('Modified',[string]) | Out-Null
    $GPODataTable.Columns.Add('Owner',[string]) | Out-Null

    # Fill in the table
    foreach ($Policy in $Policies) {
        
        if ($Policy.WmiFilter.Name.Count -eq 0) { $wmifilter='None' }
        else { $wmifilter=$Policy.WmiFilter.Name }

        $GProw= $GPODataTable.NewRow()
        $GProw.'Name'         = [string]$Policy.DisplayName
        $GProw.'GPO Status'   = [string]$Policy.GPOStatus
        $GProw.'WMI Filter'   = [string]$wmifilter
        $GProw.'Modified'     = [string]$Policy.ModificationTime
        $GProw.'Owner'        = [string]$Policy.Owner
        $GPODataTable.Rows.Add($GProw)
    }

    Update-DataGridView -DataGridView $Script:GPODataGridView -Item $GPODataTable # Rebind the GPO DataTable to the GPODataGridView
}

function Update-WMIDataTable{
    # This updates the dynamic WMI Table that shows when clicking the WMI Filters Node
    $Global:WMIFilters=Get-GPWmiFilter -Server $DC | Sort-Object Name

    # Build the table framework
    $WMIDataTable= New-Object System.Data.DataTable
    $WMIDataTable.Columns.Add('Name',[string]) | Out-Null
    $WMIDataTable.Columns.Add('Description',[string]) | Out-Null
    $WMIDataTable.Columns.Add('Linked GPOs',[string]) | Out-Null
    $WMIDataTable.Columns.Add('Author',[string]) | Out-Null
    $WMIDataTable.Columns.Add('Created',[string]) | Out-Null
    $WMIDataTable.Columns.Add('Modified',[string]) | Out-Null

    # Fill in the table
    foreach ($Filter in $WMIFilters) {
        [array]$linkedGPO=$Policies | Where-Object {$_.WmiFilter.Name -eq $filter.Name}
        Switch ($linkedGPO.Count){
            0       {$linkedGPORes='<None>'}
            1       {$linkedGPORes=$linkedGPO.DisplayName}
            Default {$linkedGPORes='<Multiple>'}
            }

        $WMIRow= $WMIDataTable.NewRow()
        $WMIRow.'Name'         = [string]$Filter.Name
        $WMIRow.'Description'  = [string]$Filter.Description
        $WMIRow.'Linked GPOs'  = [string]$linkedGPORes
        $WMIRow.'Author'       = [string]$Filter.Author
        $WMIRow.'Created'      = [string](Get-ADObject $Filter.DistinguishedName -Properties whenCreated -Server $DC).whenCreated
        $WMIRow.'Modified'     = [string]$Filter.Modified
        $WMIDataTable.Rows.Add($WMIRow)
    }

    Update-DataGridView -DataGridView $Script:WMIDataGridView -Item $WMIDataTable # Rebind the WMI DataTable to the WMIDataGridView
}

function ConvertTo-DataTable{
    <#
        .SYNOPSIS
                        Converts objects into a DataTable.
              
        .DESCRIPTION
                        Converts objects into a DataTable, which are used for DataBinding.
              
        .PARAMETER  InputObject
                        The input to convert into a DataTable.
              
        .PARAMETER  Table
                        The DataTable you wish to load the input into.
              
        .PARAMETER RetainColumns
                        This switch tells the function to keep the DataTable's existing columns.
                           
        .PARAMETER FilterCIMProperties
                        This switch removes CIM properties that start with an underline.
              
        .EXAMPLE
                        $DataTable = ConvertTo-DataTable -InputObject (Get-Process)
    #>
    [OutputType([System.Data.DataTable])]
    param(
        $InputObject, 
        [ValidateNotNull()]
        [System.Data.DataTable]$Table,
        [switch]$RetainColumns,
        [switch]$FilterCIMProperties
        )
              
    if($null -eq $Table) {
        $Table = New-Object System.Data.DataTable
        }
              
    if ($null -eq $InputObject ){
        $Table.Clear()
        return @( ,$Table)
        }
              
    if ($InputObject -is [System.Data.DataTable]) {
        $Table = $InputObject
        }
    elseif ($InputObject -is [System.Data.DataSet] -and $InputObject.Tables.Count -gt 0) {
        $Table = $InputObject.Tables[0]
        }
    else {
        if (-not $RetainColumns -or $Table.Columns.Count -eq 0) {
            #Clear out the Table Contents
            $Table.Clear()
                                         
            if ($null -eq $InputObject) { return } #Empty Data
                                         
            $object = $null
            #find the first non null value
            foreach ($item in $InputObject) {
                if ($null -ne $item)
                {
                    $object = $item
                    break
                    }
                }
                                         
            if ($null -eq $object) { return } #All null then empty
                                         
            #Get all the properties in order to create the columns
            foreach ($prop in $object.PSObject.Get_Properties()) {
                if (-not $FilterCIMProperties -or -not $prop.Name.StartsWith('__')) {
                    #filter out CIM properties
                    #Get the type from the Definition string
                    $type = $null
                                                                    
                    if ($null -ne $prop.Value) {
                        try { $type = $prop.Value.GetType() }
                        catch { Out-Null }
                        }
                                                                    
                    if ($null -ne $type) {
                        [void]$table.Columns.Add($prop.Name, $type)
                        }
                    else {
                        #Type info not found 
                        [void]$table.Columns.Add($prop.Name)
                        }
                    }
                }
                                         
            if ($object -is [System.Data.DataRow]) {
                foreach ($item in $InputObject) {
                    $Table.Rows.Add($item)
                    }
                return @( ,$Table)
                }
            }
            else {
                $Table.Rows.Clear()
                }
                           
            foreach ($item in $InputObject) {
                $row = $table.NewRow()
                                         
                if ($item) {
                    foreach ($prop in $item.PSObject.Get_Properties()) {
                        if ($table.Columns.Contains($prop.Name)) {
                            $row.Item($prop.Name) = $prop.Value
                            }
                        }
                    }
                [void]$table.Rows.Add($row)
                }
        }
              
    return @(,$Table)
}

function Update-Domain {
    [CmdletBinding()]
    Param(
        [String]$DomainFQDN,

        [Switch]$LocalDomain
        )

    # This will refresh all variables when the domainbox is changed
    $script:form.Cursor=[System.Windows.Forms.Cursors]::WaitCursor
    if(!$LocalDomain){
        $global:domain=Get-ADDomain -Identity $DomainFQDN
        $global:DC=(Get-ADDomainController -Server $domain.DNSRoot).Hostname
        $global:policyDefs = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\PolicyDefinitions"
        $global:logname="$($domain.name)_GPChanges.log"
        }
    Build-TreeView
    Update-GPODataTable
    Update-WMIDataTable
    Backup-GPOLinks #Backup GPOs if not already backed up
    $script:form.Cursor=[System.Windows.Forms.Cursors]::Default
}

function Add-Node { 
    param ( 
        $RootNode, 
        $dname,
        $name,
        $Type,
        $HasChildren = $true
    )

    $newNode = new-object System.Windows.Forms.TreeNode
    $newNode.Name = $dname 
    $newNode.Text = $name
    If ($HasChildren) {
        $newNode.Nodes.Add('') | Out-Null
        }

    switch ($Type) {
        OrganizationalUnit         {$newnode.ImageIndex = 3
                                    $newNode.SelectedImageIndex = 3
                                    $newNode.Tag='OU'}
        BlockedOrganizationalUnit  {$newnode.ImageIndex = 7
                                    $newNode.SelectedImageIndex = 7
                                    $newNode.Tag='OU'}
        Domain                     {$newNode.ImageIndex = 2
                                    $newNode.SelectedImageIndex = 2
                                    $newNode.Tag='OU'}
        GroupPolicy                {$newNode.ImageIndex=5
                                    $newNode.SelectedImageIndex=5
                                    $newNode.Tag='GPO'}
        GroupPolicyObject          {$newNode.ImageIndex=6
                                    $newNode.SelectedImageIndex=6
                                    $newNode.Tag='GPO'}
        WMIFilter                  {$newNode.ImageIndex=4
                                    $newNode.SelectedImageIndex=4
                                    $newNode.Tag='WMI'}
        Default                    {$newnode.ImageIndex = 0
                                    $newNode.SelectedImageIndex = 0}
    }
    $RootNode.Nodes.Add($newNode) | Out-Null 
    $newNode
}

function Get-NextLevel {
    param (
        $RootNode,
        $Type
    )
                           
    If ($Type -eq 'Domain') {
        $ADObjects = $domain

        $RootNode.Nodes.Clear()

        $ADObjects | % {
            $node = Add-Node -RootNode $RootNode -dname $_.distinguishedName -name $_.DNSRoot -Type Domain
            Get-NextLevel -RootNode $node -Type Domain
            }
        }
        else {
            $ADObjects = Get-ADOrganizationalUnit -Filter * -SearchBase $RootNode.Name -SearchScope OneLevel -Server $DC | Sort-Object Name
            $GPOObjects = (Get-GPInheritance $RootNode.Name -Server $DC).GpoLinks | Sort-Object DisplayName
                           
            If ($ADObjects) {
                $RootNode.Nodes.Clear()

                $GPOObjects | % {
                    Add-Node $RootNode -dname "CN={$($_.GpoId)},CN=Policies,$($domain.SystemsContainer)" -name $_.DisplayName -Type GroupPolicy -HasChildren $false
                    }

                $ADObjects | % {
                    If ( (Get-ADOrganizationalUnit -Filter * -SearchBase $_.DistinguishedName -SearchScope OneLevel -Server $DC) -or ((Get-GPInheritance $_.DistinguishedName -Server $DC).GpoLinks) ) {
                        if( (Get-GPInheritance -Target $_.distinguishedname -Server $DC).gpoinheritanceblocked ) {
                            Add-Node $RootNode $_.distinguishedname $_.name -Type BlockedOrganizationalUnit -HasChildren $true
                            }
                        else{
                            Add-Node $RootNode $_.distinguishedname $_.name -Type OrganizationalUnit -HasChildren $true
                            }
                        }
                    else {
                        if( (Get-GPInheritance -Target $_.distinguishedname -Server $DC).gpoinheritanceblocked ) {
                            Add-Node $RootNode $_.distinguishedname $_.name -Type BlockedOrganizationalUnit -HasChildren $true
                            }
                        else{
                            Add-Node $RootNode $_.distinguishedname $_.name -Type OrganizationalUnit -HasChildren $true
                            }
                        }
                    }
                }
        Else {
            $RootNode.Nodes.Clear()
            $GPOObjects | % {
                Add-Node $RootNode -dname "CN={$($_.GpoId)},CN=Policies,$($domain.SystemsContainer)" -name $_.DisplayName -Type GroupPolicy -HasChildren $false
                }
            }
        }
}

function Build-TreeView { 
    $Script:OUTreeView.Nodes.Add($Script:OUTreeViewTreeNode1)

    $treeNodes = $OUTreeView.Nodes[0]

    #Generate rootdomain node and add subdomain nodes
    $Script:RootDomainNode = Add-Node -dname $Domain.DistinguishedName -name $Domain.DNSRoot -RootNode $treeNodes -Type Domain
    #Copy the RootDomainNode to parent scope
    New-Variable -Name RootDomainNode -Value $RootDomainNode -Scope 1
                           
    $treeNodes.Expand()
    $RootDomainNode.Expand()

    # Add GPO and WMI Nodes
    $Script:RootDomainNode.Nodes.Add($Script:GPO_Node)
    $Script:GPO_Node.Nodes.Add('') | Out-Null
    $Script:RootDomainNode.Nodes.Add($Script:WMI_Node)
    $Script:WMI_Node.Nodes.Add('') | Out-Null
} 

function Import-Icon {

    Param(
        [Parameter(Mandatory)]
        [String]$DllPath,

        [int]$IconIndex=-1
        )
    
    [System.IntPtr] $phiconSmall = 0
    [System.IntPtr] $phiconLarge = 0
    

    if($IconIndex -ne -1) {
        $nofIconsExtracted = [Shell32_Extract]::ExtractIconEx($dllPath, $iconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)
        $iconLarge = [System.Drawing.Icon]::FromHandle($phiconLarge)
        $bmpLarge  = $iconLarge.ToBitmap()

        [User32_DestroyIcon]::DestroyIcon($phiconSmall) | Out-Null
        [User32_DestroyIcon]::DestroyIcon($phiconLarge) | Out-Null

        Return $bmpLarge
        }
    else{
        [array]$ExtractedIcons=@()
        $nofImages = [Shell32_Extract]::ExtractIconEx($dllPath, -1, [ref] $phiconLarge, [ref] $phiconSmall, 0)
        if($nofImages -gt 0) {
            foreach ($iconIndex in 0 .. ($nofImages-1)) {
                $nofIconsExtracted = [Shell32_Extract]::ExtractIconEx($dllPath, $iconIndex, [ref] $phiconLarge, [ref] $phiconSmall, 1)
                $iconLarge = [System.Drawing.Icon]::FromHandle($phiconLarge)
                $bmpLarge  = $iconLarge.ToBitmap()

                $ExtractedIcons+=$bmpLarge
                [User32_DestroyIcon]::DestroyIcon($phiconSmall) | Out-Null
                [User32_DestroyIcon]::DestroyIcon($phiconLarge) | Out-Null
                }
            }
        Return $ExtractedIcons
        }
}

Write-Host "`nWelcome to the 83 NOS GPO closed beta, do not distribute this script." -ForegroundColor Yellow

#####VARIABLES

# Set working directory
if(Get-Module 'ISE') {$global:workingdir="$([Environment]::GetFolderPath('Desktop'))\GPMCbreezy"}
else{$global:workingdir=$PSScriptRoot}

# Import Required Modules
Import-Module GroupPolicy,ActiveDirectory,GPWmifilter
if(!(Get-Module GPWmifilter)){
    Copy-Item "$workingdir\lib\Modules\*" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules" -Recurse
    Import-Module GPWmiFilter
}

# Initial Domain Variables
$global:Forest=Get-ADForest
$global:Domain=Get-ADDomain
$global:DC=(Get-ADDomainController -Server $domain.DNSRoot).Hostname

# Initial Path Variables
$global:date=Get-Date -Format MM.dd.yyyy-hhmmss
$global:logdir="$workingdir\GPLogs"
#$global:logdir="\\ACC\Continuity\Backup\GPLogs"
$global:backupdir="$logdir\PolicyBackups\$(Get-Date -Format MMddyyyy)"
$global:policyDefs = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\PolicyDefinitions"
$global:logname="$($domain.name)_GPChanges.log"
$script_Version="Beta F"

# User Info
$global:userid=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Create Logs Directory
New-Item $logdir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
New-Item $backupdir -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

# Import the Assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

# FontSetup
$DefaultFont=New-Object System.Drawing.Font("Calibri",12,0,3,0)
$DefaultBoldFont=New-Object System.Drawing.Font("Calibri",12,1,3,0)
$10ptFont=New-Object System.Drawing.Font("Calibri",10,0,3,0)

#region imagelist
$imagelist = New-Object 'System.Windows.Forms.ImageList'
$Formatter_binaryFomatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
$System_IO_MemoryStream = New-Object System.IO.MemoryStream (,[byte[]][System.Convert]::FromBase64String('
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAu
MC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAA
ACZTeXN0ZW0uV2luZG93cy5Gb3Jtcy5JbWFnZUxpc3RTdHJlYW1lcgEAAAAERGF0YQcCAgAAAAkD
AAAADwMAAADQDQAAAk1TRnQBSQFMAgEBBwEAARABAAEQAQABEAEAARABAAT/AQkBAAj/AUIBTQE2
AQQGAAE2AQQCAAEoAwABQAMAASADAAEBAQABCAYAAQgYAAGAAgABgAMAAoABAAGAAwABgAEAAYAB
AAKAAgADwAEAAcAB3AHAAQAB8AHKAaYBAAEzBQABMwEAATMBAAEzAQACMwIAAxYBAAMcAQADIgEA
AykBAANVAQADTQEAA0IBAAM5AQABgAF8Af8BAAJQAf8BAAGTAQAB1gEAAf8B7AHMAQABxgHWAe8B
AAHWAucBAAGQAakBrQIAAf8BMwMAAWYDAAGZAwABzAIAATMDAAIzAgABMwFmAgABMwGZAgABMwHM
AgABMwH/AgABZgMAAWYBMwIAAmYCAAFmAZkCAAFmAcwCAAFmAf8CAAGZAwABmQEzAgABmQFmAgAC
mQIAAZkBzAIAAZkB/wIAAcwDAAHMATMCAAHMAWYCAAHMAZkCAALMAgABzAH/AgAB/wFmAgAB/wGZ
AgAB/wHMAQABMwH/AgAB/wEAATMBAAEzAQABZgEAATMBAAGZAQABMwEAAcwBAAEzAQAB/wEAAf8B
MwIAAzMBAAIzAWYBAAIzAZkBAAIzAcwBAAIzAf8BAAEzAWYCAAEzAWYBMwEAATMCZgEAATMBZgGZ
AQABMwFmAcwBAAEzAWYB/wEAATMBmQIAATMBmQEzAQABMwGZAWYBAAEzApkBAAEzAZkBzAEAATMB
mQH/AQABMwHMAgABMwHMATMBAAEzAcwBZgEAATMBzAGZAQABMwLMAQABMwHMAf8BAAEzAf8BMwEA
ATMB/wFmAQABMwH/AZkBAAEzAf8BzAEAATMC/wEAAWYDAAFmAQABMwEAAWYBAAFmAQABZgEAAZkB
AAFmAQABzAEAAWYBAAH/AQABZgEzAgABZgIzAQABZgEzAWYBAAFmATMBmQEAAWYBMwHMAQABZgEz
Af8BAAJmAgACZgEzAQADZgEAAmYBmQEAAmYBzAEAAWYBmQIAAWYBmQEzAQABZgGZAWYBAAFmApkB
AAFmAZkBzAEAAWYBmQH/AQABZgHMAgABZgHMATMBAAFmAcwBmQEAAWYCzAEAAWYBzAH/AQABZgH/
AgABZgH/ATMBAAFmAf8BmQEAAWYB/wHMAQABzAEAAf8BAAH/AQABzAEAApkCAAGZATMBmQEAAZkB
AAGZAQABmQEAAcwBAAGZAwABmQIzAQABmQEAAWYBAAGZATMBzAEAAZkBAAH/AQABmQFmAgABmQFm
ATMBAAGZATMBZgEAAZkBZgGZAQABmQFmAcwBAAGZATMB/wEAApkBMwEAApkBZgEAA5kBAAKZAcwB
AAKZAf8BAAGZAcwCAAGZAcwBMwEAAWYBzAFmAQABmQHMAZkBAAGZAswBAAGZAcwB/wEAAZkB/wIA
AZkB/wEzAQABmQHMAWYBAAGZAf8BmQEAAZkB/wHMAQABmQL/AQABzAMAAZkBAAEzAQABzAEAAWYB
AAHMAQABmQEAAcwBAAHMAQABmQEzAgABzAIzAQABzAEzAWYBAAHMATMBmQEAAcwBMwHMAQABzAEz
Af8BAAHMAWYCAAHMAWYBMwEAAZkCZgEAAcwBZgGZAQABzAFmAcwBAAGZAWYB/wEAAcwBmQIAAcwB
mQEzAQABzAGZAWYBAAHMApkBAAHMAZkBzAEAAcwBmQH/AQACzAIAAswBMwEAAswBZgEAAswBmQEA
A8wBAALMAf8BAAHMAf8CAAHMAf8BMwEAAZkB/wFmAQABzAH/AZkBAAHMAf8BzAEAAcwC/wEAAcwB
AAEzAQAB/wEAAWYBAAH/AQABmQEAAcwBMwIAAf8CMwEAAf8BMwFmAQAB/wEzAZkBAAH/ATMBzAEA
Af8BMwH/AQAB/wFmAgAB/wFmATMBAAHMAmYBAAH/AWYBmQEAAf8BZgHMAQABzAFmAf8BAAH/AZkC
AAH/AZkBMwEAAf8BmQFmAQAB/wKZAQAB/wGZAcwBAAH/AZkB/wEAAf8BzAIAAf8BzAEzAQAB/wHM
AWYBAAH/AcwBmQEAAf8CzAEAAf8BzAH/AQAC/wEzAQABzAH/AWYBAAL/AZkBAAL/AcwBAAJmAf8B
AAFmAf8BZgEAAWYC/wEAAf8CZgEAAf8BZgH/AQAC/wFmAQABIQEAAaUBAANfAQADdwEAA4YBAAOW
AQADywEAA7IBAAPXAQAD3QEAA+MBAAPqAQAD8QEAA/gBAAHwAfsB/wEAAaQCoAEAA4ADAAH/AgAB
/wMAAv8BAAH/AwAB/wEAAf8BAAL/AgAD/wEAEP8B8QL1AvQC/wH3AQcD7gG8AfMB/wIAAfQL8AH0
Af8RAAf/AfQC8wb/AfEB9QHyAYYD/wH3BJoBdAEcAf8CAAHuCpoBcwGZAf8RAAb/AfABBwH3Ae0B
vAX/AfEB9AHPAYYB8wHyAfQB9wQaAZkBHAH0AgAB8wEbCRoCmQH/EQAG/wEHAbwC9wHvBf8B8QHz
AbwDhgH0AfcBGgTDAZkB9AQAARoJwwGZAf8RAAb/AQcBuwGRAe0B7wX/AfEC8wG1Aq4B9AHvBBoB
wwGZAfQEAAEbAcMHGgHDAZkB/xEABf8B8AEZAbUCkQHsAfIE/wHxAhkCtQGvAfQB7wEaBMMBmQH0
BAABGwnDAQcB/xEABP8B8QG8AQkB9wGRAuwB9wHyA/8B8gG8AvAD8QH3AwcBGwHDAQcB9AQAARsB
wwEaBbwBGwHDAQcB/xEAA/8B8AK7AbUCkQKuAW0BkQG8Av8DAAEbAcMHGwHDAQcB9AQAARsEwwMb
AsMBBwH/EQAD/wEHAbwCuwK1AbQCkQLtAv8DAAEbCcMB7gH0BAABGwHDBhsCwwHuAf8RAAP/Ae8B
uwK1AfcBtQORAewB7QL/AwAB9AH2Au4EBwEbAfYB7gH0BAABGwH2Ae4FBwEbAfYB7gH/EQAD/wHz
AbwB8wHxA/ABGwHvAQcB8QL/AwAB9AH2BhsB9AH2Ae4B9AQAAfMB9gYbAvYB7gH/EQAD/wH0AfAB
9gEHAu8BvAH2Ae8BcwEHAv8DAAH0CfYB7gH0BAAB8wn2Ae4B/xEAA/8B9AHyAfQF9gG8AXMBHAL/
AwAB9AH2Ae4FBwHyAfYB7gH0BAAB8wH2AvAEvAHzAfYB7gH/EQAE/wH0AvIC8AO8Ae8BvAL/AwAB
9An2AbwBHAG8AwAB8wn2Ae4BHAHyEAAF/wL0BvMB9AL/AwABGwn2AfQCmQMAARsJ9gEbApkQABD/
AwAB9AsaAfMDAAHzChoBmQH0EAAS/wz0Bv8C9Ab/A/QS/wp0BHMD/wwqA/8D7AHrAW0B9wL/AQcC
7AHrAXIBbQH0Af8KdARzAv8BdAGaA3kBegd5AXMD/wFRARwBdANzBVEBKgP/AfcBBwGYATQBVgH3
Av8BvAHvAQcBVgE5AXIB9AH/AXQBmgN5AXoHeQFzAv8BeQyaAXQD/wF0ApkCeQN0A1IBKgP/Ae8B
BwHvAngBkgLxAwcBeAFYAesB9AH/AXkCmgVLBZoBdAL/AXkMmgF0A/8BmQIaAaAEmgJ6AXkBUgP/
Ae8CBwHvAZIC7AFyAe0CBwLvAewB9AH/AXkCmgFLA1EBKgWaAXQC/wF5AaALmgF0A/8BmQIaAaAE
mgJ6AXkBUgP/AQcB7wL3Au0BeAE1AXgB7wP3AewB9AH/AXkBoAGaAXkBmQJ5AVEFmgF0Av8BeQGg
C5oBdAP/AZkCGgGgBJoCegF5AVID/wEHA+8B9wHtAZgBeAGZAQcD7wHsAv8BeQGgAZoCmQGgAXkB
UgWaAXQC/wGZAaALmgF0A/8BmQIaAaAEmgJ6AXkBUgP/AbwD8wG8AZIBBwHvAQcB8QLzAfIB7QL/
AZkBoAGaAZkBeQGaAXkBUgWaAXQC/wGZAaALmgF0A/8BmQEaAZoCmQZ5AVID/wG8AQcC7wH3A+0B
7wIHAu8B7QL/AZkBoAGaAnkBdAJSBZoBdAL/AZkBwwaaAaAEmgF0A/8BmQEaAZkDGgOaAVIBeQFS
A/8CvAIHAvcCBwO8AgcBkgL/AZkBwwGaBHQBeQGgBJoBdAL/AZkBwwOaAqABmQWaAXQD/wGZARoB
mQL2BMMBUgF5AVID/wK8AesB7AIHAvMB8AG8Ae0BbQEHAfcC/wGZAcMDmgKgAZkFmgF0Av8BmQWg
AZoCdAV5A/8BmQIaAvYEwwFYAXkBUgP/AbwBBwKSAe8B9wKSAe8BvAHvAZIB7wH3Av8BmQWgAZoC
dAV5Av8BeQGaBBoBdAOaApkBmgF5A/8BmQMaApkDeQFYAXkBUgP/A/QB8gG8AfECvAHvAfAE9AL/
AZkBmgQaAXQDmgKZAZoBeQL/AZkGeQGaAvYB1gG0AZoBeQP/AVEBHAF5A3QBUgRRASoG/wH0AbwB
9wESAewB7wHwBv8BGwZ5AZoC9gHWAbQBmgGZCP8BmgZ5AZoD/wxRBv8B9AG8AQcC7wH3AfEM/wHD
BnkBw0H/AUIBTQE+BwABPgMAASgDAAFAAwABIAMAAQEBAAEBBgABARYAA/8EAAEBAYABAQUAAQEB
gAEBBQABAQGAAQEFAAEBAeABAQUAAQEB4AEBBQABAQHgAQEFAAEBAeABAQQAAeABAQHgAQEEAAHg
AQEB4AEBBAAB4AEBAeABAQQAAeABAQHgAQEEAAHgAQEB4AEBBAAB4AEBAeABAQQAAeABAAHgBQAB
4AEAAeAFAAHgAQAB4IMACw=='))
$imagelist.ImageStream = $Formatter_binaryFomatter.Deserialize($System_IO_MemoryStream)
$Formatter_binaryFomatter = $null
$System_IO_MemoryStream = $null
$imagelist.TransparentColor = 'Transparent'
#endregion imagelist

#region TooManyClicks

$DGVEditGPO_Click={
    $EditReason=[Microsoft.VisualBasic.Interaction]::InputBox("Enter a justification for editing.`nThis should be a CRQ or INC.","GPO Edit")
    if($EditReason -ne ''){
        Write-Console -Message "Backing up GPO before edit." -Color Black -BackColor White
        Backup-GPO -Name $SelectedLGPOName -Server $DC -Path $backupdir -Comment $EditReason
        $policypath="LDAP://$((Get-GPO -Name $SelectedLGPOName -Server $DC).Path)"
        gpme.msc /GPOBJECT: $policypath
        Write-Log -Message "Opened $SelectedLGPOName for editing due to $EditReason" -Component GPOEdit -Type Info
        }
}

$OUEditGPO_Click={
    $EditReason=[Microsoft.VisualBasic.Interaction]::InputBox("Enter a justification for editing.`nThis should be a CRQ or INC.","GPO Edit")
    if($EditReason -ne ''){
        Write-Console -Message "Backing up GPO before edit." -Color Black -BackColor White
        Backup-GPO -Name $TVSelectedNodeText -Server $DC -Path $backupdir -Comment $EditReason
        $policypath="LDAP://$TVSelectedNodeName"
        gpme.msc /GPOBJECT: $policypath
        Write-Log -Message "Opened $TVSelectedNodeText for editing due to $EditReason" -Component GPOEdit -Type Info
        }
}

$BlockInheritance_Click={
    #Block inheritance
    try {
        Set-GPInheritance -IsBlocked Yes -Target $TVSelectedNodeName -Server $DC
        $TVSelectedNode.ImageIndex=7;$TVSelectedNode.SelectedImageIndex=7
        Write-Log -Message "Blocked Inheritance on $TVSelectedNodeName" -Component OUInheritance -Type Info

        # Refresh OU Context Menu
        Invoke-Command $OUTreeView_AfterSelect
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$UnblockInheritance_Click={
    #Unblock inheritance
    try {
        Set-GPInheritance -IsBlocked No -Target $TVSelectedNodeName -Server $DC
        $TVSelectedNode.ImageIndex=3;$TVSelectedNode.SelectedImageIndex=3
        Write-Log -Message "Unblocked Inheritance on $TVSelectedNodeName" -Component OUInheritance -Type Info

        # Refresh OU Context Menu
        Invoke-Command $OUTreeView_AfterSelect
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$GPOEnforce_Click={
    # Enforces the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Enforced Yes -Server $DC
        Write-Log -Message "Enforced $SelectedLGPOName on $TVSelectedNodeName" -Component GPOEnforce -Type Warning

        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        $LGPOdatagridview.Rows[$SelectedLGPOIndex].Selected = $true
        }
     catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$GPOUnenforce_Click={
    # Unenforces the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Enforced No -Server $DC
        Write-Log -Message "Unenforced $SelectedLGPOName on $TVSelectedNodeName" -Component GPOUnenforce -Type Warning

        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        $LGPOdatagridview.Rows[$SelectedLGPOIndex].Selected = $true
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$GPOEnable_Click={
    #Enables GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -LinkEnabled Yes -Server $DC
        Write-Log -Message "Enabled $SelectedLGPOName on $TVSelectedNodeName" -Component GPOEnable -Type Warning

        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        $LGPOdatagridview.Rows[$SelectedLGPOIndex].Selected = $true
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$GPODisable_Click={
    # Disables GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -LinkEnabled No -Server $DC
        Write-Log -Message "Disabled $SelectedLGPOName on $TVSelectedNodeName" -Component GPODisable -Type Warning

        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        $LGPOdatagridview.Rows[$SelectedLGPOIndex].Selected = $true
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$LinkGPO_Click={
    #Form to link GPO to OU
    $gpolinkform=New-Object System.Windows.Forms.Form -Property @{
        text            = "Select a GPO to Link"
        StartPosition   = [Windows.Forms.FormStartPosition]::CenterScreen
        ClientSize      = New-Object System.Drawing.Size(600,700)
        TopMost         = $true
        }
    
    $gpoInstrucLabel = New-Object System.Windows.Forms.Label -Property @{
        Location      =  New-Object System.Drawing.Point(25,10)
        Name          = "InstructionsLabel"
        ClientSize    = New-Object System.Drawing.Size(400,35)
        Font          = $DefaultFont
        Text          = "Select a GPO to link"
        }
    
    $gpodatagrid=New-Object System.Windows.Forms.DataGridView -Property @{
        Location              = New-Object System.Drawing.Point(25,50)
        ClientSize            = New-Object System.Drawing.Size(550,575)
        SelectionMode         = 'FullRowSelect'
        BackgroundColor       = 'WhiteSmoke'
        MultiSelect           = $false
        AllowUserToAddRows    = $false
        AllowUserToDeleteRows = $false
        RowHeadersVisible     = $false
        AllowUserToResizeRows = $false
        AutoSizeColumnsMode   = 'Fill'
        ColumnHeadersVisible  = $true
        ReadOnly              = $true
        ColumnCount           = 1
        Anchor                = 'Left,Right,Top,Bottom'
        }
    $gpodatagrid.Columns[0].Name='Name'
    $AvailPolicies=$Policies.DisplayName | Where-Object {$_ -notin $LinkedOUDataTable.GPO} | Sort-Object
    $AvailPolicies.foreach{$gpodatagrid.Rows.Add($_) | Out-Null}

    $okButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(400,650)
        Size = New-Object System.Drawing.Size(75,25)
        Anchor = 'Bottom,Right'
        Text = 'OK'
        DialogResult = [System.Windows.Forms.DialogResult]::OK
        }
    
    $cancelButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(500,650)
        Size = New-Object System.Drawing.Size(75,25)
        Anchor = 'Bottom,Right'
        Text = 'Cancel'
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        }

    $gpolinkform.Controls.Add($gpoInstrucLabel)
    $gpolinkform.Controls.Add($gpodatagrid)
    $gpolinkform.AcceptButton = $okButton
    $gpolinkform.Controls.Add($okButton)
    $gpolinkform.CancelButton = $cancelButton
    $gpolinkform.Controls.Add($cancelButton)
    $result=$gpolinkform.ShowDialog()

    if($result -eq 'OK'){
        # When select ok check if something is selected
        if($gpodatagrid.SelectedCells){
            # Link GPO to OU
            try {
                New-GPLink -Name $gpodatagrid.SelectedCells.value -Target $TVSelectedNodeName -LinkEnabled No -Server $DC
                Write-Log -Message "Linked $($gpodatagrid.SelectedCells.value) to $TVSelectedNodeName" -Component NewGPOLink -Type Info
            
                # Refresh DataGridView
                Invoke-Command $OUTreeView_AfterSelect
                }
            catch {
                $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
                Write-Console -Message $errormsg -Color White -BackColor Red
                }
            }
        }
}

$DeleteGPOLink_Click={
    # Delete the GPO
    try {
        Remove-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Server $DC
        Write-Log -Message "Deleted $SelectedLGPOName link from $TVSelectedNodeName" -Component GPODelete -Type Error
    
        # Refresh DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$ImportGP_Click={
    $gpodir="$workingdir\Unpack\GPOs" # set GPO Directory
    $wmidir="$workingdir\Unpack\WMIFilters" # Sets the WMI Filter Directory
    $GpoManifest=Import-Clixml -Path "$workingdir\Unpack\GPOManifest.xml" # import GPO Manifest
    [array]$Selected_GPOs=$GpoManifest | Select-Object DisplayName,Description,WmiFilter,Target | Out-GridView -PassThru -Title "Select GPOs to Import"

    if($Selected_GPOs.Count -gt 0) {
        foreach($SelectedGpo in $Selected_GPOs){
            if(Get-GPO -Name $SelectedGpo.DisplayName -Server $DC -ErrorAction SilentlyContinue){
            
                # If the GPO exists ask if you want to replace it
                $ImportAnyway=[Microsoft.VisualBasic.Interaction]::MsgBox("$($SelectedGpo.DisplayName)`nalready exists in your domain. Overwrite it?","YesNo,SystemModal,Exclamation","Import Error!")

                if($ImportAnyway='Yes'){
                    try {
                        $imported_GPO=Import-GPO -BackupGpoName $SelectedGpo.DisplayName -Path $gpodir -TargetName $SelectedGpo.DisplayName -Server $DC -MigrationTable $MigTable # Import the GPO using migration table

                        # Write to log and console
                        Write-Log -Message "Imported GPO: $($imported_GPO.DisplayName) from backup with no WMI Filter" -Component GPOImport -Type Info
                        }
                    catch {
                        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
                        Write-Console -Message $errormsg -Color White -BackColor Red
                        }
                    }
            }else{
            
                if($SelectedGpo.WmiFilter) {
                    # GPO has a WMI Filter
                
                    if($SelectedGpo.WmiFilter -in $WMIDataTable.Name){
                        # WMI Filter Exists in Domain
                    
                        try{
                            # Import GPO
                            $imported_GPO=Import-GPO -BackupGpoName $SelectedGpo.DisplayName -Path $gpodir -TargetName $SelectedGpo.DisplayName -Server $DC -CreateIfNeeded -MigrationTable $MigTable # Import the GPO using migration table
                            Set-GPWmiFilterAssignment -Policy $Imported_GPO -Filter $SelectedGpo.WmiFilter -Server $DC | Out-Null #Apply WMI Filter

                            # Write to log and console
                            Write-Log -Message "Imported GPO: $($imported_GPO.DisplayName) from backup and applied WMI Filter: $($SelectedGpo.WmiFilter)" -Component GPOImport -Type Info
                            }
                        catch {
                            $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
                            Write-Console -Message $errormsg -Color White -BackColor Red
                            }
                    } else {
                        # WMI Filter doesn't exist

                        try{
                            #Create the new filter
                            $filtertobuild="$wmidir\$($SelectedGpo.WmiFilter).xml" | Import-Clixml
                            $expression=$filtertobuild.Filter.split(';') | Where-Object {$_ -like "select*"}
                            New-GPWmiFilter -Name $filtertobuild.Name -Description $filtertobuild.Description -Expression $expression -Server $DC | Out-Null

                            # Write to log and console
                            Write-Log -Message "Imported WMI Filter: $($SelectedGpo.WmiFilter)" -Component WMIFilterImport -Type Info

                            # Import GPO
                            $imported_GPO=Import-GPO -BackupGpoName $SelectedGpo.DisplayName -Path $gpodir -TargetName $SelectedGpo.DisplayName -Server $DC -CreateIfNeeded -MigrationTable $MigTable # Import the GPO using migration table
                            Set-GPWmiFilterAssignment -Policy $Imported_GPO -Filter $SelectedGpo.WmiFilter -Server $DC | Out-Null #Apply WMI Filter

                            # Write to log and console
                            Write-Log -Message "Imported GPO: $($imported_GPO.DisplayName) from backup and applied WMI Filter: $($SelectedGpo.WmiFilter)" -Component GPOImport -Type Info
                            }
                        catch {
                            $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber) Char: $($_.InvocationInfo.OffsetInLine)"
                            Write-Console -Message $errormsg -Color White -BackColor Red
                            }
                        }
                    }
                }
            }
        Update-GPODataTable
        }
}

$ImportWMI_Click={
    $WMIFilters=foreach($filter in Get-ChildItem "$workingdir\Unpack\WMIFilters") {Import-Clixml -Path $filter.FullName} #convert WMIFilters to array
    $WMIFilters.ForEach({$_.Filter=$_.Filter.split(';') | Where-Object {$_ -like "select*"}}) #Convert the Filter to a readable filter
    [array]$Selected_WMIFilters=$WMIFilters | Out-GridView -PassThru -Title "Select Filters to Import" # Show list to user

    if($Selected_WMIFilters.Count -gt 0) {
        foreach($wmifilter in $Selected_WMIFilters){
            if(Get-GPWmiFilter $WMIFilter.Name -Server $DC -ErrorAction SilentlyContinue){
                $result=[Microsoft.VisualBasic.Interaction]::InputBox("$($WMIFilter.Name)`nAlready exists in your domain. Would you like to import under a different name?","Import Error!")
                if( ($result -ne '') -and ($result -ne [string]$WMIFilter.Name) ){
                    try {
                        New-GPWmiFilter -Name $result -Description $wmifilter.Description -Filter $wmifilter.Filter -Server $DC
                        Write-Log -Message "WMI Filter: $result was successfully imported" -Component WMIFilter -Type Info
                        }
                    catch{
                        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
                        Write-Console -Message $errormsg -Color White -BackColor Red
                        }
                }else{
                    try {
                        New-GPWmiFilter -Name $wmifilter.Name -Description $wmifilter.Description -Filter $wmifilter.Filter -Server $DC
                        Write-Log -Message "WMI Filter: $($WMIFilter.Name) was successfully imported" -Component WMIFilter -Type Info
                        }
                    catch {
                        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
                        Write-Console -Message $errormsg -Color White -BackColor Red
                        }
                    }
                }
            }
        Update-WMIDataTable
        }
}

$TopButton_Click={
    #When clicking the top button

    # Move the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Order 1 -Server $DC
        Write-Log -Message "Changed link for $SelectedLGPOName in $TVSelectedNodeName from $SelectedLGPOOrder to 1" -Component LinkOrderChange -Type Info

        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        Invoke-Command $LGPOdatagridview_MouseDown
        $LGPOdatagridview.Rows[0].Selected = $true
        Invoke-Command $LGPOdatagridview_OrderChanged
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$UpButton_Click={
    # When clicking the up button

    # Gather info and calculate
    $new_link=$SelectedLGPOOrder - 1

    Write-Debug "SelectedLGPOOrder: $SelectedLGPOOrder"
    Write-Debug "New Link: $new_link"

    # Move the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Order $new_link -Server $DC
        Write-Log -Message "Changed link for $SelectedLGPOName in $TVSelectedNodeName from $SelectedLGPOOrder to $new_link" -Component LinkOrderChange -Type Info
    
        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        Invoke-Command $LGPOdatagridview_MouseDown
        $LGPOdatagridview.Rows[$($new_link-1)].Selected = $true
        Invoke-Command $LGPOdatagridview_OrderChanged
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber) Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$DownButton_Click={
    # When clicking the up button

    # Gather info and calculate
    $new_link=$SelectedLGPOOrder + 1

    # Move the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Order $new_link -Server $DC
        Write-Log -Message "Changed link for $SelectedLGPOName in $TVSelectedNodeName from $SelectedLGPOOrder to $new_link" -Component LinkOrderChange -Type Info
    
        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        Invoke-Command $LGPOdatagridview_MouseDown
        $LGPOdatagridview.Rows[$($new_link-1)].Selected = $true
        Invoke-Command $LGPOdatagridview_OrderChanged
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$BottomButton_Click={
    # When clicking the up button

    # Move the GPO
    try {
        Set-GPLink -Name $SelectedLGPOName -Target $TVSelectedNodeName -Order $LinkedPolicyCount -Server $DC
        Write-Log -Message "Changed link for $SelectedLGPOName in $TVSelectedNodeName from $SelectedLGPOOrder to $LinkedPolicyCount" -Component LinkOrderChange -Type Info
    
        # Refresh and reselect DataGridView
        Invoke-Command $OUTreeView_AfterSelect
        Invoke-Command $LGPOdatagridview_MouseDown
        $LGPOdatagridview.Rows[$($LinkedPolicyCount-1)].Selected = $true
        Invoke-Command $LGPOdatagridview_OrderChanged
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$ZipImport_Click={
   # Select the backup zip file
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = [Environment]::GetFolderPath('Desktop') 
        Filter           = "zip files|*.zip"
        }
    $result = $FileBrowser.ShowDialog()

    if($result -eq 'OK') {
        try {
            # Extract the file to the unpack directory
            Expand-Archive $FileBrowser.FileName -DestinationPath "$workingdir\unpack" -ErrorAction Stop
    
            # Change Variables and check status
            $ZipImport.Checked = $true
            $FolderImport.Checked = $false
            $global:backupimported=$true
            $ADMXImport.Enabled = $true
            $GPOImport.Enabled = $true
            $WMIImport.Enabled = $true

            Write-Console -Message "Successfully Imported $($FileBrowser.SafeFileName)" -Color Black -BackColor White
            }
        catch{
            $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
            Write-Console -Message $errormsg -Color White -BackColor Red
            }
        }
}

$FolderImport_Click={
    # Select the backup folder
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $result = $FolderBrowser.ShowDialog()

    if($result -eq 'OK') {
        try {
            # Copy Files to unpack directory
            Copy-Item $FolderBrowser.SelectedPath -Destination "$workingdir\unpack"

            # Change Variables and check status
            $ZipImport.Checked = $false
            $FolderImport.Checked = $true
            $global:backupimported=$true
            $ADMXImport.Enabled = $true
            $GPOImport.Enabled = $true
            $WMIImport.Enabled = $true

            Write-Console -Message "Successfully Imported $($FolderBrowser.SelectedPath.Split('\')[-1])" -Color Black -BackColor White
            }
        catch{
            $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
            Write-Console -Message $errormsg -Color White -BackColor Red
            }
        }
}

$ADMXImport_Click={
    # Sets the paths for the ADMX stuff
    $ADMXdir="$workingdir\Unpack\ADMX"
    $BackupDefs="$workingdir\Logs\$($domain)_PolicyDefinitions"

    try {
        # Copy the old stuff then zip
        New-Item $BackupDefs -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
        Copy-Item -Path $policyDefs -Destination $BackupDefs -Recurse -Container
        Compress-Archive -Path $BackupDefs -DestinationPath "$logdir\$($domain.Name)_PolicyDefinitions_$date" -CompressionLevel Optimal
        Write-Log -Message "Current PolicyDefinitions folder was backed up" -Component PolicyDefinitions -Type Info

        # Copy the new stuff
        Copy-Item -Path $ADMXdir\* -Destination $policyDefs -Recurse -Force
        Write-Log -Message "PolicyDefinitions were imported successfully" -Component PolicyDefinitions -Type Info
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$SendRequest_Click={
    # Form to send me an email
    $featureform=New-Object System.Windows.Forms.Form -Property @{
        Text            = "Feature Request Form"
        StartPosition   = [Windows.Forms.FormStartPosition]::CenterScreen
        ClientSize      = New-Object System.Drawing.Size(450,500)
        FormBorderStyle = 'FixedDialog'
        TopMost         = $true
    }
    
    $FeatureInstruc = New-Object System.Windows.Forms.Label -Property @{
        Location      =  New-Object System.Drawing.Point(25,0)
        ClientSize    = New-Object System.Drawing.Size(400,20)
        Font          = $DefaultFont
        Text          = "Enter your information and your request below"
    }
    
    $NameInstruc = New-Object System.Windows.Forms.Label -Property @{
        Location      =  New-Object System.Drawing.Point(25,30)
        ClientSize    = New-Object System.Drawing.Size(400,20)
        Font          = $10ptFont
        Text          = "Enter your name:"
    }
    
    $NameBox=New-Object System.Windows.Forms.TextBox -Property @{
        Location              = New-Object System.Drawing.Point(25,50)
        ClientSize            = New-Object System.Drawing.Size(400,25)
        Multiline             = $false
        Enabled               = $true
        BackColor             = 'white'
    }
    
    $EmailInstruc = New-Object System.Windows.Forms.Label -Property @{
        Location      =  New-Object System.Drawing.Point(25,80)
        ClientSize    = New-Object System.Drawing.Size(400,20)
        Font          = $10ptFont
        Text          = "Enter your email:"
    }
    
    $EmailBox=New-Object System.Windows.Forms.TextBox -Property @{
        Location              = New-Object System.Drawing.Point(25,100)
        ClientSize            = New-Object System.Drawing.Size(400,25)
        Multiline             = $false
        Enabled               = $true
        BackColor             = 'white'
    }
    
    $requestbox=New-Object System.Windows.Forms.TextBox -Property @{
        Location              = New-Object System.Drawing.Point(25,150)
        ClientSize            = New-Object System.Drawing.Size(400,250)
        Multiline             = $true
        AcceptsReturn         = $true
        Enabled               = $true
        ScrollBars            = 'Vertical'
        BackColor             = 'white'
    }
    
    $SendButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(100,425)
        Size = New-Object System.Drawing.Size(75,23)
        Text = 'Send'
        DialogResult = [System.Windows.Forms.DialogResult]::OK
        }
    
    $cancelButton = New-Object System.Windows.Forms.Button -Property @{
        Location = New-Object System.Drawing.Point(275,425)
        Size = New-Object System.Drawing.Size(75,23)
        Text = 'Cancel'
        DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        }

    $featureform.Controls.Add($FeatureInstruc)
    $featureform.Controls.Add($NameInstruc)
    $featureform.Controls.Add($NameBox)
    $featureform.Controls.Add($EmailInstruc)
    $featureform.Controls.Add($EmailBox)
    $featureform.Controls.Add($requestbox)
    $featureform.AcceptButton = $SendButton
    $featureform.Controls.Add($SendButton)
    $featureform.CancelButton = $cancelButton
    $featureform.Controls.Add($cancelButton)
    $result=$featureform.ShowDialog()

    #Send the email with some nice formatting
    if($result -eq 'OK'){
        Send-MailMessage -From $EmailBox.Text -To 'michael.k.calabrese.mil@mail.smil.mil' -Subject 'GPMC-breezy Feature Request' -Body $("Script Version -- $script_Version" + "`n`n" + $requestbox.Text + "`n`n" + "Requested by $($NameBox.Text)") -SmtpServer "smtp.mail.smil.mil"
        }
}

$Inprogress_Click={
    [Microsoft.VisualBasic.Interaction]::MsgBox("Calabrese is working on:`n`n$Inprogress_array","OkOnly,SystemModal,Information","Features in Progress")
}

$DoAction_Click={
}

$TVSaveReport_Click={
    $SRDialogue=New-Object System.Windows.Forms.SaveFileDialog -Property @{
        Filter             = "HTML File|*htm;*.html|XML File|*.xml"
        FileName           = $TVSelectedNodeText
        Title              = "Save GPO Report"
        AddExtension       = $true
        CheckPathExists    = $true
        FilterIndex        = 1
        }
    $result=$SRDialogue.ShowDialog()

    if($result -eq 'OK'){
        if($SRDialogue.FilterIndex -eq 1){ Get-GPOReport -Name $TVSelectedNodeText -ReportType Html -Server $DC | Out-File $SRDialogue.FileName -Force }
        else { Get-GPOReport -Name $TVSelectedNodeText -ReportType Xml -Server $DC | Out-File $SRDialogue.FileName -Force }
        }
}

$DGVSaveReport_Click={
    $SRDialogue=New-Object System.Windows.Forms.SaveFileDialog -Property @{
        Filter             = "HTML File|*htm;*.html|XML File|*.xml"
        FileName           = $SelectedLGPOName
        Title              = "Save GPO Report"
        AddExtension       = $true
        CheckPathExists    = $true
        FilterIndex        = 1
        }
    $result=$SRDialogue.ShowDialog()

    if($result -eq 'OK'){
        if($SRDialogue.FilterIndex -eq 1){ Get-GPOReport -Name $SelectedLGPOName -ReportType Html -Server $DC | Out-File $SRDialogue.FileName -Force }
        else { Get-GPOReport -Name $SelectedLGPOName -ReportType Xml -Server $DC | Out-File $SRDialogue.FileName -Force }
        }
}

$OUTreeView_MouseClick={
    if($_.Button -eq 'Right') {
        $OUTreeView.SelectedNode = $_.Node

        $TVContextMenu.Items.Clear()
        if ($_.Node.ImageIndex -eq 2) {
            $TVContextMenu.Items.Add($ChangeDomainToolStripMenuItem)
            }
        if ($_.Node.Tag -eq 'GPO') {
            $TVContextMenu.Items.Add($OUEditGPOToolStripMenuItem)
            $TVContextMenu.Items.Add($TVSaveReportToolStripMenuItem)
            }
        if ($_.Node.Tag -eq 'OU') {
             $TVContextMenu.Items.Add($LinkGPOToolStripMenuItem)

            if ( (Get-GPInheritance -Target $TVSelectedNodeName -Server $DC).GpoInheritanceBlocked) {
                $TVContextMenu.Items.Add($UnblockInheritanceToolStripMenuItem)
                }
            else {
                $TVContextMenu.Items.Add($BlockInheritanceToolStripMenuItem)
                }
            }
        if ($_.Node.Name -eq 'Group Policy Objects') {
            if ($backupimported) {
                $TVContextMenu.Items.Add($ImportGPToolStripMenuItem)
                }
            }
        if ($_.Node.Name -eq 'WMI Filters') {
            if ($backupimported) {
                $TVContextMenu.Items.Add($ImportWMIToolStripMenuItem)
                }
            }
        If ($TVContextMenu.Items.Count -gt 0) {
            $TVContextMenu.Show($OUTreeView, $_.Location)
            }
        }
}

$IGPODataGridView_CellMouseDown={      
    if($_.Button -eq 'Right') {
        $IGPOdatagridview.ClearSelection()
        $IGPOdatagridview.Rows[$_.RowIndex].Selected = $true
        }
}

$LGPODataGridView_CellMouseDown={
    $LGPODataGridView.Rows[$_.RowIndex].Selected=$true

    Write-Debug "Linked Policy Count: $LinkedPolicyCount"

    if($LinkedPolicyCount -eq 0) {
        #Disable all buttons
        $top_button.Enabled = $false
        $up_button.Enabled = $false
        $down_button.Enabled = $false
        $bottom_button.Enabled = $false
    }else{
        #Set the selectedLGPOName variable for use later
        $global:SelectedLGPOName=$LGPODataGridView.SelectedCells[1].Value
        [int]$global:SelectedLGPOIndex=($LGPODataGridView.SelectedCells[0].Value - 1)
        [int]$global:SelectedLGPOOrder=$SelectedLGPOIndex+1

        Write-Debug "Selected GPO Name: $SelectedLGPOName"
        Write-Debug "Selected GPO Index: $SelectedLGPOIndex"
        Write-Debug "Selected GPO Order: $SelectedLGPOOrder"

        if($SelectedLGPOIndex -gt 0) {
            #Enable the top buttons
            $top_button.Enabled = $true
            $up_button.Enabled = $true
        }else{
            #Disable the top buttons
            $top_button.Enabled = $false
            $up_button.Enabled = $false
            }

        if($SelectedLGPOIndex -lt ($LinkedPolicyCount - 1) ) {
            #Enable the bottom buttons
            $down_button.Enabled = $true
            $bottom_button.Enabled = $true
        }else{
            #Disable the bottom buttons
            $down_button.Enabled = $false
            $bottom_button.Enabled = $false
            }
        }
}

$LGPOdatagridview_OrderChanged={
    #Set the selectedLGPOName variable for use later
    $global:SelectedLGPOName=$LGPODataGridView.SelectedCells[1].Value
    [int]$global:SelectedLGPOIndex=($LGPODataGridView.SelectedCells[0].Value - 1)
    [int]$global:SelectedLGPOOrder=$SelectedLGPOIndex+1

    Write-Debug "Selected GPO Name: $SelectedLGPOName"
    Write-Debug "Selected GPO Index: $SelectedLGPOIndex"
    Write-Debug "Selected GPO Order: $SelectedLGPOOrder"

    if($SelectedLGPOIndex -gt 0) {
        #Enable the top buttons
        $top_button.Enabled = $true
        $up_button.Enabled = $true
    }else{
        #Disable the top buttons
        $top_button.Enabled = $false
        $up_button.Enabled = $false
        }

    if($SelectedLGPOIndex -lt ($LinkedPolicyCount - 1) ) {
        #Enable the bottom buttons
        $down_button.Enabled = $true
        $bottom_button.Enabled = $true
    }else{
        #Disable the bottom buttons
        $down_button.Enabled = $false
        $bottom_button.Enabled = $false
        }
}

$LGPOdatagridview_MouseDown = {
    $LGPODataGridView.ClearSelection()
    $LGPOContextMenu.Items.Clear()
}

$GPODataGridView_MouseClick={      
    if($_.Button -eq 'Right') {
        $GPODataGridView.ClearSelection()
        $GPODataGridView.Rows[$_.RowIndex].Selected = $true
        }
}

$WMIDataGridView_MouseClick={  
    if($_.Button -eq 'Right') {
        $WMIDataGridView.ClearSelection()
        $WMIDataGridView.Rows[$_.RowIndex].Selected = $true
        }
}

#endregion TooManyClicks

#region ContextMenuItems

# ContextMenu ContextMenuStrips
$TVContextMenu = New-Object System.Windows.Forms.ContextMenuStrip

$LGPOContextMenu = New-Object System.Windows.Forms.ContextMenuStrip

# ContextMenu ToolStripMenuItems
$ChangeDomainToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$ChangeDomainToolStripMenuItem.Text = "Change Domain..."
$ChangeDomainToolStripMenuItem.Add_Click($ChangeDomainToolStripMenuItem_Click)

$OUEditGPOToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$OUEditGPOToolStripMenuItem.Text = "Edit..."
$OUEditGPOToolStripMenuItem.Add_Click($OUEditGPO_Click)

$DGVEditGPOToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$DGVEditGPOToolStripMenuItem.Text = "Edit"
$DGVEditGPOToolStripMenuItem.Add_Click($DGVEditGPO_Click)

$BlockInheritanceToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$BlockInheritanceToolStripMenuItem.Text    = "Block Inheritance"
$BlockInheritanceToolStripMenuItem.Checked = $false
$BlockInheritanceToolStripMenuItem.Add_Click($BlockInheritance_Click)

$UnblockInheritanceToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$UnblockInheritanceToolStripMenuItem.Text    = "Block Inheritance"
$UnblockInheritanceToolStripMenuItem.Checked = $true
$UnblockInheritanceToolStripMenuItem.Add_Click($UnblockInheritance_Click)

$GPOEnforceToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$GPOEnforceToolStripMenuItem.Text    = "Enforced"
$GPOEnforceToolStripMenuItem.Checked = $false
$GPOEnforceToolStripMenuItem.Add_Click($GPOEnforce_Click)

$GPOUnenforceToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$GPOUnenforceToolStripMenuItem.Text    = "Enforced"
$GPOUnenforceToolStripMenuItem.Checked = $true
$GPOUnenforceToolStripMenuItem.Add_Click($GPOUnenforce_Click)

$GPOEnableToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$GPOEnableToolStripMenuItem.Text    = "Link Enabled"
$GPOEnableToolStripMenuItem.Checked = $false
$GPOEnableToolStripMenuItem.Add_Click($GPOEnable_Click)

$GPODisableToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$GPODisableToolStripMenuItem.Text    = "Link Enabled"
$GPODisableToolStripMenuItem.Checked = $true
$GPODisableToolStripMenuItem.Add_Click($GPODisable_Click)

$LinkGPOToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$LinkGPOToolStripMenuItem.Text = "Link an Existing GPO..."
$LinkGPOToolStripMenuItem.Add_Click($LinkGPO_Click)

$DeleteGPOLinkToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$DeleteGPOLinkToolStripMenuItem.Text = "Delete"
$DeleteGPOLinkToolStripMenuItem.Add_Click($DeleteGPOLink_Click)

$ImportGPToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$ImportGPToolStripMenuItem.Text = "Import GPO from Backup"
$ImportGPToolStripMenuItem.Add_Click($ImportGP_Click)

$ImportWMIToolStripMenuItem = New-Object 'System.Windows.Forms.ToolStripMenuItem'
$ImportWMIToolStripMenuItem.Text = "Import WMI Filter from Backup"
$ImportWMIToolStripMenuItem.Add_Click($ImportWMI_Click)

$DGVSaveReportToolStripMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$DGVSaveReportToolStripMenuItem.Text = "Save Report..."
$DGVSaveReportToolStripMenuItem.Add_Click($DGVSaveReport_Click)

$TVSaveReportToolStripMenuItem = New-Object System.Windows.Forms.ToolStripMenuItem
$TVSaveReportToolStripMenuItem.Text = "Save Report..."
$TVSaveReportToolStripMenuItem.Add_Click($TVSaveReport_Click)
#endregion contextmenus

#region Event Script Blocks
$form_Shown={
    #Build treeview when form is shown
    try {
        Update-Domain -LocalDomain
        }
    catch {
        $errormsg= "$($_.Exception.Message) At Line: $($_.InvocationInfo.ScriptLineNumber)  Char: $($_.InvocationInfo.OffsetInLine)"
        Write-Console -Message $errormsg -Color White -BackColor Red
        }
}

$OUTreeView_BeforeExpand=[System.Windows.Forms.TreeViewCancelEventHandler]{
    #Get next level for current node
    If ($_.Node.Level -eq 1 -and $RootOU) {
        $_.Node.Nodes.Clear()
        $RootNode = Add-Node -dname $RootOU -name $RootOU.Split(',')[0].Substring(3) -RootNode $_.Node
        $RootNode.Expand()
        }
    elseIf ($_.Node.Text -eq 'Group Policy Objects') {
        $_.Node.Nodes.Clear()
        foreach ($policy in $Policies) {
            Add-Node -dname "CN={$($policy.Id)},CN=Policies,$($domain.SystemsContainer)" -name $policy.DisplayName -Type GroupPolicyObject -HasChildren $false -RootNode $_.Node
            }
        }
    elseIf ($_.Node.Text -eq 'WMI Filters') {
        $_.Node.Nodes.Clear()
        foreach ($filter in $WMIFilters) {
            Add-Node -dname $filter.Name -name $filter.Name -Type WMIFilter -HasChildren $false -RootNode $_.Node
            }
        }
    elseIf ($_.Node.Level -ne 0) {
        Get-NextLevel -RootNode $_.Node
        }
}

$OUTreeView_AfterSelect={
    # When the TreeView "OU Selector" is clicked
    [String]$Global:TVSelectedNodeText=$OUTreeView.SelectedNode.Text
    [String]$Global:TVSelectedNodeName=$OUTreeView.SelectedNode.Name
    [String]$Global:TVSelectedNodeTag=$OUTreeView.SelectedNode.Tag
    $Global:TVSelectedNode=$OUTreeView.SelectedNode

    Write-Debug "OUTreeView_AfterSelect"
    Write-Debug "    TVSelectedNodeText: $TVSelectedNodeText"
    Write-Debug "    TVSelectedNodeName: $TVSelectedNodeName"
    Write-Debug "    TVSelectedNodeTag: $TVSelectedNodeTag"

    Invoke-Command $TabControlSelected

    # Remove TabControl
    $Vsplitcontainer.Panel2.Controls.Clear()

    # Set the label to the right to selected item name
    $selectionLabel.Text = $TVSelectedNodeText
    $VSplitContainer.Panel2.Controls.Add($selectionLabel)

    if($TVSelectedNodeText -eq 'Group Policy Objects'){
        # When you click on Group Policy Objects

        # Set the label to the right to selected item name
        $selectionLabel.Text = "Group Policy Objects in $($domain.DNSRoot)"
        
        # Attach GPOTabControl to Vsplitcontainer
        $Vsplitcontainer.Panel2.Controls.Add($GPOTabControl)

    }elseif($TVSelectedNodeText -eq 'WMI Filters'){
        # When you click on WMI Filters

        # Set the label to the right to selected item name
        $selectionLabel.Text = $selectionLabel.Text = "WMI Filters in $($domain.DNSRoot)"

        # Attach WMITabControl to Vsplitcontainer
        $Vsplitcontainer.Panel2.Controls.Add($WMITabControl)

    }elseif($TVSelectedNodeTag -eq 'OU'){
        # When you click on OUs

        # Set the label to the right to selected item name
        $selectionLabel.Text = $TVSelectedNodeText

        # Attach OUTabControl to Vsplitcontainer
        $Vsplitcontainer.Panel2.Controls.Add($OUtabcontrol)

        # Linked GPOs
        $LinkedOUPolicies=Get-LinkedOUPolicies -OU $TVSelectedNodeName
        $script:LinkedOUDataTable=New-Object System.Data.DataTable
        ConvertTo-DataTable -InputObject $LinkedOUPolicies -Table $LinkedOUDataTable
        Update-DataGridView -DataGridView $LGPOdatagridview -Item $LinkedOUDataTable
        [int]$global:LinkedPolicyCount=$LGPOdatagridview.Rows.Count # how many policies are in the OU

        # Inherited GPOs
        $InheritedOUPolicies=Get-InheritedOUPolicies -OU $TVSelectedNodeName
        $InheritedOUDataTable=New-Object System.Data.DataTable
        ConvertTo-DataTable -InputObject $InheritedOUPolicies -Table $InheritedOUDataTable
        Update-DataGridView -DataGridView $IGPOdatagridview -Item $InheritedOUDataTable

        if($LinkedPolicyCount -lt 2) {
            #Disable all buttons
            $top_button.Enabled = $false
            $up_button.Enabled = $false
            $down_button.Enabled = $false
            $bottom_button.Enabled = $false
        }else{
            #Enable the bottom buttons
            $down_button.Enabled = $true
            $bottom_button.Enabled = $true
            }

    }elseif($TVSelectedNodeTag -eq 'GPO'){
        # If you click GPO shortcut or GPO

        # Set the label to the right to selected item name
        $selectionLabel.Text = $TVSelectedNodeText

        Invoke-Command $SelectedPolicyTabControl_IndexChanged

        # Attach SelectedPolicyTabControl to Vsplitcontainer
        $Vsplitcontainer.Panel2.Controls.Add($SelectedPolicyTabControl)
    }elseif($TVSelectedNodeTag -eq 'WMI'){
        # If you click WMI Filter

        # Set the label to the right to selected item name
        $selectionLabel.Text = $TVSelectedNodeText
    }elseif($TVSelectedNodeTag -eq 'Root'){
        # If you click the root node

        # Set the label to the right to selected item name
        $selectionLabel.Text = "Welcome to GPMC-breezy"

        # Attach SelectedPolicyTabControl to Vsplitcontainer
        $Vsplitcontainer.Panel2.Controls.Add($Welcometabcontrol)
	}else{
        Write-Console -Message "Clicking here doesn't work, dude" -Color White -BackColor Red
        }
    $VSplitContainer.Panel2.Controls.Add($selectionLabel)
}

$SelectedPolicyTabControl_IndexChanged={
    Write-Debug "SelectedPolicyTabControl_IndexChanged"
    $form.Cursor = 'WaitCursor'
    Switch($SelectedPolicyTabControl.SelectedIndex){

        0 { # Selecting the scope tab
            
            #gather info and link to datagridview
            Get-PolicyLinks -GPO $TVSelectedNodeText

            #gather security filter info
            Get-PolicyACL

            # Gather GPO info and populate
            $script:scopeGPO=Get-GPO -Name $TVSelectedNodeText -Server $DC
            $scopeWMIDropDown.Items.Clear()
            if($scopeGPO.wmifilter.Name -eq $null){
                $scopeWMIDropDown.Items.Add("<none>")
                }
            else{
                $scopeWMIDropDown.Items.Add($scopeGPO.wmifilter.Name)
                }
            $scopeWMIDropDown.SelectedIndex=0
            $scopeWMIDropDown.Add_DropDown($scopeWMIDropDown_dropdown)
            }
        
        1 { # Selecting the Details Tab
            $res=Get-GPO $TVSelectedNodeText -Server $DC
            $DTDomainres.Text = $res.DomainName
            $DTOwnerres.Text = "$($res.Owner.split('\')[-1]) ($($res.Owner))"
            $DTCreatedres.Text = "$($res.CreationTime.ToShortDateString()) $($res.CreationTime.ToLongTimeString())"
            $DTModifiedres.Text = "$($res.ModificationTime.ToShortDateString()) $($res.ModificationTime.ToLongTimeString())"
            $DTUserVerres.Text = "$($res.User.DSVersion) (AD), $($res.User.SysvolVersion) (SYSVOL)"
            $DTComputerVerres.Text = "$($res.Computer.DSVersion) (AD), $($res.Computer.SysvolVersion) (SYSVOL)"
            $DTUniqueIDres.Text = "{$($res.Id)}"
            $DTCommentres.Text = $res.Description

            Switch($res.GpoStatus) {
                AllSettingsDisabled       {$DTGPOStatusres.SelectedIndex=0}
                ComputerSettingsDisabled  {$DTGPOStatusres.SelectedIndex=1}
                AllSettingsEnabled        {$DTGPOStatusres.SelectedIndex=2}
                UserSettingsDisabled      {$DTGPOStatusres.SelectedIndex=3}
                }
            }
        
        2 { # Selecting the Settings Tab
            if($WebBrowser.Name -ne $TVSelectedNodeText){
                #if the document is already populated, open a new one
                    $WebBrowser.Name = $TVSelectedNodeText
                    
                    #write generating report and run a gporeport
                    $WebBrowser.Navigate("about:blank")
                    $WebBrowser.Document.Write("Generating Report...")
                    $gporeport=Get-GPOReport -ReportType Html -Name $TVSelectedNodeText -Server $DC
                    #$WebBrowser.Document.OpenNew($true)
                    $WebBrowser.DocumentText = $gporeport
                    }
                }
            }
        $form.Cursor = 'Default'
}

$DTGPOStatusres_IndexChanged={
    Write-Debug "DTGPOStatusres_IndexChanged"

    Switch ($DTGPOStatusres.SelectedIndex) {
        0    { (Get-GPO $TVSelectedNodeText -Server $DC).GpoStatus = "AllSettingsDisabled" }
        1    { (Get-GPO $TVSelectedNodeText -Server $DC).GpoStatus = "ComputerSettingsDisabled" }
        2    { (Get-GPO $TVSelectedNodeText -Server $DC).GpoStatus = "AllSettingsEnabled" }
        3    { (Get-GPO $TVSelectedNodeText -Server $DC).GpoStatus = "UserSettingsDisabled" }
    }
}

$TabControlSelected={
    Write-Debug "TabControlSelected"

    $OUtabcontrol.Size = $script:tabsize
    $GPOTabControl.Size = $script:tabsize
    $WMITabControl.Size = $script:tabsize
    $SelectedPolicyTabControl.Size = $script:tabsize
}

$scopeWMIDropDown_dropdown={
    $Script:scopeWMIDropDown.Items.Clear()
    $Script:scopeWMIDropDown.Items.Add("<none>")
    foreach($Filter in $WMIFilters){
        [Void]$Script:scopeWMIDropDown.Items.Add($Filter.Name)
        }
    if($scopeGPO.WmiFilter.Name -eq $null){ $Script:scopeWMIDropDown.SelectedIndex=0 }
    else{ $Script:scopeWMIDropDown.SelectedIndex=$scopeWMIDropDown.Items.IndexOf($scopeGPO.WmiFilter.Name) }
}

$LGPODataGridView_CellContextMenuStripNeeded={
    if($LinkedPolicyCount -gt 0) {
        $LGPOContextMenu.Items.Add($DGVEditGPOToolStripMenuItem) # Edit GPO button

        # Enforce Button
        if($LGPOdatagridview.SelectedCells[2].Value -eq 'True'){ $LGPOContextMenu.Items.Add($GPOUnenforceToolStripMenuItem) }
        else{ $LGPOContextMenu.Items.Add($GPOEnforceToolStripMenuItem) }

        # Enable Button
        if($LGPOdatagridview.SelectedCells[3].Value -eq 'True'){ $LGPOContextMenu.Items.Add($GPODisableToolStripMenuItem) }
        else{ $LGPOContextMenu.Items.Add($GPOEnableToolStripMenuItem) }

        $LGPOContextMenu.Items.Add("-") 

        $LGPOContextMenu.Items.Add($DGVSaveReportToolStripMenuItem) # Save Report

        $LGPOContextMenu.Items.Add("-")

        $LGPOContextMenu.Items.Add($DeleteGPOLinkToolStripMenuItem) # Delete GPO Link
        }
}
#endregion Event Script Blocks

#region MenuStrip

# Build menu controls
$MainMenu = New-Object System.Windows.Forms.MenuStrip
#$MenuToolStrip = New-Object System.Windows.Forms.ToolStrip
$FileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("File")
$ActionMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Action")
$ImportMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Import")
$RequestMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Request")

# Build Submenu controls
$DoAction = New-Object System.Windows.Forms.ToolStripMenuItem("Do Action")
$DoAction.Add_Click($DoAction_Click)

$ZipImport = New-Object System.Windows.Forms.ToolStripMenuItem("Zip Backup")
$ZipImport.Add_Click($ZipImport_Click)

$FolderImport = New-Object System.Windows.Forms.ToolStripMenuItem("Folder Backup")
$FolderImport.Add_Click($FolderImport_Click)

$ADMXImport = New-Object System.Windows.Forms.ToolStripMenuItem("ADMX Files")
$ADMXImport.Enabled = $false
$ADMXImport.Add_Click($ADMXImport_Click)

$GPOImport = New-Object System.Windows.Forms.ToolStripMenuItem("Import GPO")
$GPOImport.Enabled = $false
$GPOImport.Add_Click($ImportWMI_Click)

$WMIImport = New-Object System.Windows.Forms.ToolStripMenuItem("Import WMI")
$WMIImport.Enabled = $false
$WMIImport.Add_Click($ImportGP_Click)

$SendRequest = New-Object System.Windows.Forms.ToolStripMenuItem("Send Request")
$SendRequest.Add_Click($SendRequest_click)

$Inprogress = New-Object System.Windows.Forms.ToolStripMenuItem("In Progress")
$Inprogress.Add_Click($Inprogress_Click)

# Add menu controls
#$form.Controls.Add($MenuToolStrip)
[Void]$MainMenu.Items.Add($FileMenu)

[Void]$MainMenu.Items.Add($ActionMenu)
[Void]$ActionMenu.DropDownItems.Add($DoAction)

[Void]$MainMenu.Items.Add($ImportMenu)
[Void]$ImportMenu.DropDownItems.Add($ZipImport)
[Void]$ImportMenu.DropDownItems.Add($FolderImport)
[Void]$ImportMenu.DropDownItems.Add("-")
[Void]$ImportMenu.DropDownItems.Add($ADMXImport)
[Void]$ImportMenu.DropDownItems.Add($GPOImport)
[Void]$ImportMenu.DropDownItems.Add($WMIImport)

[Void]$MainMenu.Items.Add($RequestMenu)
[Void]$RequestMenu.DropDownItems.Add($Inprogress)
[Void]$RequestMenu.DropDownItems.Add($SendRequest)

#endregion MenuStrip

# Form Objects
$Form = New-Object System.Windows.Forms.Form -Property @{
    Font               = $DefaultFont
    StartPosition      = [Windows.Forms.FormStartPosition]::CenterScreen
    ClientSize         = New-Object System.Drawing.Size(1800,900)
    Text               = "GPMC-breezy, a faster way to manage GPOs"
    AutoScale          = $true
    AutoScaleMode      = 'DPI'
    Icon               = [System.Drawing.Icon]::ExtractAssociatedIcon('C:\Windows\System32\GPOAdmin.dll')
    }
$form.Add_Shown($form_Shown)
$form.Controls.Add($mainmenu)
$tabsize=New-Object System.Drawing.Size(1395,675)

# First split container that puts the status box at the bottom
$HSplitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{
    Font               = $DefaultFont
    Size               = New-Object System.Drawing.Size(1800,850)
    Location           = New-Object System.Drawing.Point(0,50)
    Anchor             = 'Top,Bottom,Left,Right'
    Margin             = '4,4,4,4'
    Orientation        = 'Horizontal'
    SplitterDistance   = 700
    SplitterWidth      = 5
}
$Form.Controls.Add($HSplitContainer)

# Status box that shows messages and history
$statusbox = New-Object System.Windows.Forms.RichTextBox -Property @{
    Font               = New-Object System.Drawing.Font("Calibri",15,0,3,0)
    Dock               = 'Fill'
    BackColor          = 'White'
    ScrollBars         = 'Vertical'
    ReadOnly           = $true
    Multiline          = $true
    WordWrap           = $false
    }
$HSplitContainer.panel2.Controls.Add($statusbox)

# Split containter that puts the OUTreeView across from the tab control
$VSplitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{
    Font               = $DefaultFont
    Size               = New-Object System.Drawing.Size(1800,700)
    Location           = New-Object System.Drawing.Point(0,0)
    SplitterDistance   = 400
    Dock               = 'Fill'
    Margin             = '4,4,4,4'
    Orientation        = 'Vertical'
    SplitterWidth      = 5
    TabIndex           = 0 
}
$HSplitContainer.panel1.Controls.Add($VSplitContainer)

# OU/GPO selector menu
$OUTreeView = New-Object System.Windows.Forms.TreeView -Property @{
    Font                = $DefaultFont
    Name                = "OU TreeView"
    Dock                = 'Fill'  
    ImageIndex          = 1
    SelectedImageIndex  = 1
    TabIndex            = 1
    ImageList           = $imagelist
    Sorted              = $false
    Scrollable          = $true
    HideSelection       = $false
    }
$OUTreeView.Add_NodeMouseClick($OUTreeView_MouseClick)
$OUTreeView.Add_BeforeExpand($OUTreeView_BeforeExpand)
$OUTreeView.add_AfterSelect($OUTreeView_AfterSelect)
$VSplitContainer.Panel1.Controls.Add($OUTreeView)

$OUTreeViewTreeNode1 = New-Object 'System.Windows.Forms.TreeNode' -Property @{
    Text               = "Group Policy Management"
    Tag                = "root"
    ImageIndex         = 1
    SelectedImageIndex = 1
}

$GPO_Node = New-Object System.Windows.Forms.TreeNode -Property @{
    Text               = "Group Policy Objects"
    ImageIndex         = 0
    SelectedImageIndex = 0
    }

$WMI_Node = New-Object System.Windows.Forms.TreeNode -Property @{
    Text               = "WMI Filters"
    ImageIndex         = 0
    SelectedImageIndex = 0
}  

$selectionLabel = New-Object System.Windows.Forms.Label -Property @{
    Font               = New-Object System.Drawing.Font("Calibri",11,1,3,0)
    Location           = New-Object System.Drawing.Point(0,0)
    Size               = New-Object System.Drawing.Size(1000,25)
    Text               = 'Welcome to GPMC-Breezy'
    }
$VSplitContainer.Panel2.Controls.Add($selectionLabel)

#region WelcomeTab
$Welcometabcontrol = New-Object System.Windows.Forms.TabControl -Property @{
    Font               = $DefaultFont
    Size               = New-Object System.Drawing.Size($tabsize)
    Location           = New-Object System.Drawing.Point(0,25)
    Anchor             = 'top,bottom,left,right'
    Margin             = '4, 4, 4, 4'
    SelectedIndex      = 0
    TabIndex           = 0
    }
$Welcometabcontrol.Add_resize{$script:tabsize=$OUtabcontrol.Size}
$VSplitContainer.Panel2.Controls.Add($Welcometabcontrol)

    # Read Me tab and controls
    $ReadMeTab = New-Object System.Windows.Forms.TabPage -Property @{
        Font               = $DefaultFont
        Size               = New-Object System.Drawing.Size(1387,670)
        Location           = New-Object System.Drawing.Point(4, 26)
        UseVisualStyleBackColor = $true
        Padding            = '3, 3, 3, 3'
        Margin             = '4, 4, 4, 4'
        Text               = 'Read Me'
        TabIndex           = 0
        }
    $Welcometabcontrol.Controls.Add($ReadMeTab)

    $readmetextbox = New-Object System.Windows.Forms.RichTextBox -Property @{
        BackColor          = 'White'
        Dock               = 'Fill'
        ReadOnly           = $true
        }
    $readmetextbox.LoadFile("$workingdir\lib\RTF\ReadMe.rtf")
    $ReadMeTab.Controls.Add($readmetextbox)
    # End Read Me tab and controls

    # How-To tab and controls
    $HowToTab = New-Object System.Windows.Forms.TabPage -Property @{
        Font               = $DefaultFont
        Size               = New-Object System.Drawing.Size(1387,670)
        Location           = New-Object System.Drawing.Point(4, 26)
        UseVisualStyleBackColor = $true
        Padding            = '3, 3, 3, 3'
        Margin             = '4, 4, 4, 4'
        Text               = 'How-To'
        TabIndex           = 1
        }
    $Welcometabcontrol.Controls.Add($HowToTab)

    $HowTotextbox = New-Object System.Windows.Forms.RichTextBox -Property @{
        BackColor          = 'White'
        Dock               = 'Fill'
        ReadOnly           = $true
        }
    $HowTotextbox.LoadFile("$workingdir\lib\RTF\HowTo.rtf")
    $HowToTab.Controls.Add($HowTotextbox)
    # End How-To tab and controls

#endregion WelcomeTab

#region OUTabs
$OUtabcontrol = New-Object System.Windows.Forms.TabControl -Property @{
    Font               = $DefaultFont
    Size               = $tabsize
    Location           = New-Object System.Drawing.Point(0,25)
    Anchor             = 'top,bottom,left,right'
    Margin             = '4, 4, 4, 4'
    SelectedIndex      = 0
    TabIndex           = 0
    }
$OUtabcontrol.Add_Selected($TabControlSelected)
$OUtabcontrol.Add_resize{$script:tabsize=$OUtabcontrol.Size}

    # Linked GPO tab and controls
    $LinkedGPOTab = New-Object System.Windows.Forms.TabPage -Property @{
        Font               = $DefaultFont
        Size               = New-Object System.Drawing.Size(1387,670)
        Location           = New-Object System.Drawing.Point(4, 26)
        Text = 'Linked Group Policy Objects'
        UseVisualStyleBackColor = $True
        Padding = '3, 3, 3, 3'
        Margin = '4, 4, 4, 4'
        TabIndex = 0
        }
    $OUtabcontrol.Controls.Add($LinkedGPOTab)

    $LGPOdatagridview = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        Size                        = New-Object System.Drawing.Size(1337,670)
        Location                    = New-Object System.Drawing.Point(50,0)
        Anchor                      = 'top,bottom,left,right'
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
    }
    $LGPOdatagridview.Add_CellMouseDown($LGPODataGridView_CellMouseDown)
    $LGPOdatagridview.Add_MouseDown($LGPOdatagridview_MouseDown)
    $LGPODataGridView.ContextMenuStrip=$LGPOContextMenu
    $LGPODataGridView.Add_CellContextMenuStripNeeded($LGPODataGridView_CellContextMenuStripNeeded)
    $LinkedGPOTab.Controls.Add($LGPOdatagridview)

    $top_button = New-Object System.Windows.Forms.Button -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",14,1,3,0)
        Location           = New-Object System.Drawing.Point(5,5)
        ClientSize         = New-Object System.Drawing.Size(40,40)
        Text               = [char]::ConvertFromUtf32(0x21C8)
        Enabled            = $false
    }
    $top_button.Add_Click($TopButton_Click)
    $LinkedGPOTab.Controls.Add($top_button)


    $up_button = New-Object System.Windows.Forms.Button -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",14,1,3,0)
        Location           = New-Object System.Drawing.Point(5,50)
        ClientSize         = New-Object System.Drawing.Size(40,40)
        Text               = [char]::ConvertFromUtf32(0x2191)       
        Enabled            = $false
    }
    $up_button.Add_Click($UpButton_Click)
    $LinkedGPOTab.Controls.Add($up_button)


    $down_button = New-Object System.Windows.Forms.Button -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",14,1,3,0)
        Location           = New-Object System.Drawing.Point(5,95)
        ClientSize         = New-Object System.Drawing.Size(40,40)
        Text               = [char]::ConvertFromUtf32(0x2193)
        Enabled            = $false
    }
    $down_button.Add_Click($DownButton_Click)
    $LinkedGPOTab.Controls.Add($down_button)


    $bottom_button = New-Object System.Windows.Forms.Button -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",14,1,3,0)
        Location   = New-Object System.Drawing.Point(5,140)
        ClientSize = New-Object System.Drawing.Size(40,40)
        Text       = [char]::ConvertFromUtf32(0x21CA)
        Enabled    = $false
    }
    $bottom_button.Add_Click($BottomButton_Click)
    $LinkedGPOTab.Controls.Add($bottom_button)
    # End Linked GPO tab and controls

    # InheritedGPO tab and controls
    $InheritedGPOTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        Text = 'Group Policy Inheritance'
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Name = 'tabpage2'
        Padding = '3, 3, 3, 3'
        TabIndex = 1
        }
    $OUtabcontrol.Controls.Add($InheritedGPOTab)

    $IGPOdatagridview = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        Dock                        = 'Fill'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
    }
    $IGPOdatagridview.Add_CellMouseDown($IGPODataGridView_CellMouseDown)
    $InheritedGPOTab.Controls.Add($IGPOdatagridview)
    # End InheritedGPO tab and controls

    # Delegation tab and controls
    $OUDelegationTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 1
        Text = 'Delegation'
        }
    $OUtabcontrol.Controls.Add($OUDelegationTab)
    # End Delegation tab and controls

#endregion OUTabs

#region GPOTabs
$GPOTabControl = New-Object System.Windows.Forms.TabControl -Property @{
    Font               = $DefaultFont
    Size               = $tabsize
    Location           = New-Object System.Drawing.Point(0,25)
    Anchor             = 'top,bottom,left,right'
    Margin             = '4, 4, 4, 4'
    SelectedIndex      = 0
    TabIndex           = 0
    }
$GPOTabControl.Add_Selected($TabControlSelected)
$GPOTabControl.Add_resize{$script:tabsize=$GPOTabControl.Size}

# Contents tab and controls
    $GPOContentsTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 0
        Text = 'Contents'
        }
    $GPOTabControl.Controls.Add($GPOContentsTab)

    $GPODataGridView = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        Dock                        = 'Fill'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
    }
    $GPODataGridView.Add_CellMouseClick($GPODataGridView_MouseClick)
    $GPOContentsTab.Controls.Add($GPODataGridView)
    # End Contents tab and controls

    # Delegation tab and controls
    $GPODelegationTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 1
        Text = 'Delegation'
        }
    $GPOTabControl.Controls.Add($GPODelegationTab)
    # End Delegation tab and controls

#endregion GPOTab

#region WMITabs
$WMITabControl = New-Object System.Windows.Forms.TabControl -Property @{
    Font               = $DefaultFont
    Size               = $tabsize
    Location           = New-Object System.Drawing.Point(0,25)
    Anchor             = 'top,bottom,left,right'
    Margin             = '4, 4, 4, 4'
    SelectedIndex      = 0
    TabIndex           = 0
    }
$WMITabControl.Add_Selected($TabControlSelected)
$WMITabControl.Add_resize{$script:tabsize=$WMITabControl.Size}

# Contents tab and controls
    $WMIContentsTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 0
        Text = 'Contents'
        }
    $WMITabControl.Controls.Add($WMIContentsTab)

    $WMIDataGridView = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        Dock                        = 'Fill'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
    }
    $WMIDataGridView.Add_CellMouseClick($WMIDataGridView_MouseClick)
    $WMIContentsTab.Controls.Add($WMIDataGridView)
    # End Contents tab and controls

    # Delegation tab and controls
    $WMIDelegationTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 1
        Text = 'Delegation'
        }
    $WMITabControl.Controls.Add($WMIDelegationTab)
    # End Delegation tab and controls

#endregion GPOTab

#region SelectedPolicyTabs
$SelectedPolicyTabControl = New-Object System.Windows.Forms.TabControl -Property @{
    Font               = $DefaultFont
    Size               = $tabsize
    Location           = New-Object System.Drawing.Point(0,25)
    Anchor             = 'top,bottom,left,right'
    Margin             = '4, 4, 4, 4'
    SelectedIndex      = 0
    TabIndex           = 0
    }
$SelectedPolicyTabControl.Add_Selected($TabControlSelected)
$SelectedPolicyTabControl.Add_resize{$script:tabsize=$SelectedPolicyTabControl.Size}
$SelectedPolicyTabControl.Add_SelectedIndexChanged($SelectedPolicyTabControl_IndexChanged)

    # Scope tab and controls
    $ScopeTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 0
        Text = 'Scope'
        }
    $SelectedPolicyTabControl.Controls.Add($ScopeTab)

    $WMISplit = New-Object System.Windows.Forms.SplitContainer -Property @{
        Font               = $DefaultFont
        Dock               = 'Fill'
        Margin             = '4,4,4,4'
        Orientation        = 'Horizontal'
        BackColor          = 'LightGray'
        TabIndex           = 0
        FixedPanel         = 'None'
        }
    $ScopeTab.Controls.Add($WMISplit)

    # have to resize the stuff after it's created because Dock 'Fill'
    $WMISplit.Panel1.BackColor = 'White'
    $WMISplit.Panel2.BackColor = 'White'
    $WMISplit.SplitterDistance= $($WMISplit.Height - 100)
    $WMISplit.IsSplitterFixed = $true

    $scopeWMIlabel1 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultBoldFont
        Location           = New-Object System.Drawing.Point(0,5)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = 'WMI Filtering'
        }
    $WMISplit.Panel2.Controls.Add($scopeWMIlabel1)

    $scopeWMIlabel2 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(0,35)
        Size               = New-Object System.Drawing.Size(500,25)
        Text               = 'This GPO is linked to the following WMI Filter:'
        }
    $WMISplit.Panel2.Controls.Add($scopeWMIlabel2)

    $scopeWMIDropDown = New-Object System.Windows.Forms.ComboBox -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(0,65)
        Size               = New-Object System.Drawing.Size(500,25)
        Anchor             = 'Left,Top'
        BackColor          = 'LightGray'
        DropDownStyle      = 'DropDownList'
        }
    $WMISplit.Panel2.Controls.Add($scopeWMIDropDown)

    $ScopeSplit = New-Object System.Windows.Forms.SplitContainer -Property @{
        Font               = $DefaultFont
        Dock               = 'Fill'
        Margin             = '4,4,4,4'
        Orientation        = 'Horizontal'
        FixedPanel         = 'Panel1'
        SplitterWidth      = 5
        BackColor          = 'LightGray'
        TabIndex           = 0 
        }
    $WMISplit.Panel1.Controls.Add($ScopeSplit)

    # have to resize the stuff after it's created because Dock 'Fill'
    $ScopeSplit.Panel1.BackColor = 'White'
    $ScopeSplit.Panel2.BackColor = 'White'
    $ScopeSplit.SplitterDistance=275

    $scopelabel1 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultBoldFont
        Location           = New-Object System.Drawing.Point(0,5)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = 'Links'
        }
    $ScopeSplit.Panel1.Controls.Add($scopelabel1)

    $scopelabel2 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $10ptFont
        Location           = New-Object System.Drawing.Point(0,35)
        Size               = New-Object System.Drawing.Size(250,25)
        Text               = 'Display links in this location:'
        }
    $ScopeSplit.Panel1.Controls.Add($scopelabel2)

    $scopelabel3 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $10ptFont
        Location           = New-Object System.Drawing.Point(0,65)
        Size               = New-Object System.Drawing.Size(500,25)
        Text               = 'The following sites, domains, and OUs are linked to this GPO:'
        }
    $ScopeSplit.Panel1.Controls.Add($scopelabel3)

    $scopeselector = New-Object System.Windows.Forms.ComboBox -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(275,35)
        Size               = New-Object System.Drawing.Size(1100,25)
        Anchor             = 'Right,Left,Top'
        BackColor          = 'LightGray'
        DropDownStyle      = 'DropDownList'
        }
    [Void]$scopeselector.Items.Add('[Entire forest]')
    [Void]$scopeselector.Items.Add('[All sites]')
    [Void]$scopeselector.Items.Add($domain.DNSRoot)
    $scopeselector.SelectedIndex=2
    $ScopeSplit.Panel1.Controls.Add($scopeselector)

    $linkdgv = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        Location                    = New-Object System.Drawing.Point(0,95)
        Size                        = New-Object System.Drawing.Size(1380,175)
        Anchor                      = 'Left,Right,Bottom,Top'
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
        }
    $ScopeSplit.Panel1.Controls.Add($linkdgv)

    $scopelabel4 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultBoldFont
        Location           = New-Object System.Drawing.Point(0,5)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = 'Security Filtering'
        }
    $ScopeSplit.Panel2.Controls.Add($scopelabel4)

    $scopelabel5 = New-Object System.Windows.Forms.Label -Property @{
        Font               = $10ptFont
        Location           = New-Object System.Drawing.Point(0,35)
        Size               = New-Object System.Drawing.Size(700,25)
        Text               = 'The settings in this GPO can only apply to the following users, groups, and computers:'
        }
    $ScopeSplit.Panel2.Controls.Add($scopelabel5)

    $secdgv = New-Object System.Windows.Forms.DataGridView -Property @{
        Font                        = $10ptFont
        Location                    = New-Object System.Drawing.Point(0,65)
        Size                        = New-Object System.Drawing.Size(1380,210)
        Anchor                      = 'Left,Right,Bottom,Top'
        SelectionMode               = 'FullRowSelect'
        BackgroundColor             = 'WhiteSmoke'
        ColumnHeadersHeightSizeMode = 'AutoSize'
        AutoSizeColumnsMode         = 'Fill'
        RowHeadersVisible           = $false
        AllowUserToResizeRows       = $false
        MultiSelect                 = $false
        AllowUserToAddRows          = $false
        AllowUserToDeleteRows       = $false
        ReadOnly                    = $true
        ColumnHeadersVisible        = $true
        }
    $ScopeSplit.Panel2.Controls.Add($secdgv)
    # End Scope tab and controls

    # Details tab and controls
    $DetailsTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 1
        Text = 'Details'
        }
    $SelectedPolicyTabControl.Controls.Add($DetailsTab)

    $DTDomain = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,15)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Domain:"
        }
    $DetailsTab.Controls.Add($DTDomain)

    $DTDomainres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,15)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTDomainres)

    $DTOwner = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,45)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Owner:"
        }
    $DetailsTab.Controls.Add($DTOwner)

    $DTOwnerres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,45)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTOwnerres)

    $DTCreated = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,75)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Created:"
        }
    $DetailsTab.Controls.Add($DTCreated)

    $DTCreatedres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,75)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTCreatedres)

    $DTModified = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,105)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Modified:"
        }
    $DetailsTab.Controls.Add($DTModified)

    $DTModifiedres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,105)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTModifiedres)

    $DTUserVer = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,135)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "User version:"
        }
    $DetailsTab.Controls.Add($DTUserVer)

    $DTUserVerres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,135)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTUserVerres)

    $DTComputerVer = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,165)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Computer version:"
        }
    $DetailsTab.Controls.Add($DTComputerVer)

    $DTComputerVerres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,165)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTComputerVerres)

    $DTUniqueID = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,195)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Unique ID:"
        }
    $DetailsTab.Controls.Add($DTUniqueID)

    $DTUniqueIDres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,195)
        Size               = New-Object System.Drawing.Size(600,25)
        }
    $DetailsTab.Controls.Add($DTUniqueIDres)

    $DTGPOStatus = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,225)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "GPO Status:"
        }
    $DetailsTab.Controls.Add($DTGPOStatus)

    $DTGPOStatusres = New-Object System.Windows.Forms.ComboBox -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,225)
        Size               = New-Object System.Drawing.Size(350,25)
        BackColor          = 'WhiteSmoke'
        DropDownStyle      = 'DropDownList'
        }
    [Void]$DTGPOStatusres.Items.Add("All settings disabled")
    [Void]$DTGPOStatusres.Items.Add("Computer configuration settings disabled")
    [Void]$DTGPOStatusres.Items.Add("Enabled")
    [Void]$DTGPOStatusres.Items.Add("User configuration settings disabled")
    $DTGPOStatusres.Add_SelectedIndexChanged($DTGPOStatusres_IndexChanged)
    $DetailsTab.Controls.Add($DTGPOStatusres)

    $DTComment = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(15,255)
        Size               = New-Object System.Drawing.Size(200,25)
        Text               = "Comment:"
        }
    $DetailsTab.Controls.Add($DTComment)

    $DTCommentres = New-Object System.Windows.Forms.Label -Property @{
        Font               = $DefaultFont
        Location           = New-Object System.Drawing.Point(215,255)
        Size               = New-Object System.Drawing.Size(600,600)
        }
    $DetailsTab.Controls.Add($DTCommentres)
    # End Details tab and controls

    # Settings tab and controls
    $SettingsTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 2
        Text = 'Settings'
        }
    $SelectedPolicyTabControl.Controls.Add($SettingsTab)

    $WebBrowser = New-Object System.Windows.Forms.WebBrowser -Property @{
        Dock                       = 'Fill'
        DocumentText               = 'Generating Report...'
        ScriptErrorsSuppressed     = $true
        }
    $SettingsTab.Controls.Add($WebBrowser)
    # End Settings tab and controls

    # Delegation tab and controls
    $DelegationTab = New-Object System.Windows.Forms.TabPage -Property @{
        Location = New-Object System.Drawing.Point(4, 26)
        Size = New-Object System.Drawing.Size(1387,670)
        UseVisualStyleBackColor = $True
        Margin = '4, 4, 4, 4'
        Padding = '3, 3, 3, 3'
        TabIndex = 3
        Text = 'Delegation'
        }
    $SelectedPolicyTabControl.Controls.Add($DelegationTab)
    # End Delegation tab and controls
#endregion SelectedPolicyTabs

$Form.ShowDialog() | Out-Null
$Form.Close()

#UNCLASSIFIED