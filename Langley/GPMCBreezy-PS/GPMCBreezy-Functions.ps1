#UNCLASSIFIED

#This is a list of functions for external actions
#Created by Michael Calabrese

Function Show-BackupTreeView {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory)]
        [String]$BackupPath, 
        [Parameter()]
        [Switch]$CurrentDomain
        )

    function Add-Node {
        [CmdletBinding()]

        Param ( 
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$RootNode,
            [Parameter(Mandatory)]
            [String]$DName,
            [Parameter(Mandatory)]
            [String]$Name,
            [Parameter(Mandatory)]
            [String]$Type,
            [Parameter()]
            [switch]$HasChildren
            )

        $newNode = new-object System.Windows.Forms.TreeNode
        $newNode.Name = $DName 
        $newNode.Text = $Name
        If ($HasChildren) {
            $newNode.Nodes.Add('') | Out-Null
            }

    switch ($Type) {
            Forest                     {$newnode.ImageIndex = 0;$newNode.SelectedImageIndex = 0;$newNode.Tag='OU'}
            DomainsContainer           {$newnode.ImageIndex = 1;$newNode.SelectedImageIndex = 1;$newNode.Tag='OU'}
            Domain                     {$newnode.ImageIndex = 2;$newNode.SelectedImageIndex = 2;$newNode.Tag='OU'}
            OrganizationalUnit         {$newnode.ImageIndex = 3;$newNode.SelectedImageIndex = 3;$newNode.Tag='OU'}
            BlockedInheritanceOU       {$newnode.ImageIndex = 4;$newNode.SelectedImageIndex = 4;$newNode.Tag='OU'}
            Container                  {$newnode.ImageIndex = 5;$newNode.SelectedImageIndex = 5}
            GPOContainer               {$newnode.ImageIndex = 6;$newNode.SelectedImageIndex = 6}
            SitesContainer             {$newnode.ImageIndex = 7;$newNode.SelectedImageIndex = 7}
            WmiFilterContainer         {$newnode.ImageIndex = 8;$newNode.SelectedImageIndex = 8}
            WmiFilter                  {$newnode.ImageIndex = 9;$newNode.SelectedImageIndex = 9;$newNode.Tag='WMI'}
            GroupPolicyObject          {$newnode.ImageIndex = 10;$newNode.SelectedImageIndex = 10;$newNode.Tag='GPO'}
            UnenforcedandLinkedGPO     {$newnode.ImageIndex = 11;$newNode.SelectedImageIndex = 11;$newNode.Tag='GPO'}
            EnforcedandLinkedGPO       {$newnode.ImageIndex = 12;$newNode.SelectedImageIndex = 12;$newNode.Tag='GPO'}
            EnforcedandUnLinkedGPO     {$newnode.ImageIndex = 13;$newNode.SelectedImageIndex = 13;$newNode.Tag='GPO'}
            UnEnforcedandUnLinkedGPO   {$newnode.ImageIndex = 14;$newNode.SelectedImageIndex = 14;$newNode.Tag='GPO'}
        }
        $RootNode.Nodes.Add($newNode) | Out-Null 
        $newNode
    }

    function Get-NextLevel {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$RootNode,
            [Parameter()]
            [String]$Type
            )
                           
        If ($Type -eq 'Domain') {
            $ADObjects = $script:domain

            $RootNode.Nodes.Clear()

            $ADObjects | % {
                $node = Add-Node -RootNode $RootNode -dname $_.distinguishedName -name $_.DNSRoot -Type Domain
                Get-NextLevel -RootNode $node -Type Domain
                }
            }
            else {
                $ADObjects = $backupxml | Where-Object {$_.ParentOU -eq $RootNode.Name} | Sort-Object OUName

                $GPOObjects = ($backupxml | Where-Object {$_.OUDN -eq $RootNode.Name} ).Policies | Sort-Object GPO
                           
                If ($ADObjects) {
                    $RootNode.Nodes.Clear()

                    if($GPOObjects.count -gt 0){
                        $GPOObjects | % {
                            switch ($_) {
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $true)}      {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $false)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnenforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $true)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandUnLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $false)}    {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnEnforcedandUnLinkedGPO}
                                }
                            }
                        }

                    $ADObjects | % {
                        $DN='OU=' + $_.OUName + ',' + $_.ParentOU
                        If ( ($ADObjects.Policies) -or ($backupxml | Where-Object {$_.ParentOU -eq $DN}) ) {
                            if($_.Inheritance -eq $false){
                                Add-Node $RootNode $DN $_.OUName -Type BlockedInheritanceOU -HasChildren
                                }
                            else{
                                Add-Node $RootNode $DN $_.OUName -Type OrganizationalUnit -HasChildren
                                }
                            }
                        Else {
                            if($_.Inheritance -eq $false){
                                Add-Node $RootNode $DN $_.OUName -Type BlockedInheritanceOU -HasChildren
                                }
                            else{
                                Add-Node $RootNode $DN $_.OUName -Type OrganizationalUnit -HasChildren
                                }
                            }   
                        }
                    }
            Else {
                $RootNode.Nodes.Clear()
                if($GPOObjects.count -gt 0){
                    $GPOObjects | % {
                            switch ($_) {
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $true)}      {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $false)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnenforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $true)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandUnLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $false)}    {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnEnforcedandUnLinkedGPO}
                                }
                            }
                        }
                }
            }
    }

    function Build-TreeView { 
        
        Param(
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$TreeViewNode,
            [Parameter(Mandatory)]
            $domain
            )

        #Generate rootdomain node and add subdomain nodes
        $RootDomainNode = Add-Node -DName $Domain.DistinguishedName -Name $Domain.DNSRoot -RootNode $TreeViewNode -Type Domain -HasChildren
                               
        $TreeViewNode.Expand()
        $RootDomainNode.Expand()
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

    #Test path and exit if not real
    if (!(Test-Path $BackupPath)){Exit}

    #Import the Assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    #FontSetup
    $DefaultFont=New-Object System.Drawing.Font("Calibri",12,0,3,0)

    #Import xml files
    if($CurrentDomain){
        $Domain=Get-ADDomain
        }
    else{
        $Domain=Import-Clixml "$BackupPath\DomainInfo.xml"
        }

    $backupxml=Import-Clixml "$BackupPath\GpoLinks.xml"
    

#region imagelist                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  #region imagelist
$imagelist = New-Object System.Windows.Forms.ImageList
$Formatter_binaryFomatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
$System_IO_MemoryStream = New-Object System.IO.MemoryStream (,[byte[]][System.Convert]::FromBase64String('
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAu
MC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAA
ACZTeXN0ZW0uV2luZG93cy5Gb3Jtcy5JbWFnZUxpc3RTdHJlYW1lcgEAAAAERGF0YQcCAgAAAAkD
AAAADwMAAAA4FQAAAk1TRnQBSQFMAgEBDwEAARgBAAEYAQABEAEAARABAAT/AQkBAAj/AUIBTQE2
AQQGAAE2AQQCAAEoAwABQAMAAUADAAEBAQABCAYAARAYAAGAAgABgAMAAoABAAGAAwABgAEAAYAB
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
/wMAAv8BAAH/AwAB/wEAAf8BAAL/AgAD/wEAMP8QABL/BvIGmQEaBP8B8wXyAfECBwHxA/8QAAH/
AfMG7wZSAZkC/wH0AfEE9AHwA1gDUgGZBP8B8AX0AQcBHAHvAe0B8QL/EAAB/wHyAbwE/wHvA3oD
UgGZAv8B9AHyAbUBvAHzAvAEUgFRATABmQT/AfAB/wG1AfMBBwH/AbwB7wEcAZkB7wL/EAAB/wHy
AbwCzwK1Ae8CUgFYA1IBmQL/AfQC8gK1AvADWANSAZkE/wHwAf8BvAK1Af8BBwKZARoB7wL/EAAB
/wHyAbwB8AKGAbUB7wJSAVgDUgGZAv8B9AHyAfECtQLwAXMBUQFSAXMBSwFRARoE/wHwAf8B7gK1
Af8B7gGZARoBoAHvAv8QAAH/AfIBvAG1AoYBtQHvAe0BUQF5ARwBKgFzARsC/wH0AfIB9ALzAfQB
8AEaAUsBeQHvASoBcwX/AfAB/wPzAf8BvAIaAcMB7wL/EAAB/wHyAbwE/wHvAcMBSwF5Ae8BKgFz
A/8B9Aa8AfcBcwJSAVEBHAX/AfAFvAEHAfcBGgHDAe8C/xAAAf8B8wfvAXMDUQGZBf8B8AIbAxoB
mQEcAXMBHAH0B/8BvAHDARsEGgHDAe8C/xAAA/8B8AIbAe4DBwGZAXMBBwH1Bf8B8AH0AfMBvALu
ARoBwwHvAfQI/wG8AfYB8AG8Au4BGwHDAe8B9gH/EAAD/wHwAvQB8gMbAcMB7wHzBv8B8AH2AfMD
7wEHAcMB7wFzARsH/wHwAfYB7gPvARsBwwHtAZkB9BAAA/8B8QH2AfID9wHvAfYB7wFzARoF/wHx
B/YB7wFzARwH/wHxB/YB7QFzARsQAAP/AfIB9Ab2Ae8BcwEcBf8B9AHwA/QC8wEbARoB7AGZB/8B
8wHyAvQD8wEbAQcBHAHzEAAD/wH0AfEB8wLyAfEC8AHuAZIB7gb/AfQB8wPyBPEB9Aj/AfQB8wLy
BPEB8gH/EAAF/wP0BfMB9iL/EAAg/xDxEAAg/wEAAfQL8AH0Af8BAAHxAv8C9AL/AfcBBwS8AfMB
/wEACf8B9QG8AQcL/wH0AvMG/wEAAbwKmgFzAZkB/wEAAfEB/wHyAYYD/wH3BJoBdAEcAf8BAAn/
AfMBtQGRCv8B8AEHAfcB7QG8Bf8BAAHzARsJGgKZAf8BAAHxAfQBzwGGAfMB8gH0AfcEGgGZARwB
9AEAAf8BGwZ0AnMB7wGuAUsJ/wEHAbwC9wHvBf8DAAEaCcMBmQH/AQAB8QHzAbwDhgH0AfcBGgTD
AZkB9AEAAf8BGwGZBZoBmQEHAvcBrgHyCP8BBwG7AZEB7QHvBf8DAAEbAcMHGgHDAZkB/wEAAfEC
8wG1Aq4B9AHvBBoBwwGZAfQBAAH/ARsBmQSaAZkBuwHwAZIBrgLtAfAG/wHwARkBtQKRAewB8gT/
AwABGwnDAQcB/wEAAfECGQK1Aa8B9AHvARoEwwGZAfQBAAH/ARsBmQSaAe8BtQGRAa4CbQHrAe8F
/wHxAbwBCQH3AZEC7AH3AfID/wMAARsBwwEaBbwBGwHDAQcB/wEAAfIBvALwA/EB9wMHARsBwwEH
AfQBAAH/ARsGmgHuA/YBwwG8AfQE/wHwArsBtQKRAq4BbQGRAbwC/wMAARsEwwMbAsMBBwH/BAAB
GwHDBxsBwwEHAfQBAAH/AfMGmgHuAfMC7wH2AQcB8AT/AQcBvAK7ArUBtAKRAu0C/wMAARsBwwYb
AsMBvAH/BAABGwnDAbwB9AEAAf8B9AWaAaABGgLyAvEBvAHyBP8B7wG7ArUB9wG1A5EB7AHtAv8D
AAEbAfYBvAUHARsB9gG8Af8EAAH0AfYCvAQHARsB9gG8AfQBAAH/AfQBmgGgAZoCoAF5AXQDHAGZ
AfQF/wHzAbwB8wHxA/ABGwHvAQcB8QL/AwAB8wH2BhsC9gG8Af8EAAH0AfYGGwH0AfYBvAH0AQAB
/wEbAZoBoALDAZkBeQSaAXkG/wH0AfAB9gEHAu8BvAH2Ae8BcwEHAv8DAAHzCfYBvAH/BAAB9An2
AbwB9AEAAf8B9gEaBJkBmgEbAfEBtAKZBv8B9AHyAfQF9gG8AXMBHAL/AwAB8wH2AvAEvAHzAfYB
vAH/BAAB9AH2AbwFBwHyAfYBvAH0AQAG/wH2BRoB9gf/AfQC8gLwA7wB7wG8Av8DAAHzCfYBvAEc
AfIDAAH0CfYBvAEcAbwV/wL0BvMB9AL/AwABGwn2ARsCmQMAARsJ9gH0Apkg/wMAAfMKGgGZAfQD
AAH0CxoB81H/CnQEcwb/AfIFBwHwC/8ECQK1AdwB3Qj/AQkDzwG1Bf8BdAGaA3kBegd5AXMG/wSZ
ARwCkgG8Cv8BzwG0AboBtAHHAaYBswG1B/8BCQGtA6cBhgGLBP8BeQyaAXQC/wEbA3QBmQH2AhsB
8AH3AZkB6gT/ARsFdAFmAbMBtAMZAgkC/wEbA3QBHAGLAqcBCQG0AqcBtQP/AXkMmgF0Av8BGwGZ
ApoHmQHsBP8BGwGZBJoBrgK0BLMBuwL/ARsBmQGaAVIBcwKtAacBtQHPAqcBzwP/AXkBoAuaAXQC
/wEbAZkDmgGZARsBBwKZARoB7QT/ARsBmQSaAZECGQO0AboBuwL/ARsBmQGaAVEB6wKtAacB9AG1
AqcBzwP/AXkBoAuaAXQC/wEbAZkDmgGZARsB8gEbARoBGwHsBP8BGwGZBJoBkQG0AboEswG7Av8B
GwGZAZoCmQOtAfQBtQKnAc8D/wGZAaALmgF0Av8BGwSaAZkBGwP3ARoB7AFzARsC/wEbBZoBtAIZ
A9sBugG7Av8BGwKaApkBtAKtAQkBtAKtAQkD/wGZAaALmgF0Av8B8wWaARsE9gEcAXMBBwL/AfMF
mgG0AgkCswG0AbMBuwL/AfQCmgJ0AXMBrgOtAc8B+AT/AZkBwwaaAaAEmgF0Av8B9AWaARoBGwHy
AvABBwEcAfEC/wH0BZoBBwO7AbUBkQEJARkC/wH0AZoBoAN6AZkB7gIHAZkBdAT/AZkBwwOaAqAB
mQWaAXQC/wH0AZoBoAGaAqABeQF0AhwBdAGZAfQD/wH0AZoBoAGaAqAGeQT/AfYBmgGgAZoCoAV0
AXkE/wGZBaABmgJ0BXkC/wEbAZoBoALDAZkBeQSaAXkE/wEbAZoBoALDAZkBeQSaAXkE/wH0AZkD
mgKZApoCmQF5BP8BeQGaBBoBdAOaApkBmgF5Av8B9gEaBJkBmgEbAfEBtAKZBP8B9gEaBJkBmgEb
AfEBtAKZBf8BGwMaApoCGgH3AZkBmgT/AZkGeQGaAvYB1gG0AZoBeQf/AfYFGgH2Cf8B9gUaAfYJ
/wH2AcMEGwH2Cv8BmgZ5AZqF/wL0Bv8D9BL/AfQBvAQHAe8BvAQHAe8B8BL/A+wB6wFtAfcC/wEH
AuwB6wFyAW0B9AH/CnQEcwL/AfMBBwG8AQcB7wHtAW0B9wG8AQcB7wH3AfgB7wb/AbwB9wGSAe0B
8wH0AfcCkgEHAv8B9wEHAZgBNAFWAfcC/wG8Ae8BBwFWATkBcgH0Af8BdAGaA3kBegd5AXMC/wH0
AbwC8QEHAe0B7wHxAQcB8gG8Ae8B7AHyBv8B7gHvAZgBVgHyAfQC7wEdAfcC/wHvAQcB7wJ4AZIC
8QMHAXgBWAHrAfQB/wF5ApoFSwWaAXQD/wHxAbwB8gEHAewB8gH/AQcC8QHtAfcE/wGZAXkBdAEc
Ae8B9wHsAnMB7wH3AZIB9wL/Ae8CBwHvAZIC7AFyAe0CBwLvAewB9AH/AXkCmgFLA1EBKgWaAXQD
/wH0AQcB8gLvAv8B8QG8AfAB6wHzBP8BmQKaAZkC7wLtAZcE7wL/AQcB7wL3Au0BeAE1AXgB7wP3
AewB9AH/AXkBoAGaAXkBmQJ5AVEFmgF0BP8B8QEHAe0B8QL/AfQBBwHtAQcF/wEaApoBmQHvAZIB
7AHvAZgB7wH3Ae0B7wL/AQcD7wH3Ae0BmAF4AZkBBwPvAewC/wF5AaABmgKZAaABeQFSBZoBdAX/
Ae8B9wT/AbwB+Ab/ARoCmgGZAvMBBwL4AbwB9AHzAQcC/wG8A/MBvAGSAQcB7wEHAfEC8wHyAe0C
/wGZAaABmgGZAXkBmgF5AVIFmgF0Bf8B8gHsAZIB7QLsAW0BBwb/ARoBoAGaAZkB7QFtAesC7gGS
Am0BvAL/AbwBBwLvAfcD7QHvAgcC7wHtAv8BmQGgAZoCeQF0AlIFmgF0Bv8BBwHwAfEBBwH3AewB
8gb/ARoBoASaAgcB7wEcAXQE/wK8AgcC9wIHA7wCBwGSAv8BmQHDAZoEdAF5AaAEmgF0Bv8B8gG8
AfIB8AHtAe8H/wEaAaAEmgH3Aa4BbQHvAXkE/wK8AesB7AIHAvMB8AG8Ae0BbQEHAfcC/wGZAcMD
mgKgAZkFmgF0Bv8B9AG8AvEB7AHzB/8BGgHDApoBoAGaBHQBeQT/AbwBBwKSAe8B9wKSAe8BvAHv
AZIB7wH3Av8BmQWgAZoCdAV5B/8B8QG8AfcB7wj/ARoEmgF0ApoCmQF5BP8D9AHyAbwB8QK8Ae8B
8AT0Av8BmQGaBBoBdAOaApkBmgF5B/8B9AEHAfgB9Aj/AfYEGgKaARoB7wEcAZoH/wH0AbwB9wES
AewB7wHwBv8BGwZ5AZoC9gHWAbQBmgGZCP8B8wHyDv8B9gQbAfYH/wH0AbwBBwLvAfcB8Qz/AcMG
eQHDQf8BQgFNAT4HAAE+AwABKAMAAUADAAFAAwABAQEAAQEGAAECFgAD/4UAAYABAQEAAQEEAAGA
AQEBAAEBBAABgAEBAQABAQQAAeABAQEAAQEEAAHgAQEBAAEBBAAB4AEBAQABAQQAAeABAQEAAQEE
AAHgAQEB4AEBBAAB4AEBAeABAQQAAeABAQHgAQEEAAHgAQEB4AEBBAAB4AEBAeABAQQAAeABAQHg
AQEEAAHgAQAB4AUAAeABAAHgBQAB4AEAAeD/AAIACw=='))

$imagelist.ImageStream = $Formatter_binaryFomatter.Deserialize($System_IO_MemoryStream)
$Formatter_binaryFomatter = $null
$System_IO_MemoryStream = $null
$imagelist.TransparentColor = [System.Drawing.Color]::Transparent 
<# Imagelist descriptions:
	0  Forest Triangle
	1  Domains Container
	2  Domain Cluster
	3  Standard OU 
	4  Blocked Inheritance OU
	5  Standard Container
	6  GPO Container
	7  Sites Container
	8  Wmi Filter Container
	9  Wmi Filter
    10 GPO in GPO Container
	11 Unenforced and Linked GPO
	12 Enforced and Linked GPO
	13 Enforced and UnLinked GPO
	14 UnEnforced and UnLinked GPO
#>
#endregion imagelist

    $form_Shown={
        #Build treeview when form is shown
        $form.Cursor = 'WaitCursor'
        try {
            Build-TreeView -TreeViewNode $OUTreeViewTreeNode1 -domain $Domain
            }
        catch {
            Write-Host ($_ | Out-String)
            }
        finally {
            $form.Cursor = 'Default'
            }
    }

    $OUTreeView_BeforeExpand=[System.Windows.Forms.TreeViewCancelEventHandler]{
        #Get next level for current node
        If ($_.Node.Level -eq 1 -and $RootOU) {
            $_.Node.Nodes.Clear()
            $RootNode = Add-Node -DName $RootOU -Name $RootOU.Split(',')[0].Substring(3) -RootNode $_.Node -Type Domain
            $RootNode.Expand()
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

        # Set the label to the right to selected item name
        $selectionLabel.Text = $TVSelectedNodeText
        if($GPOdatagridview.DataSource){$GPOdatagridview.DataSource.Clear()}

        if($TVSelectedNodeTag -eq 'OU'){
            # When you click on OUs
            Write-Debug "OU"

            # Linked GPOs
            $LinkedOUPolicies= ($backupxml | Where-Object {$_.OUDN -eq $TVSelectedNodeName}).Policies
            $LinkedOUDataTable=New-Object System.Data.DataTable
            ConvertTo-DataTable -InputObject $LinkedOUPolicies -Table $LinkedOUDataTable
            Update-DataGridView -DataGridView $GPOdatagridview -Item $LinkedOUDataTable -AutoSizeColumns AllCells
	    }
    }

    # Form Objects
    $Form = New-Object System.Windows.Forms.Form -Property @{
        Font               = $DefaultFont
        StartPosition      = [Windows.Forms.FormStartPosition]::CenterScreen
        ClientSize         = New-Object System.Drawing.Size(1500,700)
        Text               = "GPMC-breezy, a faster way to manage GPOs"
        AutoScale          = $true
        AutoScaleMode      = 'DPI'
        }
    $form.Add_Shown($form_Shown)

    # Split containter that puts the OUTreeView across from the tab control
    $VSplitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{
        Font               = $DefaultFont
        Size               = New-Object System.Drawing.Size(1500,700)
        Location           = New-Object System.Drawing.Point(0,0)
        Anchor             = 'top,bottom,left,right'
        SplitterDistance   = 200
        Margin             = '4,4,4,4'
        Orientation        = 'Vertical'
        SplitterWidth      = 5
        TabIndex           = 0 
        }
    $form.Controls.Add($VSplitContainer)

    # OU/GPO selector menu
    $OUTreeView = New-Object System.Windows.Forms.TreeView -Property @{
        Dock                = 'Fill'
        Font                = $DefaultFont
        ImageIndex          = 1
        SelectedImageIndex  = 1
        TabIndex            = 1
        ImageList           = $imagelist
        Sorted              = $false
        Scrollable          = $true
        HideSelection       = $false
        }
    $OUTreeView.Add_BeforeExpand($OUTreeView_BeforeExpand)
    $OUTreeView.add_AfterSelect($OUTreeView_AfterSelect)
    $VSplitContainer.Panel1.Controls.Add($OUTreeView)

    $OUTreeViewTreeNode1 = New-Object System.Windows.Forms.TreeNode -Property @{
        Text               = "Backup Visualization"
        Tag                = "root"
        ImageIndex         = 1
        SelectedImageIndex = 1
    }
    [Void]$OUTreeView.Nodes.Add($OUTreeViewTreeNode1)

    $selectionLabel = New-Object System.Windows.Forms.Label -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",11,1,3,0)
        Location           = New-Object System.Drawing.Point(0,0)
        Size               = New-Object System.Drawing.Size(1000,25)
        Text               = 'Welcome to GPMC-Breezy'
        }
    $VSplitContainer.Panel2.Controls.Add($selectionLabel)

    $GPOdatagridview = New-Object System.Windows.Forms.DataGridView -Property @{
            Font                        = $DefaultFont
            Size                        = New-Object System.Drawing.Size(1295,675)
            Location                    = New-Object System.Drawing.Point(0,25)
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
    $VSplitContainer.Panel2.Controls.Add($GPOdatagridview)

    [Void]$form.ShowDialog()
}

Function Show-RestoreTreeView {
    [CmdletBinding()]

    Param (
        [Parameter(Mandatory)]
        [String]$RestoreFile
        )

    function Add-Node {
        [CmdletBinding()]

        Param ( 
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$RootNode,
            [Parameter(Mandatory)]
            [String]$DName,
            [Parameter(Mandatory)]
            [String]$Name,
            [Parameter(Mandatory)]
            [String]$Type,
            [Parameter()]
            [switch]$HasChildren
            )

        $newNode = new-object System.Windows.Forms.TreeNode
        $newNode.Name = $DName 
        $newNode.Text = $Name
        If ($HasChildren) {
            $newNode.Nodes.Add('') | Out-Null
            }

    switch ($Type) {
            Forest                     {$newnode.ImageIndex = 0;$newNode.SelectedImageIndex = 0;$newNode.Tag='OU'}
            DomainsContainer           {$newnode.ImageIndex = 1;$newNode.SelectedImageIndex = 1;$newNode.Tag='OU'}
            Domain                     {$newnode.ImageIndex = 2;$newNode.SelectedImageIndex = 2;$newNode.Tag='OU'}
            OrganizationalUnit         {$newnode.ImageIndex = 3;$newNode.SelectedImageIndex = 3;$newNode.Tag='OU'}
            BlockedInheritanceOU       {$newnode.ImageIndex = 4;$newNode.SelectedImageIndex = 4;$newNode.Tag='OU'}
            Container                  {$newnode.ImageIndex = 5;$newNode.SelectedImageIndex = 5}
            GPOContainer               {$newnode.ImageIndex = 6;$newNode.SelectedImageIndex = 6}
            SitesContainer             {$newnode.ImageIndex = 7;$newNode.SelectedImageIndex = 7}
            WmiFilterContainer         {$newnode.ImageIndex = 8;$newNode.SelectedImageIndex = 8}
            WmiFilter                  {$newnode.ImageIndex = 9;$newNode.SelectedImageIndex = 9;$newNode.Tag='WMI'}
            GroupPolicyObject          {$newnode.ImageIndex = 10;$newNode.SelectedImageIndex = 10;$newNode.Tag='GPO'}
            UnenforcedandLinkedGPO     {$newnode.ImageIndex = 11;$newNode.SelectedImageIndex = 11;$newNode.Tag='GPO'}
            EnforcedandLinkedGPO       {$newnode.ImageIndex = 12;$newNode.SelectedImageIndex = 12;$newNode.Tag='GPO'}
            EnforcedandUnLinkedGPO     {$newnode.ImageIndex = 13;$newNode.SelectedImageIndex = 13;$newNode.Tag='GPO'}
            UnEnforcedandUnLinkedGPO   {$newnode.ImageIndex = 14;$newNode.SelectedImageIndex = 14;$newNode.Tag='GPO'}
        }
        $RootNode.Nodes.Add($newNode) | Out-Null 
        $newNode
    }

    function Get-NextLevel {
        [CmdletBinding()]

        Param (
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$RootNode,
            [Parameter()]
            [String]$Type
            )
                           
        If ($Type -eq 'Domain') {
            $ADObjects = $script:domain

            $RootNode.Nodes.Clear()

            $ADObjects | % {
                $node = Add-Node -RootNode $RootNode -dname $_.distinguishedName -name $_.DNSRoot -Type Domain
                Get-NextLevel -RootNode $node -Type Domain
                }
            }
            else {
                $ADObjects = $backupxml | Where-Object {$_.ParentOU -eq $RootNode.Name} | Sort-Object OUName

                $GPOObjects = ($backupxml | Where-Object {$_.OUDN -eq $RootNode.Name} ).Policies | Sort-Object GPO
                           
                If ($ADObjects) {
                    $RootNode.Nodes.Clear()

                    if($GPOObjects.count -gt 0){
                        $GPOObjects | % {
                            switch ($_) {
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $true)}      {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $false)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnenforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $true)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandUnLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $false)}    {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnEnforcedandUnLinkedGPO}
                                }
                            }
                        }

                    $ADObjects | % {
                        $DN='OU=' + $_.OUName + ',' + $_.ParentOU
                        If ( ($ADObjects.Policies) -or ($backupxml | Where-Object {$_.ParentOU -eq $DN}) ) {
                            if($_.Inheritance -eq $false){
                                Add-Node $RootNode $DN $_.OUName -Type BlockedInheritanceOU -HasChildren
                                }
                            else{
                                Add-Node $RootNode $DN $_.OUName -Type OrganizationalUnit -HasChildren
                                }
                            }
                        Else {
                            if($_.Inheritance -eq $false){
                                Add-Node $RootNode $DN $_.OUName -Type BlockedInheritanceOU -HasChildren
                                }
                            else{
                                Add-Node $RootNode $DN $_.OUName -Type OrganizationalUnit -HasChildren
                                }
                            }   
                        }
                    }
            Else {
                $RootNode.Nodes.Clear()
                if($GPOObjects.count -gt 0){
                    $GPOObjects | % {
                            switch ($_) {
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $true)}      {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $true) -and ($_.Enforced -eq $false)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnenforcedandLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $true)}     {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type EnforcedandUnLinkedGPO}
                                {($_.'Link Enabled' -eq $false) -and ($_.Enforced -eq $false)}    {Add-Node $RootNode -DName $_.GPO -Name $_.GPO -Type UnEnforcedandUnLinkedGPO}
                                }
                            }
                        }
                }
            }
    }

    function Build-TreeView { 
        
        Param(
            [Parameter(Mandatory)]
            [System.Windows.Forms.TreeNode]$TreeViewNode,
            [Parameter(Mandatory)]
            $domain
            )

        #Generate rootdomain node and add subdomain nodes
        $RootDomainNode = Add-Node -DName $Domain.DistinguishedName -Name $Domain.DNSRoot -RootNode $TreeViewNode -Type Domain -HasChildren
                               
        $TreeViewNode.Expand()
        $RootDomainNode.Expand()
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

    #Import the Assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    #FontSetup
    $DefaultFont=New-Object System.Drawing.Font("Calibri",12,0,3,0)

    #Import xml files
    $Domain=Get-ADDomain
    $backupxml=Import-Clixml $RestoreFile
    $title="GPMCBreezy `"RestoreView`" $($restorefile.Split('\')[-1] -replace '.xml','')"

#region imagelist                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  #region imagelist
$imagelist = New-Object System.Windows.Forms.ImageList
$Formatter_binaryFomatter = New-Object System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
$System_IO_MemoryStream = New-Object System.IO.MemoryStream (,[byte[]][System.Convert]::FromBase64String('
AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAu
MC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAA
ACZTeXN0ZW0uV2luZG93cy5Gb3Jtcy5JbWFnZUxpc3RTdHJlYW1lcgEAAAAERGF0YQcCAgAAAAkD
AAAADwMAAAA4FQAAAk1TRnQBSQFMAgEBDwEAARgBAAEYAQABEAEAARABAAT/AQkBAAj/AUIBTQE2
AQQGAAE2AQQCAAEoAwABQAMAAUADAAEBAQABCAYAARAYAAGAAgABgAMAAoABAAGAAwABgAEAAYAB
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
/wMAAv8BAAH/AwAB/wEAAf8BAAL/AgAD/wEAMP8QABL/BvIGmQEaBP8B8wXyAfECBwHxA/8QAAH/
AfMG7wZSAZkC/wH0AfEE9AHwA1gDUgGZBP8B8AX0AQcBHAHvAe0B8QL/EAAB/wHyAbwE/wHvA3oD
UgGZAv8B9AHyAbUBvAHzAvAEUgFRATABmQT/AfAB/wG1AfMBBwH/AbwB7wEcAZkB7wL/EAAB/wHy
AbwCzwK1Ae8CUgFYA1IBmQL/AfQC8gK1AvADWANSAZkE/wHwAf8BvAK1Af8BBwKZARoB7wL/EAAB
/wHyAbwB8AKGAbUB7wJSAVgDUgGZAv8B9AHyAfECtQLwAXMBUQFSAXMBSwFRARoE/wHwAf8B7gK1
Af8B7gGZARoBoAHvAv8QAAH/AfIBvAG1AoYBtQHvAe0BUQF5ARwBKgFzARsC/wH0AfIB9ALzAfQB
8AEaAUsBeQHvASoBcwX/AfAB/wPzAf8BvAIaAcMB7wL/EAAB/wHyAbwE/wHvAcMBSwF5Ae8BKgFz
A/8B9Aa8AfcBcwJSAVEBHAX/AfAFvAEHAfcBGgHDAe8C/xAAAf8B8wfvAXMDUQGZBf8B8AIbAxoB
mQEcAXMBHAH0B/8BvAHDARsEGgHDAe8C/xAAA/8B8AIbAe4DBwGZAXMBBwH1Bf8B8AH0AfMBvALu
ARoBwwHvAfQI/wG8AfYB8AG8Au4BGwHDAe8B9gH/EAAD/wHwAvQB8gMbAcMB7wHzBv8B8AH2AfMD
7wEHAcMB7wFzARsH/wHwAfYB7gPvARsBwwHtAZkB9BAAA/8B8QH2AfID9wHvAfYB7wFzARoF/wHx
B/YB7wFzARwH/wHxB/YB7QFzARsQAAP/AfIB9Ab2Ae8BcwEcBf8B9AHwA/QC8wEbARoB7AGZB/8B
8wHyAvQD8wEbAQcBHAHzEAAD/wH0AfEB8wLyAfEC8AHuAZIB7gb/AfQB8wPyBPEB9Aj/AfQB8wLy
BPEB8gH/EAAF/wP0BfMB9iL/EAAg/xDxEAAg/wEAAfQL8AH0Af8BAAHxAv8C9AL/AfcBBwS8AfMB
/wEACf8B9QG8AQcL/wH0AvMG/wEAAbwKmgFzAZkB/wEAAfEB/wHyAYYD/wH3BJoBdAEcAf8BAAn/
AfMBtQGRCv8B8AEHAfcB7QG8Bf8BAAHzARsJGgKZAf8BAAHxAfQBzwGGAfMB8gH0AfcEGgGZARwB
9AEAAf8BGwZ0AnMB7wGuAUsJ/wEHAbwC9wHvBf8DAAEaCcMBmQH/AQAB8QHzAbwDhgH0AfcBGgTD
AZkB9AEAAf8BGwGZBZoBmQEHAvcBrgHyCP8BBwG7AZEB7QHvBf8DAAEbAcMHGgHDAZkB/wEAAfEC
8wG1Aq4B9AHvBBoBwwGZAfQBAAH/ARsBmQSaAZkBuwHwAZIBrgLtAfAG/wHwARkBtQKRAewB8gT/
AwABGwnDAQcB/wEAAfECGQK1Aa8B9AHvARoEwwGZAfQBAAH/ARsBmQSaAe8BtQGRAa4CbQHrAe8F
/wHxAbwBCQH3AZEC7AH3AfID/wMAARsBwwEaBbwBGwHDAQcB/wEAAfIBvALwA/EB9wMHARsBwwEH
AfQBAAH/ARsGmgHuA/YBwwG8AfQE/wHwArsBtQKRAq4BbQGRAbwC/wMAARsEwwMbAsMBBwH/BAAB
GwHDBxsBwwEHAfQBAAH/AfMGmgHuAfMC7wH2AQcB8AT/AQcBvAK7ArUBtAKRAu0C/wMAARsBwwYb
AsMBvAH/BAABGwnDAbwB9AEAAf8B9AWaAaABGgLyAvEBvAHyBP8B7wG7ArUB9wG1A5EB7AHtAv8D
AAEbAfYBvAUHARsB9gG8Af8EAAH0AfYCvAQHARsB9gG8AfQBAAH/AfQBmgGgAZoCoAF5AXQDHAGZ
AfQF/wHzAbwB8wHxA/ABGwHvAQcB8QL/AwAB8wH2BhsC9gG8Af8EAAH0AfYGGwH0AfYBvAH0AQAB
/wEbAZoBoALDAZkBeQSaAXkG/wH0AfAB9gEHAu8BvAH2Ae8BcwEHAv8DAAHzCfYBvAH/BAAB9An2
AbwB9AEAAf8B9gEaBJkBmgEbAfEBtAKZBv8B9AHyAfQF9gG8AXMBHAL/AwAB8wH2AvAEvAHzAfYB
vAH/BAAB9AH2AbwFBwHyAfYBvAH0AQAG/wH2BRoB9gf/AfQC8gLwA7wB7wG8Av8DAAHzCfYBvAEc
AfIDAAH0CfYBvAEcAbwV/wL0BvMB9AL/AwABGwn2ARsCmQMAARsJ9gH0Apkg/wMAAfMKGgGZAfQD
AAH0CxoB81H/CnQEcwb/AfIFBwHwC/8ECQK1AdwB3Qj/AQkDzwG1Bf8BdAGaA3kBegd5AXMG/wSZ
ARwCkgG8Cv8BzwG0AboBtAHHAaYBswG1B/8BCQGtA6cBhgGLBP8BeQyaAXQC/wEbA3QBmQH2AhsB
8AH3AZkB6gT/ARsFdAFmAbMBtAMZAgkC/wEbA3QBHAGLAqcBCQG0AqcBtQP/AXkMmgF0Av8BGwGZ
ApoHmQHsBP8BGwGZBJoBrgK0BLMBuwL/ARsBmQGaAVIBcwKtAacBtQHPAqcBzwP/AXkBoAuaAXQC
/wEbAZkDmgGZARsBBwKZARoB7QT/ARsBmQSaAZECGQO0AboBuwL/ARsBmQGaAVEB6wKtAacB9AG1
AqcBzwP/AXkBoAuaAXQC/wEbAZkDmgGZARsB8gEbARoBGwHsBP8BGwGZBJoBkQG0AboEswG7Av8B
GwGZAZoCmQOtAfQBtQKnAc8D/wGZAaALmgF0Av8BGwSaAZkBGwP3ARoB7AFzARsC/wEbBZoBtAIZ
A9sBugG7Av8BGwKaApkBtAKtAQkBtAKtAQkD/wGZAaALmgF0Av8B8wWaARsE9gEcAXMBBwL/AfMF
mgG0AgkCswG0AbMBuwL/AfQCmgJ0AXMBrgOtAc8B+AT/AZkBwwaaAaAEmgF0Av8B9AWaARoBGwHy
AvABBwEcAfEC/wH0BZoBBwO7AbUBkQEJARkC/wH0AZoBoAN6AZkB7gIHAZkBdAT/AZkBwwOaAqAB
mQWaAXQC/wH0AZoBoAGaAqABeQF0AhwBdAGZAfQD/wH0AZoBoAGaAqAGeQT/AfYBmgGgAZoCoAV0
AXkE/wGZBaABmgJ0BXkC/wEbAZoBoALDAZkBeQSaAXkE/wEbAZoBoALDAZkBeQSaAXkE/wH0AZkD
mgKZApoCmQF5BP8BeQGaBBoBdAOaApkBmgF5Av8B9gEaBJkBmgEbAfEBtAKZBP8B9gEaBJkBmgEb
AfEBtAKZBf8BGwMaApoCGgH3AZkBmgT/AZkGeQGaAvYB1gG0AZoBeQf/AfYFGgH2Cf8B9gUaAfYJ
/wH2AcMEGwH2Cv8BmgZ5AZqF/wL0Bv8D9BL/AfQBvAQHAe8BvAQHAe8B8BL/A+wB6wFtAfcC/wEH
AuwB6wFyAW0B9AH/CnQEcwL/AfMBBwG8AQcB7wHtAW0B9wG8AQcB7wH3AfgB7wb/AbwB9wGSAe0B
8wH0AfcCkgEHAv8B9wEHAZgBNAFWAfcC/wG8Ae8BBwFWATkBcgH0Af8BdAGaA3kBegd5AXMC/wH0
AbwC8QEHAe0B7wHxAQcB8gG8Ae8B7AHyBv8B7gHvAZgBVgHyAfQC7wEdAfcC/wHvAQcB7wJ4AZIC
8QMHAXgBWAHrAfQB/wF5ApoFSwWaAXQD/wHxAbwB8gEHAewB8gH/AQcC8QHtAfcE/wGZAXkBdAEc
Ae8B9wHsAnMB7wH3AZIB9wL/Ae8CBwHvAZIC7AFyAe0CBwLvAewB9AH/AXkCmgFLA1EBKgWaAXQD
/wH0AQcB8gLvAv8B8QG8AfAB6wHzBP8BmQKaAZkC7wLtAZcE7wL/AQcB7wL3Au0BeAE1AXgB7wP3
AewB9AH/AXkBoAGaAXkBmQJ5AVEFmgF0BP8B8QEHAe0B8QL/AfQBBwHtAQcF/wEaApoBmQHvAZIB
7AHvAZgB7wH3Ae0B7wL/AQcD7wH3Ae0BmAF4AZkBBwPvAewC/wF5AaABmgKZAaABeQFSBZoBdAX/
Ae8B9wT/AbwB+Ab/ARoCmgGZAvMBBwL4AbwB9AHzAQcC/wG8A/MBvAGSAQcB7wEHAfEC8wHyAe0C
/wGZAaABmgGZAXkBmgF5AVIFmgF0Bf8B8gHsAZIB7QLsAW0BBwb/ARoBoAGaAZkB7QFtAesC7gGS
Am0BvAL/AbwBBwLvAfcD7QHvAgcC7wHtAv8BmQGgAZoCeQF0AlIFmgF0Bv8BBwHwAfEBBwH3AewB
8gb/ARoBoASaAgcB7wEcAXQE/wK8AgcC9wIHA7wCBwGSAv8BmQHDAZoEdAF5AaAEmgF0Bv8B8gG8
AfIB8AHtAe8H/wEaAaAEmgH3Aa4BbQHvAXkE/wK8AesB7AIHAvMB8AG8Ae0BbQEHAfcC/wGZAcMD
mgKgAZkFmgF0Bv8B9AG8AvEB7AHzB/8BGgHDApoBoAGaBHQBeQT/AbwBBwKSAe8B9wKSAe8BvAHv
AZIB7wH3Av8BmQWgAZoCdAV5B/8B8QG8AfcB7wj/ARoEmgF0ApoCmQF5BP8D9AHyAbwB8QK8Ae8B
8AT0Av8BmQGaBBoBdAOaApkBmgF5B/8B9AEHAfgB9Aj/AfYEGgKaARoB7wEcAZoH/wH0AbwB9wES
AewB7wHwBv8BGwZ5AZoC9gHWAbQBmgGZCP8B8wHyDv8B9gQbAfYH/wH0AbwBBwLvAfcB8Qz/AcMG
eQHDQf8BQgFNAT4HAAE+AwABKAMAAUADAAFAAwABAQEAAQEGAAECFgAD/4UAAYABAQEAAQEEAAGA
AQEBAAEBBAABgAEBAQABAQQAAeABAQEAAQEEAAHgAQEBAAEBBAAB4AEBAQABAQQAAeABAQEAAQEE
AAHgAQEB4AEBBAAB4AEBAeABAQQAAeABAQHgAQEEAAHgAQEB4AEBBAAB4AEBAeABAQQAAeABAQHg
AQEEAAHgAQAB4AUAAeABAAHgBQAB4AEAAeD/AAIACw=='))

$imagelist.ImageStream = $Formatter_binaryFomatter.Deserialize($System_IO_MemoryStream)
$Formatter_binaryFomatter = $null
$System_IO_MemoryStream = $null
$imagelist.TransparentColor = [System.Drawing.Color]::Transparent 
<# Imagelist descriptions:
	0  Forest Triangle
	1  Domains Container
	2  Domain Cluster
	3  Standard OU 
	4  Blocked Inheritance OU
	5  Standard Container
	6  GPO Container
	7  Sites Container
	8  Wmi Filter Container
	9  Wmi Filter
    10 GPO in GPO Container
	11 Unenforced and Linked GPO
	12 Enforced and Linked GPO
	13 Enforced and UnLinked GPO
	14 UnEnforced and UnLinked GPO
#>
#endregion imagelist

    $form_Shown={
        #Build treeview when form is shown
        $form.Cursor = 'WaitCursor'
        try {
            Build-TreeView -TreeViewNode $OUTreeViewTreeNode1 -domain $Domain
            }
        catch {
            Write-Host ($_ | Out-String)
            }
        finally {
            $form.Cursor = 'Default'
            }
    }

    $OUTreeView_BeforeExpand=[System.Windows.Forms.TreeViewCancelEventHandler]{        
        #Get next level for current node
        If ($_.Node.Level -eq 1 -and $RootOU) {
            $_.Node.Nodes.Clear()
            $RootNode = Add-Node -DName $RootOU -Name $RootOU.Split(',')[0].Substring(3) -RootNode $_.Node -Type Domain
            $RootNode.Expand()
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

        # Set the label to the right to selected item name
        $selectionLabel.Text = $TVSelectedNodeText
        if($GPOdatagridview.DataSource){$GPOdatagridview.DataSource.Clear()}

        if($TVSelectedNodeTag -eq 'OU'){
            # When you click on OUs
            Write-Debug "OU"

            # Linked GPOs
            $LinkedOUPolicies= ($backupxml | Where-Object {$_.OUDN -eq $TVSelectedNodeName}).Policies
            $LinkedOUDataTable=New-Object System.Data.DataTable
            ConvertTo-DataTable -InputObject $LinkedOUPolicies -Table $LinkedOUDataTable
            Update-DataGridView -DataGridView $GPOdatagridview -Item $LinkedOUDataTable -AutoSizeColumns AllCells
	    }
    }

    # Form Objects
    $Form = New-Object System.Windows.Forms.Form -Property @{
        Font               = $DefaultFont
        StartPosition      = [Windows.Forms.FormStartPosition]::CenterScreen
        ClientSize         = New-Object System.Drawing.Size(1500,700)
        Text               = $title
        AutoScale          = $true
        AutoScaleMode      = 'DPI'
        }
    $form.Add_Shown($form_Shown)

    # Split containter that puts the OUTreeView across from the tab control
    $VSplitContainer = New-Object System.Windows.Forms.SplitContainer -Property @{
        Font               = $DefaultFont
        Size               = New-Object System.Drawing.Size(1500,700)
        Location           = New-Object System.Drawing.Point(0,0)
        Anchor             = 'top,bottom,left,right'
        SplitterDistance   = 200
        Margin             = '4,4,4,4'
        Orientation        = 'Vertical'
        SplitterWidth      = 5
        TabIndex           = 0 
        }
    $form.Controls.Add($VSplitContainer)

    # OU/GPO selector menu
    $OUTreeView = New-Object System.Windows.Forms.TreeView -Property @{
        Dock                = 'Fill'
        Font                = $DefaultFont
        ImageIndex          = 1
        SelectedImageIndex  = 1
        TabIndex            = 1
        ImageList           = $imagelist
        Sorted              = $false
        Scrollable          = $true
        HideSelection       = $false
        }
    $OUTreeView.Add_BeforeExpand($OUTreeView_BeforeExpand)
    $OUTreeView.add_AfterSelect($OUTreeView_AfterSelect)
    $VSplitContainer.Panel1.Controls.Add($OUTreeView)

    $OUTreeViewTreeNode1 = New-Object System.Windows.Forms.TreeNode -Property @{
        Text               = "Backup Visualization"
        Tag                = "root"
        ImageIndex         = 1
        SelectedImageIndex = 1
    }
    [Void]$OUTreeView.Nodes.Add($OUTreeViewTreeNode1)

    $selectionLabel = New-Object System.Windows.Forms.Label -Property @{
        Font               = New-Object System.Drawing.Font("Calibri",11,1,3,0)
        Location           = New-Object System.Drawing.Point(0,0)
        Size               = New-Object System.Drawing.Size(1000,25)
        Text               = 'Welcome to GPMC-Breezy'
        }
    $VSplitContainer.Panel2.Controls.Add($selectionLabel)

    $GPOdatagridview = New-Object System.Windows.Forms.DataGridView -Property @{
            Font                        = $DefaultFont
            Size                        = New-Object System.Drawing.Size(1295,675)
            Location                    = New-Object System.Drawing.Point(0,25)
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
    $VSplitContainer.Panel2.Controls.Add($GPOdatagridview)

    [Void]$form.ShowDialog()
}

Function Backup-GPOs {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [String]$BackupPath,
        [Parameter()]
        [Switch]$GenerateDomainInfo
        )

    #Variables
    $Date=Get-Date -Format MMddyyyy
    $domain=Get-ADDomain
    $DC=(Get-ADDomainController).Hostname
    $policyDefs = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\PolicyDefinitions"
    $BackupPath="$BackupPath\Backup_$Date"
    $GPOPath="$BackupPath\GPOs"
    $WMIPath="$BackupPath\WMIFilters"

    #PreReq Tests
    Import-Module ActiveDirectory,GPWmiFilter
    if(!(Get-Module GPWmiFilter)){
        Write-Warning "Exiting Script, GPWMIFilter not found"
        Pause
        Exit
        }

    if(!(Test-Path "$env:ProgramFiles\7-Zip\7z.exe")){
        Write-Warning "Exiting Script, 7Zip not installed"
        Pause
        Exit
        }

    #Functions
    function Get-OUPolicies {
        Param(
            [Parameter(Mandatory)]
            [String]$OU,
            [Parameter(Mandatory)]
            [String]$DC
            )

        $gpos=(Get-GPInheritance -Target $OU -Server $DC).GpoLinks
        [array]$PolicyArray=foreach($gpo in $gpos) {
            $details=Get-GPO -Guid $gpo.GpoId -Server $DC
            [pscustomobject]@{
                'Link Order'   = $gpo.Order
                'GPO'          = $gpo.DisplayName
                'Enforced'     = [string]$gpo.Enforced
                'Link Enabled' = [string]$gpo.Enabled
                'GPO Status'   = [string]$details.GpoStatus.ToString()
                'WMI Filter'   = $details.WmiFilter.Name
                'Modified'     = $details.ModificationTime
                'Domain'       = $details.DomainName
            }
        }

        Return $PolicyArray
    }
    
    #Create Paths
    Write-Host "Creating Folders.."

    New-Item $BackupPath -ItemType Directory -Force | Out-Null
    New-Item $GPOPath -ItemType Directory -Force | Out-Null
    New-Item $WMIPath -ItemType Directory -Force | Out-Null

    #Big Vars
    $AllGPOS=Get-GPO -All -Server $DC
    $AllOUs=Get-ADOrganizationalUnit -Filter * -Properties gPOptions -Server $DC

    #Check for links and ignore if unlinked
    Write-Host "Checking GPOs for links.."

    $Export=foreach($GPO in $AllGPOS) {
        Write-Host "    Checking $($GPO.DisplayName)"
        [xml]$report=$GPO | Get-GPOReport -ReportType Xml -Server $DC
        if($report.GPO.LinksTo) {
            [pscustomobject]@{
                DisplayName  = $GPO.DisplayName
                WmiFilter    = $GPO.WmiFilter.Name
                Id           = $GPO.Id
                Description  = $GPO.Description
                }
            }
        }
    $Export | %{Backup-GPO -Guid $_.Id -Path $GPOPath -Server $DC}

    # Export GPO info to xml file
    Write-Host "Writing GPOManifest.xml"
    $Export | Export-Clixml -Path "$BackupPath\GPOManifest.xml"

    # Convert WMIFilter to xml
    Write-Host "Exporting WMI Filters"
    $Export.WmiFilter | Select-Object -Unique | %{Get-GPWmiFilter -Name $_ -Server $DC | Export-Clixml -Path "$WMIPath\$_.xml"}

    # Copy ADMX and ADML to folder
    Write-Host "Copying PolicyDefinitions"
    Copy-Item -Path $policyDefs -Destination $BackupPath -Recurse -Container

    $linkbackups=foreach($OU in $AllOUs){
        if ($OU.gPOptions -eq 1){ [pscustomobject]@{OUName=$OU.Name;OUDN=$OU.DistinguishedName;ParentOU=($OU.DistinguishedName -split(',') | Select-Object -Skip 1) -join(',');Inheritance=$false;Policies=Get-OUPolicies $OU.DistinguishedName} }
        else{ [pscustomobject]@{OUName=$OU.Name;OUDN=$OU.DistinguishedName;ParentOU=($OU.DistinguishedName -split(',') | Select-Object -Skip 1) -join(',');Inheritance=$true;Policies=Get-OUPolicies $OU.DistinguishedName} }
    }
    $linkbackups+=[pscustomobject]@{OUName=$domain.Name;OUDN=$domain.DistinguishedName;ParentOU='';Inheritance='';Policies=Get-OUPolicies $domain.DistinguishedName}
    $linkbackups | Export-Clixml -Path "$BackupPath\GpoLinks.xml"

    if($GenerateDomainInfo){
        $domain | Export-Clixml -Path "$BackupPath\DomainInfo.xml"
        }

    Start-Process "C:\Program Files\7-Zip\7z.exe" -ArgumentList "A -tzip `"$BackupPath.zip`" `"$BackupPath\*`"" -Wait

    Write-Host "Backup Complete, zip file located at $BackupPath.zip"
    pause
}

#UNCLASSIFIED