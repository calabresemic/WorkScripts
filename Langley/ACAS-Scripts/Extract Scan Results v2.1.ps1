#Requires -Version 5.0
#title           :Extract Scan Results
#description     :This script will take a zip file with ACAS results and create a spreadsheet with compare table, a txt file for missing assets and a txt file for bad access.
#author		     :Michael Calabrese (1468714589)
#date            :2/19/2021
#version         :2.1

#==============================================================================
#Script Setup
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.Office.Interop.Excel

Function ConvertTo-CSV ($ExcelFile) {
$Excel = New-Object -ComObject Excel.Application
$Excel.Visible = $false
$excel.DisplayAlerts = $false
$WB = $Excel.Workbooks.Open($ExcelFile)
$WS = $WB.Worksheets | where {$_.name -ne "Compare"}
if ($WS){$WS.SaveAs("$workingDir\Unzip\$($WS.Name).csv",6)}
$WB.close($false)
$Excel.Quit()
Stop-Process -ProcessName EXCEL
}

#Variables

$csv=@()     #This array is used to collect all rows that we want to keep
$results=@() #This array is used to calculate CCRI score
$date=Get-Date -Format "MM/dd/yyyy"
$ignoredate=(Get-Date).AddDays(-30)
$workingDir = $PSScriptRoot
#$workingDir = "$([Environment]::GetFolderPath("Desktop"))\ACAS" #Uncomment this line to use in ISE
$requiredcolumns=@('Plugin','Plugin Name','Severity','NetBIOS Name','Plugin Text','Plugin Publication Date') #These are colums we need at a minimum to be able to use the scans

#Location of NIPR/SIPR Asset Lists

$localassets=@('MUHJ-DC-005P','MUHJ-DC-006P','MUHJ-HC-003P','MUHJ-HC-004P') #83d NOS Local Assets
$assets= Import-Csv '\\zhtx-bs-013v\cyod\07--Cyber 365\07--83NOS Assets List\LATEST Official Asset list.csv' | where {$_.Name -notin $localassets} #83d NOS Enterprise Assets

#==============================================================================
#Import information

#Open File Dialog for selecting scan results
do{
    $resultselector = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = $workingDir
        Filter = 'SCANZ|*.zip'
        Title = "Select Scan Results file to import"
    }
    
    $resultselector.ShowDialog() | Out-Null

} until ( ($resultselector.FileName -match 'Enterprise') -or ($resultselector.FileName -match 'NOS') )

#Extract Results

Expand-Archive $resultselector.FileName -DestinationPath "$workingDir\Unzip"

"Organizing Data"

Get-ChildItem "$workingDir\Unzip\*" -Include *.pdf,*BITI*,*ACAS*,*EITSM*,*Forescout*,*HBSS*,*SAMP*,*SCE*,*VPS*,*Workstations*,*Failed*,*19506*,*Compliance* -Recurse | Remove-Item #Remove clutter from results

if($xlsx=Get-ChildItem "$workingDir\Unzip" -Recurse -Include *.xlsx){$xlsx.FullName.foreach{ConvertTo-Csv $_}} #If results are xlsx format, convert to csv for easy import

$Import = (Get-ChildItem "$workingDir\Unzip" -Recurse -Include *.csv).FullName | Import-Csv #Import all csv files

#==============================================================================
#This is where all the filtering happens

#Abort script if the results don't contain the required columns

if($requiredcolumns.ForEach{($Import | Get-Member -MemberType NoteProperty).Name -contains $_} -contains $false) {

    "The results are missing some/all of the required columns($($requiredcolumns -join ',')). Aborting.";pause #Jumps to cleanup section

} else {
    
    $DSResults = $Import | Where-Object { ($assets.name -contains $_."NetBIOS Name".split("\")[1]) -or ($localassets -contains $_."NetBIOS Name".split("\")[1])} #Take only our assets from the original import

    if($DSResults) { 
        #If our assets are in the results

        $GoodAccess=($DSResults | Where-Object {$_.port -eq '445'}).'NetBios Name' | Select-Object -Unique      #This is a guess at what good access should look like based on the results
        $BadAccess=$DSResults.'NetBios Name' | Where-Object {$_ -notin $GoodAccess} | Select-Object -Unique     #If access is not good it must be bad?
        $scannedAssets=foreach($Name in $DSResults."NetBIOS Name" | Select-Object -Unique){$Name.split("\")[1]} #This is for calculating the missing assets

        "Sorting the results`n"

        foreach($row in $DSResults){

            if($row.'NetBios Name' -in $GoodAccess) { 
                #We only want the data from good access

                if($row.'Plugin Publication Date' -eq $null){
                    
                    $csv+=$row #If Publication Date is blank, move it over by default. It's probably just SSL

                } else {

                    #This section removes the results that are within 30 days. They don't count and SCCM should deal with them.

                    $row.'Plugin Publication Date'=$row.'Plugin Publication Date'.TrimEnd(' EST').TrimEnd(' EDT') #Trim EST and EDT notation from end of date

                    if([datetime]$row.'Plugin Publication Date' -lt $ignoredate){

                        $csv+=$row #The Plugin Publication Date is older than 30 days we want this
                    }
                }
            }
        }

        #Calculate CCRI Score based on severity of plugins

        foreach($Name in $GoodAccess){

            "Calculating CCRI score for $($Name.Split("\")[1])" 

            $presort=$csv | Where-Object {$_."Netbios Name" -like "$name"} #Only grab one name at a time

            #Count each category of vuln
            $CAT1=($presort.severity | Where-Object {$_ -match 'Critical' -or $_ -match 'High'}).count
            $CAT2=($presort.severity | Where-Object {$_ -match 'Medium'}).count
            $CAT3=($presort.severity | Where-Object {$_ -match 'Low'}).count

            $Score = [math]::round((($CAT1 * 10) + ($CAT2 * 4) + $CAT3) / 15,2) #These are the scores that DISA uses

            $results += [pscustomobject]@{"DNS Name"=$Name.Split("\")[1];"CCRI Score"=$Score;Updated="";Assigned="";Notes="";"Last Updated"=$date} #Export to results array
            }

        "`nDone"
        "`nExporting"

        #Exports the temp CSVs
        $csv | Export-Csv "$workingDir\$($date.replace('/','')) EnterpriseAssets.csv" -NoTypeInformation               #This array is used to collect all rows that we want to keep
        $results | Sort-Object "CCRI Score" -Descending | Export-Csv "$workingDir\CCRI SCORES.csv" -NoTypeInformation  #This array is used to calculate CCRI score

        #==============================================================================
        #Use the CSVs to create the XLSX report

        # Create Excel COM Object

        $xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlWorkbookDefault
        $excel = New-Object -ComObject excel.application
        $excel.EnableEvents = $false #This prevents the addins on SIPR from breaking the process
        $excel.visible=$true         #This allows the user to see the process

        # Create a "blank" workbook

        $reportOut = $excel.Workbooks.Add()

        # Open workbook and copy into $reportOut

        $wb = $excel.WorkBooks.Open("$workingDir\CCRI SCORES.csv")
        $wb.Worksheets.Item(1).Name = "CCRI SCORES"
        $wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
        $excel.columns.item("A:F").EntireColumn.AutoFit() | Out-Null
        $wb.Close(0)

        # Open workbook and copy into $reportOut

        $wb = $excel.WorkBooks.Open("$workingDir\$($date.replace('/','')) EnterpriseAssets.csv")
        $wb.Worksheets.Item(1).Name = "$($date.replace('/','')) EnterpriseAssets"
        $wb.Worksheets.Copy($reportOut.WorkSheets.Item(1))
        $excel.Rows.RowHeight = 15
        $wb.Close(0)

        # Delete "Sheet1"

        $reportOut.WorkSheets.Item(3).Delete() 

        # Saves Excel

        if($resultselector.FileName -match 'Enterprise'){

            #If these are the enterprise scans

            $missingAssets=$assets.Name | Where-Object {$scannedAssets -notcontains $_} | Sort-Object #Calculate based on enterprise asset list

            if($missingAssets){$missingAssets | Out-File "$workingDir\MissingEnterpriseAssets.txt"} #If any assets are missing export to txt

            $reportOut.SaveAs("$workingDir\$($date.replace('/','')) EnterpriseAssets.xlsx",$xlFixedFormat) #Save XLSX as Enterprise

        } else {

            #These are the local scans

            $missingAssets=$localassets | Where-Object {$scannedAssets -notcontains $_} | Sort-Object #Calculate based on the local asset list

            if($missingAssets.count -gt 0){$missingAssets | Out-File "$workingDir\MissingLocalAssets.txt"} #If any assets are missing export to txt

            $reportOut.SaveAs("$workingDir\$($date.replace('/','')) LocalAssets.xlsx",$xlFixedFormat) #Save XLSX as Local

        }

        Stop-Process -ProcessName EXCEL #Close Excel background process

        if($BadAccess){$BadAccess.ForEach{$_.split("\")[1]>>"$workingDir\BAD-ACCESS.txt"}} #If we have bad access export separate txt

    } else {

        #There were no DS Assets in the import

        "The results are missing all of our assets. Aborting.";pause

        if($resultselector.FileName -match 'Enterprise'){$assets.Name | Where-Object {$scannedAssets -notcontains $_} | Sort-Object | Out-File "$workingDir\MissingEnterpriseAssets.txt"} #Calculate based on enterprise asset list

        else{$localassets | Where-Object {$scannedAssets -notcontains $_} | Sort-Object | Out-File "$workingDir\MissingLocalAssets.txt"} #Calculate based on the local asset list

    }
}

#==============================================================================
#Cleans up regardless of what script does

"Performing cleanup"

Remove-Item "$workingDir\Unzip" -Force -Recurse #Removes the unzip folder

Get-ChildItem $workingDir -Filter *.csv | Remove-Item #Removes any leftover CSV files