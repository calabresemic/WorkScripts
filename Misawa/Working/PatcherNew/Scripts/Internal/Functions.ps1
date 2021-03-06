#Variables
$updatesps1 = "C:\Working\PatcherNew\Scripts\External\Updates.ps1"
$updatesRps1 = "C:\Working\PatcherNew\Scripts\External\UpdatesR.ps1"
$officeps1 = "C:\Working\PatcherNew\Scripts\External\Office.ps1"
$officeRps1 = "C:\Working\PatcherNew\Scripts\External\OfficeR.ps1"
$3rdpartyps1 = "C:\Working\PatcherNew\Scripts\External\3rdParty.ps1"
$3rdpartyRps1 = "C:\Working\PatcherNew\Scripts\External\3rdPartyR.ps1"
$reportps1 = "C:\Working\PatcherNew\Scripts\External\Report.ps1"
$uninstallps1 = "C:\Working\PatcherNew\Scripts\External\Uninstall.ps1"
$sysinfops1 = "C:\Working\PatcherNew\Scripts\External\SysInfo.ps1"
$mcupdateps1 = "C:\Working\PatcherNew\Scripts\External\McUpdate.ps1"
$agentps1 = "C:\Working\PatcherNew\Scripts\External\Agent.ps1"
$datps1 = "C:\Working\PatcherNew\Scripts\External\DAT.ps1"
$mcafeeinfops1 = "C:\Working\PatcherNew\Scripts\External\McAfeeInfo.ps1"
$servicestarterps1 = "C:\Working\PatcherNew\Scripts\Internal\servicestarter.ps1"
   
    Function Menu
    #Replaces the old menu system with pop-up menu
    #To add a new menu item copy the button block and change the variable numbers and the drawing points, follow the pattern.
{
[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null

# Create the form
$form = New-Object Windows.Forms.Form
$Form.StartPosition = "CenterScreen"
$Form.AutoSize = $True
$Form.AutoSizeMode = "GrowAndShrink"
$form.KeyPreview = $True
$form.topmost = $true

#Set the dialog title
$form.text = "Master Patch Script"

# Create the label control and set text, size and location
$Font = New-Object System.Drawing.Font("Times New Roman",16)
$Form.Font = $Font
$Label = New-Object System.Windows.Forms.Label
$Label.Text = "Select From the Options Below:"
$Label.AutoSize = $True
$form.controls.add($label)

# Create Button and set text and location
$button1 = New-Object Windows.Forms.Button
$button1.text = "Install ALL Patches"
$button1.Location = New-Object Drawing.Point 0,55
$button1.size = new-object drawing.point 350,30
$form.controls.add($button1)
$button1.add_click({
$script:batch = 1
$form.close()
})

$button2 = New-Object Windows.Forms.Button
$button2.text = "Taskkill/Install Office Patches"
$button2.Location = New-Object Drawing.Point 0,85
$button2.size = new-object drawing.point 350,30
$form.controls.add($button2)
$button2.add_click({
$script:batch = 2
$form.close()
})

$button3 = New-Object Windows.Forms.Button
$button3.text = "Install 3rd Party"
$button3.Location = New-Object Drawing.Point 0,115
$button3.size = new-object drawing.point 350,30
$form.controls.add($button3)
$button3.add_click({
$script:batch = 3
$form.close()
})

$button4 = New-Object Windows.Forms.Button
$button4.text = "Report Installed Patches"
$button4.Location = New-Object Drawing.Point 0,145
$button4.size = new-object drawing.point 350,30
$form.controls.add($button4)
$button4.add_click({
$script:batch = 4
$form.close()
})

$button5 = New-Object Windows.Forms.Button
$button5.text = "Check Installed Programs"
$button5.Location = New-Object Drawing.Point 0,175
$button5.size = new-object drawing.point 350,30
$form.controls.add($button5)
$button5.add_click({
$script:batch = 5
$form.close()
})

$button6 = New-Object Windows.Forms.Button
$button6.text = "Uninstall Programs"
$button6.Location = New-Object Drawing.Point 0,205
$button6.size = new-object drawing.point 350,30
$form.controls.add($button6)
$button6.add_click({
        #Creates a new pop-up window that allows the user to select the program to uninstall or enter a custom name
        $popup = New-Object Windows.Forms.Form
        $popup.StartPosition = "CenterScreen"
        $popup.text = "Uninstaller"
        $popup.AutoSize = $True
        $popup.AutoSizeMode = "GrowAndShrink"
        $popup.TopMost = $True
        
        $pFont = New-Object System.Drawing.Font("Times New Roman",12)
        $popup.Font = $pFont
        $pLabel = New-Object System.Windows.Forms.Label
        $pLabel.Text = "Select From the Options Below:"
        $pLabel.AutoSize = $True
        $popup.controls.add($plabel)
        
        $pbutton1 = New-Object Windows.Forms.Button
        $pbutton1.text = "Google Chrome"
        $pbutton1.Location = New-Object Drawing.Point 0,35
        $pbutton1.size = new-object drawing.point 130,30
        $popup.controls.add($pbutton1)
        $pbutton1.add_click({
        $script:program = "Google Chrome"
        $script:batch = 6
        $popup.close()
        })

        $pbutton2 = New-Object Windows.Forms.Button
        $pbutton2.text = "Silverlight"
        $pbutton2.Location = New-Object Drawing.Point 140,35
        $pbutton2.size = new-object drawing.point 130,30
        $popup.controls.add($pbutton2)
        $pbutton2.add_click({
        $script:program = "Microsoft Silverlight"
        $script:batch = 6
        $pform.Close()
        })

        $ptextBox = New-Object System.Windows.Forms.TextBox 
        $ptextBox.Location = New-Object System.Drawing.Point(0,70) 
        $ptextBox.Size = New-Object System.Drawing.Size(200,30) 
        $popup.Controls.Add($ptextBox) 

        $OKButton = New-Object System.Windows.Forms.Button
        $OKButton.Location = New-Object System.Drawing.Size(210,70)
        $OKButton.Size = New-Object System.Drawing.Size(60,23)
        $OKButton.Text = "OK"
        $OKButton.Add_Click({$script:program = $ptextbox.Text;$popup.Close()})
        $popup.Controls.Add($OKButton)
        
        $popup.showDialog()

$script:batch = 6
$form.close()
})

$button7 = New-Object Windows.Forms.Button
$button7.text = "View Uptime and Disk Size"
$button7.Location = New-Object Drawing.Point 0,235
$button7.size = new-object drawing.point 350,30
$form.controls.add($button7)
$button7.add_click({
$script:batch = 7
$form.close()
})

$button8 = New-Object Windows.Forms.Button
$button8.text = "View Logged On Users"
$button8.Location = New-Object Drawing.Point 0,265
$button8.size = new-object drawing.point 350,30
$form.controls.add($button8)
$button8.add_click({
$script:batch = 8
$form.close()
})

$button9 = New-Object Windows.Forms.Button
$button9.text = "Update McAfee"
$button9.Location = New-Object Drawing.Point 0,295
$button9.size = new-object drawing.point 350,30
$form.controls.add($button9)
$button9.add_click({
$script:batch = 9
$form.close()
})

$button10 = New-Object Windows.Forms.Button
$button10.text = "ReInstall McAfee Agent"
$button10.Location = New-Object Drawing.Point 0,325
$button10.size = new-object drawing.point 350,30
$form.controls.add($button10)
$button10.add_click({
$script:batch = 10
$form.close()
})

$button11 = New-Object Windows.Forms.Button
$button11.text = "Update McAfee DAT File"
$button11.Location = New-Object Drawing.Point 0,355
$button11.size = new-object drawing.point 350,30
$form.controls.add($button11)
$button11.add_click({
$script:batch = 11
$form.close()
})

$button12 = New-Object Windows.Forms.Button
$button12.text = "View McAfee Engine/DAT Version"
$button12.Location = New-Object Drawing.Point 0,385
$button12.size = new-object drawing.point 350,30
$form.controls.add($button12)
$button12.add_click({
$script:batch = 12
$form.close()
})

$button13 = New-Object Windows.Forms.Button
$button13.text = "Start a Service"
$button13.Location = New-Object Drawing.Point 0,415
$button13.size = new-object drawing.point 350,30
$form.controls.add($button13)
$button13.add_click({
$script:batch = 13
$form.close()
})

#Adds the escape key to close the form
$form.add_KeyDown({
if ($_.KeyCode -eq "Escape"){
$script:batch = 100
$form.close()}
})

# Display the dialog
$form.showDialog() | Out-Null
}

    Function RUN ($script, $int) #This is what runs the multi-window function. Don't touch it.
{
    $computers = $compute = @()
    $computers = $list
    $compute = $computers
    
    $count = $compute.count
    [int]$totalscriptcount = $int
    [int]$compeach = [math]::truncate($count/$totalscriptcount)
    $array = @()

    $array = 1..$totalscriptcount
    $currentscriptcount = 1
    $i = 1

    Foreach($entry in $array)
        {
        [int]$beginarray = $($compeach*($currentscriptcount-1))
        [int]$endarray = $($compeach*$currentscriptcount)
        If($currentscriptcount -eq 1){$compute = @($computers[$beginarray..$endarray])}
        Else{$compute = @($computers[($beginarray+1)..$endarray])}
        "List $($i) has $($compute.count) computers in it"
        "First computer is $($compute[0]), last computer is $($compute[-1])"
        #script to be ran
        Start-Process powershell.exe "$script $compute"
        $i++
        $currentscriptcount++
        }
        
}

    Function LOG
    #Creates a file that outputs the computer name and the results of the PsExec process
    #Update: there is also a file stored on the client with a log in C:\NCCLogs
{
If($LASTEXITCODE -eq "0"){
$line = New-Object PSObject -Property @{ Computer=$computer; Result="Success" }
$exitcode += ,$line}
ElseIF($LASTEXITCODE -eq "3010"){
$line = New-Object PSObject -Property @{ Computer=$computer; Result="Restart Needed"}
$exitcode += ,$line}
ElseIF($LASTEXITCODE -eq "2359302"){
$line = New-Object PSObject -Property @{ Computer=$computer; Result="One or More Updates N/A"}
$exitcode += ,$line}
ElseIF($LASTEXITCODE -eq "-2145124329"){
$line = New-Object PSObject -Property @{ Computer=$computer; Result="Wrong OS"}
$exitcode += ,$line}
ElseIF($LASTEXITCODE -eq "15"){
$line = New-Object PSObject -Property @{ Computer=$computer; Result="McAfee Updated"}
$exitcode += ,$line}
Else{$line = New-Object PSObject -Property @{ Computer=$computer; Result="Failed error:$LASTEXITCODE"}
$exitcode += ,$line}
#Attempts to write to log until it succeeds which still doesn't always work
#This log method only shows the exit code of psexec so it's not the most accurate. 
do{
    $done = $true
    try{
        $exitcode | Export-Csv -NoTypeInformation -Append C:\Working\PatcherNew\Results\results.csv
    }
    Catch{
        $done = $false
        Start-Sleep -Milliseconds $(Get-Random -Minimum 1000 -Maximum 10000)
    }
}until($done)
}

    Function Restart
    #Schedules a restart on the target computer with a prompt that warns user of restart in 10 minutes
    #you can change the location of the .bat file to somewhere else if you would like.
{
schtasks /create /s $Computer /sc once /ru SYSTEM /tn restart /tr "\\52qkkg-hc-001v\LogonScripts\schedule.bat" /st 23:59 /f
}

    Function PSUpdate
    #Runs the PsExec process on the target computer and will retry once if it doesn't work the first time
    #Have run into problems with many computers not starting successfully the first time at Andersen
{
    PsExec -accepteula \\$Computer -s -f -c C:\Working\PatcherNew\Scripts\External\Updates.bat
    If($LASTEXITCODE -ne "0" -or "3010" -or "2359302" -or "-2145124329"){
    Start-Sleep -Milliseconds $(Get-Random -Minimum 1000 -Maximum 10000)
    PsExec -accepteula \\$Computer -s -f -c C:\Working\PatcherNew\Scripts\External\Updates.bat}
}

    Function PSOffice
    #Runs the PsExec process on the target computer and will retry once if it doesn't work the first time
    #Have run into problems with many computers not starting successfully the first time at Andersen
{
    PsExec -accepteula \\$Computer -s -f -c C:\Working\PatcherNew\Scripts\External\Office.bat
    If($LASTEXITCODE -ne "0" -or "3010" -or "2359302" -or "-2145124329"){
    Start-Sleep -Milliseconds $(Get-Random -Minimum 1000 -Maximum 10000)
    PsExec -accepteula \\$Computer -s -f -c C:\Working\PatcherNew\Scripts\External\Office.bat}
}


        function PromptRestart
    #Opens a window to allow user to select if they want to schedule restart on client machines
{
        $fp = New-Object Windows.Forms.Form
        $fp.StartPosition = "CenterScreen"
        $fp.AutoSize = $True
        $fp.AutoSizeMode = "GrowAndShrink"
        $fp.KeyPreview = $True
        $fp.topmost = $true
        $fp.text = "Full Patcher"
        $Font = New-Object System.Drawing.Font("Times New Roman",16)
        $fp.Font = $Font
        $fpl = New-Object System.Windows.Forms.Label
        $fpl.Text = "Schedule Restart?"
        $fpl.AutoSize = $True
        $fp.controls.add($fpl)

        $button1 = New-Object Windows.Forms.Button
        $button1.text = "Yes"
        $button1.Location = New-Object Drawing.Point 0,35
        $button1.size = new-object drawing.point 250,30
        $fp.controls.add($button1)
        $button1.add_click({
        $script:restart = $true
        $fp.close()})

        $button2 = New-Object Windows.Forms.Button
        $button2.text = "No"
        $button2.Location = New-Object Drawing.Point 0,65
        $button2.size = new-object drawing.point 250,30
        $fp.controls.add($button2)
        $button2.add_click({
        $script:restart = $false
        $fp.Close()})
        $fp.showDialog() | Out-Null
}

        function GetInstalledPrograms
{
        $array = @()
        $64Key="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        $32Key="SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
        $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',"$computer") 
        $regkey=$reg.OpenSubKey($64Key)
        $subkeys=$regkey.GetSubKeyNames()
            foreach($key in $subkeys)
            {
                $thisKey=$64Key+"\\"+$key 
                $thisSubKey=$reg.OpenSubKey($thisKey)
                if (-not $thisSubKey.getValue("DisplayName")) { continue } 
                    $obj = New-Object PSObject
                    $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
                    $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
                $array += $obj
            }

        $regkey=$reg.OpenSubKey($32Key)
        $subkeys=$regkey.GetSubKeyNames()
            foreach($key in $subkeys)
            {
                $thisKey=$32Key+"\\"+$key 
                $thisSubKey=$reg.OpenSubKey($thisKey)
                if (-not $thisSubKey.getValue("DisplayName")) { continue } 
                    $obj = New-Object PSObject
                    $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
                    $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
                $array += $obj}

        $array | Where-Object {$_.DisplayName -notmatch "update for"} | Sort-Object DisplayName | Out-File -Force "C:\Working\PatcherNew\Results\Installed Programs\$computer.txt"

}