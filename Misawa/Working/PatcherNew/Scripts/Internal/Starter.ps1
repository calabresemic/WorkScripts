[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms") | Out-Null

# Create the form
$start = New-Object Windows.Forms.Form
$start.StartPosition = "CenterScreen"
$start.AutoSize = $True
$start.AutoSizeMode = "GrowAndShrink"
$start.KeyPreview = $True
$start.topmost = $true

#Set the dialog title
$start.text = "Master Patch Script"

# Create the label control and set text, size and location
$startFont = New-Object System.Drawing.Font("Times New Roman",18)
$start.Font = $startFont
$startLabel = New-Object System.Windows.Forms.Label
$startLabel.Text = "Select From the Options Below:"
$startLabel.AutoSize = $True
$start.controls.add($startlabel)

# Create Button and set text and location
$startbutton1 = New-Object Windows.Forms.Button
$startbutton1.text = "Check Stale AD Computers"
$startbutton1.Location = New-Object Drawing.Point 0,55
$startbutton1.size = new-object drawing.point 350,40
$start.controls.add($startbutton1)
$startbutton1.add_click({
Start Powershell C:\Working\PatcherNew\Scripts\Internal\StaleComps.ps1
$start.Close()})

$startbutton2 = New-Object Windows.Forms.Button
$startbutton2.text = "Check AD Accounts for 1FA"
$startbutton2.Location = New-Object Drawing.Point 0,95
$startbutton2.size = new-object drawing.point 350,40
$start.controls.add($startbutton2)
$startbutton1.add_click({
Start Powershell C:\Working\PatcherNew\Scripts\Internal\Check1FA.ps1
$start.Close()})

$startbutton3 = New-Object Windows.Forms.Button
$startbutton3.text = "Ping and Continue"
$startbutton3.Location = New-Object Drawing.Point 0,135
$startbutton3.size = new-object drawing.point 350,40
$start.controls.add($startbutton3)
$startbutton3.add_click({
Start Powershell C:\Working\PatcherNew\Patch-Production.ps1
$start.Close()})

# Display the dialog
$start.showDialog()