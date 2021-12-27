###this script is to let all all users with the 640 laptop model to know they need to get with the CFP before
###August 11 2017 to get there computers reimaged.


$PCName = (Get-WmiObject -Class Win32_ComputerSystem).name
$model = (Get-WmiObject -Class Win32_ComputerSystem).Model
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$cg = $security = Get-CimInstance -Query "SELECT * FROM Win32_DeviceGuard" -Namespace root\Microsoft\Windows\DeviceGuard -OperationTimeoutSec 15

#Hits all Machines that are not WIN10 and CG compliant

If (($cg.SecurityServicesRunning -notcontains '1') -or ($os -notmatch "Windows 10") -and ($model -notlike "*virtual*"))
{
    $wshell = New-Object -ComObject Wscript.Shell
    $wshell.Popup("In an effort to increase the IT security posture of the DoD, all computer workstations must run Windows 10 operating system.  Your workstation has been identified as being compatible and must be upgraded.`n`r`n`rAt your earliest possible convenience, please contact AFRC Comm Focal Point using the vESD icon to schedule a time for your computer to be reloaded to the latest Windows 10 image. Click the vESD icon, click Hardware and click Other (bottom right) to skip automated troubleshooting.",0,"Notification",0x0)
    
    }



If (($cg.SecurityServicesRunning -notcontains '1') -or ($os -notmatch "Windows 10") -and ($model -notlike "*virtual*"))
{
Add-Type -AssemblyName PresentationFramework

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

$objForm = New-Object System.Windows.Forms.Form 
$objForm.Text = "Windows 10 MTO"
$objForm.Size = New-Object System.Drawing.Size(825,300)
$objForm.StartPosition = "CenterScreen"
$objForm.KeyPreview = $True
$objForm.BackColor = "red"
$objForm.Font = New-Object System.Drawing.Font("Arial Black",12)
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Enter") 
    {$x=$objTextBox.Text;$objForm.Close()}})
$objForm.Add_KeyDown({if ($_.KeyCode -eq "Escape") 
    {$objForm.Close()}})

#$OKButton = New-Object System.Windows.Forms.Button
#$OKButton.Location = New-Object System.Drawing.Size(285,200)
#$OKButton.AutoSize = $True
#$OKButton.Text = "Sign Up"
#$OKButton.BackColor = "white"
#$OKButton.Add_Click({
#$IE=new-object -com internetexplorer.application
#$IE.navigate2("https://afrc.eim.us.af.mil/sites/Tier0/Lists/2570SignUp/NewForm.aspx?RootFolder=")
#$IE.visible=$true
#$x=$objTextBox.Text;$objForm.Close()
#$objForm.Close()})
#$objForm.Controls.Add($OKButton)

#$CancelButton = New-Object System.Windows.Forms.Button
#$CancelButton.Location = New-Object System.Drawing.Size(450,200)
#$CancelButton.Size = New-Object System.Drawing.Size(75,23)
#$CancelButton.AutoSize = $True
#$CancelButton.Text = "Cancel"
#$CancelButton.BackColor = "white"
#$CancelButton.Visible = $true
#$CancelButton.Add_Click({$objForm.Close()})
#$objForm.Controls.Add($CancelButton)

$objLabel = New-Object System.Windows.Forms.Label
$objLabel.Location = New-Object System.Drawing.Size(10,20) 
$objLabel.autoSize = $true 
$objLabel.Text = "                                    ***WINDOWS 10 MTO Compliance***
This workstation has been identified as noncompliant and will be disabled 1 April 2018. 
Please coordinate with your unit Equipment Manager to drop off your machine to the 
Communications Focal Point as soon as possible. Per AFMAN 33-152, 2.6.1, backing up 
personal data stored locally on a machine IS the responibility of the user. 
If you have already been upgraded and are still seeing this message, open a ticket 
via the vESD icon on your desktop."

$objForm.Controls.Add($objLabel) 
$objForm.Topmost = $True
$objForm.Add_Shown({$objForm.Activate()})
[void] $objForm.ShowDialog()

$x


}
##test
#If (($cg.SecurityServicesRunning -notcontains '1') -or ($os -notmatch "Windows 10") -and ($model -notlike "*virtual*"))
#    {
#Set-ItemProperty -Name 'Wallpaper' -path 'HKCU:\Control Panel\Desktop' -Value "\\uhhz-fs-014\AFRC_ALL_ADMINS_SHARED\Functional Areas\Automation\Scripts-Developmen\Modify Reg Keys Remotely\MTOWarningWallpaper.png"
#Set-ItemProperty -Name 'WallpaperStyle' -path 'HKCU:\Control Panel\Desktop' -Value "2"
#}
#Elseif((Get-ItemProperty -Name Wallpaper 'HKCU:\Control Panel\Desktop').wallpaper -like "*MTOWarningWallpaper.png*")
#{
#
#Set-ItemProperty -Name 'Wallpaper' -path 'HKCU:\Control Panel\Desktop' -Value "C:\Windows\Web\Wallpaper\Windows\img0.jpg"
#
#}