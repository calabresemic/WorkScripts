$ProfileDesktop = [Environment]::GetFolderPath("Desktop")
$ProfilePath = $ProfileDesktop -replace '\\desktop',''
$Threshold = 80 # as percentage
$Quota = '5GB'

if($ProfilePath -notmatch 'VDI_PROFILES'){return "VDIovercommitted.ps1 not run | Thick Client"}
if (Test-Path $ProfilePath){  
    
    $ProfileSize = (Get-ChildItem $ProfilePath -Recurse |
        Measure-Object -Property Length -Sum -ErrorAction Stop).sum

    if ($ProfileSize/$Quota*100 -gt $Threshold){

        $MessageTitle = "AFRCServiceDesk - VDI Profile Storage Overcommitted"
        $Message = "Your Zero Client profile size is $([math]::Round($ProfileSize/1GB,1))GB. 
Please clean your profile data to remain under 4.5GB. 

Your Zero Client profile can be found here: 

    $ProfilePath\

You can reduce your profile data size by performing the following actions:
 - Migrate Outlook PST emails to CHES.
 - Move mission data to the appropriate organizational fileshare.
 - Remove non-work related media to maintain your storage quota.

Overcommitted profile sizes will result in functional failure of the 
Windows environment.

If you experience difficulties with reducing your profile size, 
please use the ServiceNow icon on your desktop to open a support ticket."

        Add-Type -AssemblyName PresentationFramework
 
        $window = New-Object Windows.Window
        $window.Title = $MessageTitle
        $window.WindowStartupLocation = 'CenterScreen'
        $window.Foreground = "black"
        $window.Background = "yellow"
        $window.FontSize = "14"
        $window.FontWeight = "bold"
        $window.Topmost = $true
        $TextBlock = New-Object System.Windows.Controls.TextBlock
        $TextBlock.Text = $Message
        $TextBlock.Margin = 20
        $window.Content = $TextBlock
        $window.SizeToContent = 'WidthAndHeight'
        $null = $window.ShowDialog()

        $Email = (get-aduser $env:username -Properties mail).mail
        if ($email -ne '' -or $email -ne $null){
            Send-MailMessage -SmtpServer "mail1.us.af.mil" -To $email -From "donotreply-AFRCServiceDesk@us.af.mil" -Subject $MessageTitle -Body $Message
        } # IF Email
    } # If Quota
} # If Path


<#


$Source = '\\uhhz-fs-014\AFRC_ALL_ADMINS_SHARED\Functional Areas\Automation\Scripts-Production\Logon Backup\LogonScripts\BaseScript\Custom\VDIovercommitted.ps1'
$Destination = 
    '\\52UHHZ-HC-003V\LogonScripts\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\LogonScripts\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\ARPC_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\ARPC_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Carswell_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Carswell_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Dobbins_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Dobbins_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Grissom_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Grissom_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Homestead_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Homestead_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\March_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\March_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Minneapolis_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Minneapolis_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Niagara_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Niagara_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Pittsburgh_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Pittsburgh_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Westover_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Westover_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-003V\Youngstown_Logon\BaseScript\Custom\VDIovercommitted.ps1',
    '\\52UHHZ-HC-004V\Youngstown_Logon\BaseScript\Custom\VDIovercommitted.ps1'

$Destination | % { Copy-Item $source $_ -verbose}


#>

