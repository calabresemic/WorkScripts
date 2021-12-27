#######################################################################################################################
#	Title:   IATrainingRestrictedSession.ps1
#	Version: 1.0
#	Date:    14 DEC 2020 
#	Author:  NELSON, CHASE B CTR USAF ACC 690 NSS/CYSA
#   Co-Author: CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
#	Purpose: Logon Script to notify the logged on user that they are in a resricted logon session due to their
#		 expired IA Training. Instructs the user to complete their training and provide verification to their
#		 local CST or trusted agent. For VPN users it also opens the F5 VPN client for the user to connect back to the network
#   Sources: Converted from original IATrainingRestrictedSession.vbs script in the IA Training GPO "GPO-OU-U-BASES-IA Training Overdue - Restricted Logon Session"
# 
#	Actions: Displays a notification message to the user.  Stops Lync, Teams, and Outlook if running.
#######################################################################################################################

[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
$trainingURL = "https://golearn.adls.af.mil/login.aspx"
$f5vpn = "C:\Program Files (x86)\F5 VPN\f5fpclientW.exe"
#$ciscovpn = "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"
$restrictedMessageTitle = "IA Training Expired"
$RightsRestoredTitle = "Rights Restored"
$restrictedLogonMessage = "Access to local and network resources has been restricted because your IA Training has expired.
Login to ADLS and complete the DoD Information Assurance course. Access will be restored within 24 hours of completion.
Immediate access in the case of mission failure can be restored by contacting your Base Communication Focal Point (CFP) for further assistance.

Web browser only opens once per logon. Do not close it until you have completed the course.

Please remain connected to the network and you will be alerted when your access is restored.
For VPN users please connect to VPN prior to taking training, and remain connected, to allow check for restoration of access."

$RightsRestoredMessage = "Access to local and network resources has been restored.
Please restart your computer up to 3 times to allow it to process the changes."

$processtokill=@(
"explorer.exe",
"outlook.exe",
"lync.exe",
"Teams.exe"
)

###########################################################################################
#kill processes
###########################################################################################
foreach($process in $processtokill){

taskkill /F /IM $process

}
###########################################################################################
#popup message to user
###########################################################################################

[Microsoft.VisualBasic.Interaction]::Msgbox($restrictedLogonMessage,'OkOnly,SystemModal,Critical',$restrictedMessageTitle)

###########################################################################################
#test to see if user is connected to domain, if they are not it will open VPN applications
###########################################################################################

if(Test-Connection "afnoapps.usaf.mil"-Quiet){
    
    if(Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe'){& 'C:\Program Files\Google\Chrome\Application\chrome.exe' $trainingurl
    }else{
        $IE=new-object -com internetexplorer.application
        $IE.navigate2($trainingURL)
        $IE.visible=$true
        }

}else{

Start-Process $f5vpn
if(Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe'){& 'C:\Program Files\Google\Chrome\Application\chrome.exe' $trainingurl
}else{
    $IE=new-object -com internetexplorer.application
    $IE.navigate2($trainingURL)
    $IE.visible=$true}

#Wait for VPN to connect
Do{
Start-Sleep -Seconds 5
}Until(Test-Connection "afnoapps.usaf.mil"-Quiet)

}

#Check if the user is still in the restricted group
Do{
Start-Sleep -Seconds 60
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
if("GLS_ESD_IATRAINING_RESTRICTED" -notin $groups){$gpupdate=$true}
}Until($gpupdate)

gpupdate /force
[Microsoft.VisualBasic.Interaction]::Msgbox($RightsRestoredMessage,'OkOnly,SystemModal,Information',$RightsRestoredTitle)