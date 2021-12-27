#######################################################################################################################
#	Title:   IATrainingRestrictedSession.ps1
#	Version: 1.0
#	Date:    23 MAR 2021 
#   Author: CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
#	Purpose: Logon Script notify the logged on user that they are in a resricted logon session due to their
#		 expired IA Training. Instructs the user to complete their training and provide verification to their local CFP. 
#   Sources: Converted from original IATrainingRestrictedSession.vbs script in the IA Training GPO "GPO-OU-U-BASES-IA Training Overdue - Restricted Logon Session"
# 
#	Actions: Stops Lync, Teams, Explorer, and Outlook if running. Displays a notification message to the user. Opens LMS in default browser.
#######################################################################################################################


[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') | Out-Null
$trainingURL = "https://lms-jets.cce.af.mil"
$restrictedMessageTitle = "IA Training Expired"
$restrictedLogonMessage = @"
Access to local and network resources has been restricted
because your IA Training has expired.Login to LMS and
complete the DoD Information Assurance course.

Access will be restored within 24 hours of completion.
Immediate access in the case of mission failure can be
restored by contacting your Base Communication Focal Point
(CFP) for further assistance.

Web browser only opens once per logon. Do not close it
until you have completed the course.
"@

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

start $trainingurl