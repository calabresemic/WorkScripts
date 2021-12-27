#***********************************************************************************************************************
#*	Title:   IATrainingNotify.ps1
#*	Version: 2.0
#*	Date:    19 Jan 2021
#*	Author:  CALABRESE, MICHAEL K SSgt USAF ACC 83 NOS/CYOD
#*	Purpose: Logon Script to start providing notification to users when their IA Training Expiration date is a
#*           certain number of days away. Provides warnings up until the very day their IA training expires.
#*
#*	Actions: Will take user to the AF Portal so they can log on and complete their training.
#***********************************************************************************************************************
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$iatrainingdate = $adobj.Properties.iatrainingdate
$displayiadate = ("$iatrainingdate").Split(' ')[0]
$emptype = $adobj.Properties.employeetype
$gigid = $adobj.Properties.gigid
$duedate = $iatrainingdate.addyears(1)
$trainingURL = "https://lms-jets.cce.af.mil"
$trainingcoursetitle = "Cyber Awareness Challenge 2021 (ZZ133098)"
$MessageTitle = "Air Force Information Assurance Training Reminder"
$today = Get-Date

#Get user's personnel category and adjust how many days priot to expiration this warning is displayed
Switch($emptype){
    V        {$warningdate = $duedate.adddays(-91)}
    Default  {$warningdate = $duedate.adddays(-31)}
    }

#Exit if a non-standard user account (Org Box, Admin, Service Account) is logging on
if(!($gigid)){Exit}

#Display a message to the user based on their current training date status.
Add-Type -AssemblyName Microsoft.VisualBasic

#iaTrainingDate is empty (or invalid) indicating the user has never completed IA Training.
#Show stern warning to user.
if(!($iatrainingdate)){
    $DialogMessage = @"
You have no Information Assurance training date on your
account. Department of Defense and Air Force regulations
require all information system users complete this training.

If you do not take this training, your network access will be
restricted within 24 hours and remain restricted until you
complete the course. Removal of the network restrictions may
take up to 3 days after completing the IA Training
Course: $trainingcoursetitle
found on the LMS website ($trainingURL).

Contact your local Comm Focal Point (CFP) for further assistance.

IF YOU ARE ON VPN WHEN YOUR TRAINING EXPIRES YOU WILL HAVE TO CONNECT YOUR DEVICE TO THE BASE NETWORK AND WAIT UP TO 3 DAYS TO RESTORE ACCESS.

Do you want to take the training now?
"@

$result=[Microsoft.VisualBasic.Interaction]::Msgbox($DialogMessage,'systemmodal,YesNo,Critical',$MessageTitle)}

#Training will expire within the notification period (top of script). 
#Show friendly reminder to user.
If (($today -lt $duedate) -and ($today -gt $warningdate)) {
    $DialogMessage = @"
You last completed Information Assurance training on
$displayiadate. This training is an annual requirement and
must be reaccomplished within $(($duedate - $today).Days) days to 
avoid network restriction. Recommend completion no later 
than 3 days prior to due date to avoid a potential lock out.

The training can be found on the LMS site ($trainingURL) under the title $trainingcoursetitle.

Contact your local Comm Focal Point (CFP) for further assistance.

IF YOU ARE ON VPN WHEN YOUR TRAINING EXPIRES YOU WILL HAVE TO CONNECT YOUR DEVICE TO THE BASE NETWORK AND WAIT UP TO 3 DAYS TO RESTORE ACCESS.

Do you want to take the training now?
"@

$result=[Microsoft.VisualBasic.Interaction]::Msgbox($DialogMessage,'systemmodal,YesNo,Information',$MessageTitle)}

#Training is expired right now. User must take training or they will be caught by the automation (restricted logon). 
#Show stern warning to user.
If ($today -ge $duedate) {
    $DialogMessage = @"
You last completed Information Assurance training on
$displayiadate. This training is an annual requirement and
you must complete it immediately. Removal of the network
restrictions may take up to 3 days after completing the IA Training Course.

If you do not take this training, your network access will be
restricted within 24 hours and remain restricted until you
complete the course $trainingcoursetitle found on the LMS website
($trainingURL).

Contact your local Comm Focal Point (CFP) for further assistance.

IF YOU ARE ON VPN WHEN YOUR TRAINING EXPIRES YOU WILL HAVE TO CONNECT YOUR DEVICE TO THE BASE NETWORK AND WAIT UP TO 3 DAYS TO RESTORE ACCESS.

Do you want to take the training now?
"@

$result=[Microsoft.VisualBasic.Interaction]::Msgbox($DialogMessage,'systemmodal,YesNo,Critical',$MessageTitle)}

#If the user clicked "yes" to complete the training, launch default browser and navigate to the ADLS URL
if($result -eq "Yes"){start $trainingURL}