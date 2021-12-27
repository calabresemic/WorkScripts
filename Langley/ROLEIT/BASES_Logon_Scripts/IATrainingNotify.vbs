Option Explicit
'***********************************************************************************************************************
'*	Title:   IATrainingNotify.vbs
'*	Version: 1.6
'*	Date:    1 Nov 2011
'*	Author:  INE Directory Services
'*	Purpose: Logon Script to start providing notification to users when their IA Training Expiration date is a
'*               certain number of days away.  Provides warnings up until the very day their IA training expires.
'*
'*	Actions: Will take user to the AF Portal so they can log on and complete their training.
'*
'*	Updates: 16 Jun 2016 - Updated by Randy Shallenberger to provide additional instructions to the User and to replace the lines 	
'*		 referencing "Contact ESD for Assistance" with Contact "CFP for Assistance".
'***********************************************************************************************************************

'***********************************************************************************************************************
'* URL at which users can complete the training
'***********************************************************************************************************************
Const trainingURL= "https://golearn.adls.af.mil/"



Dim ADSysInfo
Dim objUser
Dim UserDN
Dim lastIATrainingDate
Dim nextIATrainingDueDate
Dim numDaysUntilDue
Dim dialogResult
Dim WshShell
Dim i
Dim messageBoxTitle
Dim trainingCourseTitle
Dim ie
Dim daysToNotify
Dim pcc




'***********************************************************************************************************************
'* Get Distinguished Name of User's AD Account
'***********************************************************************************************************************
Set WshShell = CreateObject("WScript.Shell")
Set ADSysInfo = CreateObject("ADSystemInfo")

'***********************************************************************************************************************
'* Simple kludge to work around slow network startup
'***********************************************************************************************************************
i = 0
On Error Resume Next

Do Until i = 3

	UserDN = ADSysInfo.UserName

	If Err Then
		wscript.sleep 4000

		i = i + 1

		If i = 3 Then
			'Couldn't retrieve UserName from ADSysInfo so exit. No network connectivity.
			wscript.quit
		End If
		Err.Clear
	Else
		Exit Do
	End If
Loop



'***********************************************************************************************************************
'* Bind to the user's AD account
'***********************************************************************************************************************
Set objUser = GetObject("LDAP://" & UserDN)

If Err Then

	'Couldn't bind to the user account so exit.  Probably due to network connectivity.
	wscript.quit

End If

On Error Goto 0



'***********************************************************************************************************************
'* Get user's personnel category and adjust how many days priot to expiration this warning is displayed
'***********************************************************************************************************************
On Error Resume Next

daysToNotify = 31

Err.Clear
pcc = objUser.Get("employeeType")

If Err Or pcc = vbEmpty Then
	wscript.quit
Else
	If pcc = "v" Or pcc = "V" Then
		daystoNotify = 91
	End If
End If

On Error Goto 0



'***********************************************************************************************************************
'* Exit if a non-standard user account (Org Box, Admin, Service Account) is logging on
'***********************************************************************************************************************
If objUser.gigid = vbEmpty Then

	wscript.quit

End If



'***********************************************************************************************************************
'* Get IA Training Info
'***********************************************************************************************************************
On Error Resume Next

Err.Clear
lastIATrainingDate = objUser.Get("iaTrainingDate")

If Err Or lastIATrainingDate = vbEmpty Then
	numDaysUntilDue = -1
Else
	nextIATrainingDueDate = DateAdd("yyyy", 1, lastIATrainingDate)
	numDaysUntilDue = DateDiff("d", Now, nextIATrainingDueDate)
End If

On Error Goto 0



'***********************************************************************************************************************
'* Message strings to display to the user
'***********************************************************************************************************************
messageboxTitle = "Air Force Information Assurance Training Reminder"
trainingCourseTitle = "DoD IAA CyberAwareness Challenge V2.0 (ZZ133098)"



'***********************************************************************************************************************
'* Display a message to the user based on their current training date status.
'***********************************************************************************************************************
If lastIATrainingDate = vbEmpty Then

	' iaTrainingDate is empty (or invalid) indicating the user has
	' never completed IA Training. Show

	dialogResult = MsgBox("You have no Information Assurance training date on your account. Department of " & _
			"Defense and Air Force regulations require all information system users complete this training." & _
			vbCRLF & vbCRLF & _
			"If you do not take this training, your network access will be restricted within 24 hours and remain " & _
			"restricted until you complete the course. Removal of the network restrictions may take up to 3 days after " & _
			"completing the IA Training Course." & chr(34) & trainingCourseTitle & chr(34) & " found on " & _
			"the ADLS website (" & trainingUrl & ")." & _
			vbCRLF & vbCRLF & _
			"Contact your local Comm Focal Point (CFP) for further assistance" & _
			vbCRLF & vbCRLF & _
			"Do you want to take the training now?", _
			vbYesNo + vbDefaultButton1 + vbCritical + vbSystemModal, messageboxTitle)





Elseif numDaysUntilDue = 0 Then

	' Training is expired right now. User must take training or
	' they will be caught by the automation (restricted logon).
	' Show stern warning to user.

	dialogResult = MsgBox("You last completed Information Assurance training on " & lastIATrainingDate & ". " & _
			"This training is an annual requirement and you must complete it immediately. Removal of the network restrictions " & _
			"may take up to 3 days after completing the IA Training Course." & _
			vbCRLF & vbCRLF & _
			"If you do not take this training, your network access will be restricted within 24 hours and remain " & _
			"restricted until you complete the course " & chr(34) & trainingCourseTitle & chr(34) & " found on " & _
			"the ADLS website (" & trainingUrl & ")." & _
			vbCRLF & vbCRLF & _
			"Contact your local Comm Focal Point (CFP) for further assistance" & _
			vbCRLF & vbCRLF & _
			"Do you want to take the training now?", _
			vbYesNo + vbDefaultButton1 + vbCritical + vbSystemModal, messageboxTitle)




Elseif numDaysUntilDue <= daystoNotify Then

	' Training will expire within the notification period (top
	' of script). Show friendly reminder to user

	dialogResult = MsgBox("You last completed Information Assurance training on " & lastIATrainingDate & ". " & _
			"This training is an annual requirement must be reaccomplished within " & numDaysUntilDue & " days " & _
			"to avoid network restriction. Recommend completion no later than 3 days prior to due date to avoid a potential lock out. " & _
			vbCRLF & vbCRLF & _
			"The training can be found on the ADLS site (" & trainingUrl & ") under the title " & _
			chr(34) & trainingCourseTitle & chr(34) & _
			vbCRLF & vbCRLF & _
			"Contact your local Comm Focal Point (CFP) for further assistance." & _
			vbCRLF & vbCRLF & _
			"Do you want to take the training now?", _
			vbYesNo + vbDefaultButton2 + vbInformation + vbSystemModal, messageboxTitle)
End If



'***********************************************************************************************************************
'* If the user clicked "yes" to complete the training, launch Internet Explorer and navigate to the ADLS URL
'***********************************************************************************************************************
If dialogResult = 6 Then
	On Error Resume Next

	Force32bitIE()

	Set ie = createobject("internetexplorer.application")
	ie.visible = True
	ie.navigate trainingURL
	
	'Do Until ie.readystate = 4 Or i > 30: wscript.sleep 1000 : i = i + 1 : Loop

	On Error GoTo 0
End If


'***********************************************************************************************************************
'* Forces 32 bit IE to be utilized instead of 64 bit IE which breaks the training link
'***********************************************************************************************************************

Sub Force32bitIE()

If InStr(UCase(WScript.FullName), "SYSTEM32") > 0 and CreateObject("Scripting.FileSystemObject").FolderExists("C:\Windows\SysWOW64") Then 

   Dim objShell : Set objShell = CreateObject("WScript.Shell") 
   objShell.CurrentDirectory = "C:\Windows\SysWOW64" 
   objShell.Run "wscript.exe " & WScript.ScriptFullName,1,False  
   WScript.Quit 

End If

End Sub



