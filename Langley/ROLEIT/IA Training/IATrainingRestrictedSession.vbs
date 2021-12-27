'***********************************************************************************************************************
'*	Title:   IATrainingRestrictedSession.vbs
'*	Version: 1.0
'*	Date:    4 MAR 2011 
'*	Author:  INE Directory Services
'*	Purpose: Logon Script to start notify the logged on user that they are in a resricted logon session due to their
'*		 expired IA Training.  Instructs the user to complete their training and provide verification to their
'*		 local CST or trusted agent.
'* 
'*	Actions: Displays a notification message to the user.  Stops Communicator and Outlook if running.
'***********************************************************************************************************************

Dim restrictedLogonMessage, restrictedMessageTitle, trainingURL

'************************************URL at which users can complete the training**************************************
'trainingURL = "https://golearn.adls.af.mil/"  'ADLS
trainingURL = "https://www.my.af.mil"  'ADLS
'______________________________________________________________________________________________________________________

restrictedMessageTitle = "Network Compliance Action Required"
restrictedLogonMessage = MsgBox("Access to local and network resources has been restricted because your IA Training has expired. " &_
                         "Login to ADLS and complete the DoD Information Assurance course." & vbCrLf & vbCrLf &_
                         "Access will be restored within 24 hours of completion. Immediate access in the case of mission " &_
                         "failure can be restored by contacting your Base Communication Focal Point (CFP) for further assistance." & VbCrLf & VbCrLf &_
			 "Internet Explorer only opens once per logon. Do not close it until you have completed the course.", _
                         vbCritical + vbSystemModal, restrictedMessageTitle)
