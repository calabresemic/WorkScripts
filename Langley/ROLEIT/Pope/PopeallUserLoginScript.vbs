'---------------------------------------------------------------------------------------------------------------------------------------------------------
'    Title:	      AFRCLogonKicker.vbs
'    Version:	      1.00
'    Date:	      April 26, 2010
'    Author:	      Kevin J Dillon 83 NOS/Langley ESU
'    Description:     GrissomLoginKicker.vbs initiates the execution of the AFRC enterprise script "COI_Ent.bat" from the local DFS share.  
'                     If script is not found, a messagebox error will be generated and logged to the workstation's application log.
'---------------------------------------------------------------------------------------------------------------------------------------------------------

ON ERROR RESUME NEXT

'-----------------------------------------------------------------------------------------------------------------------------------------------------------
'Declare Variables
'-----------------------------------------------------------------------------------------------------------------------------------------------------------

Dim scriptNameRemoveLeading, scriptNameRemoveTrailing, strDFSScriptSharePath
Const LOGON_SCRIPT = "EnterpriseScript.ps1"

'-----------------------------------------------------------------------------------------------------------------------------------------------------------
'Initialize Variables
'-----------------------------------------------------------------------------------------------------------------------------------------------------------

Set objFSO	          = CreateObject("Scripting.FileSystemObject")
Set objShell 	          = WScript.CreateObject("WScript.Shell")
strDFSScriptSharePath 	  = objFSO.GetParentFolderName(WScript.ScriptFullname) & "\"
strDFSLogonScript	  = strDFSScriptSharePath & LOGON_SCRIPT
strDFSLogonCommand        = "powershell -noexit -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -file " & strDFSLogonScript

'-----------------------------------------------------------------------------------------------------------------------------------------------------------
'Main
'-----------------------------------------------------------------------------------------------------------------------------------------------------------

If objFSO.fileExists(strDFSLogonScript) Then

	Set objShell = CreateObject("Wscript.shell")
	objShell.run(strDFSLogonCommand)

Else

	msgBox "Login script failed to execute due to a missing file or improper configuration.  " & vbcrlf & vbcrlf & _
               "Please contact your script administrator for assistance with this issue." & vbcrlf & vbcrlf & _
	       "Error: " & LOGON_SCRIPT & " not found in " & strDFSScriptSharePath & vbcrlf,48,"Login Script Failure"

End If

'------------------------------------------------------------------------------------------------------------------------------------------------------------
'	Name: Generate_Log_Error()
'	Purpose: This fucntion will log errors to the application log.
'	Parameters: none 
'------------------------------------------------------------------------------------------------------------------------------------------------------------

Function Generate_Log_Error(errorMessage)
	Const EVENT_SUCCESS = 2
	objShell.LogEvent EVENT_ERROR, errorMessage
End Function