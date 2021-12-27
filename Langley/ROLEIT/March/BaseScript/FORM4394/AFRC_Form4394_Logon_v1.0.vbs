
'region Authorship
' ========================================================
'
' 	Script Information
'	
'	Title:						AFRC_Form4394_Logon.vbs
'	Original Author:			Scott Ross @ Robins AFB (scott.ross.ctr@robins.af.mil / 478-926-8173)
'	Modified by:				Jason Hurst (jason.hurst.6.ctr@us.af.mil) & Bret See (breton.see.ctr@us.af.mil) of GDIT 
'	Modified date:				3/5/2012 - 09:08:13
'	Description:				Check for user's signed AF 4394 Form 
'	
' ========================================================

'endregion

'region Changelog
'3/1/2012 - 16:00:00 (BSee) Other - Version 1.0
'3/2/2012 - 17:00:00 (JHurst) Other - Modified script to be silent if digitally signed AF 4394 form is found.
'3/5/2012 - 09:16:32 (JHurst) Other - Corrected monitoring of forms process. 
'endregion
	
'region Constants & Variables
'****************************************************************************************************************************
'Set Constants For script
'****************************************************************************************************************************

' Setup the objects.
On Error Resume Next
Set objNetwork = WScript.CreateObject("WScript.Network")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
Set objMail = CreateObject("CDO.Message")

' Query AD for the User info.
vSAN = objNetwork.UserName
Set oRootDSE = GetObject("LDAP://rootDSE")
Set oConnection = CreateObject("ADODB.Connection")
oConnection.Open "Provider=ADsDSOObject;"
Set oCommand = CreateObject("ADODB.Command")
oCommand.ActiveConnection = oConnection
oCommand.CommandText = "<LDAP://" & oRootDSE.get("defaultNamingContext") & _
	">;(&(objectCategory=User)(samAccountName=" & vSAN & "));givenname;subtree"
Set oRecordSetGN = oCommand.Execute
oCommand.CommandText = "<LDAP://" & oRootDSE.get("defaultNamingContext") & _
	">;(&(objectCategory=User)(samAccountName=" & vSAN & "));sn;subtree"
Set oRecordSetSN = oCommand.Execute
oCommand.CommandText = "<LDAP://" & oRootDSE.get("defaultNamingContext") & _
	">;(&(objectCategory=User)(samAccountName=" & vSAN & "));initials;subtree"
Set oRecordSetMI = oCommand.Execute
oCommand.CommandText = "<LDAP://" & oRootDSE.get("defaultNamingContext") & _
	">;(&(objectCategory=User)(samAccountName=" & vSAN & "));mail;subtree"
Set oRecordSetMA = oCommand.Execute

' Make sure the user is from this base.
oCommand.CommandText = "<LDAP://" & oRootDSE.get("defaultNamingContext") & _
	">;(&(objectCategory=User)(samAccountName=" & vSAN & "));distinguishedName;subtree"
Set oRecordSetDN = oCommand.Execute
strDN = oRecordSetDN.Fields("distinguishedName")

If InStr(strDN, "March AFB") = 0 Then
	WScript.Quit
End If	

	Const ForReading = 1
	strComputer = "."
	
	Const adOpenStatic = 3
	Const adLockOptimistic = 3
	
	Set objFSO = CreateObject("Scripting.FileSystemObject")
	Set WshShell = WScript.CreateObject("WScript.Shell")
	Set WshNetwork = WScript.CreateObject("WScript.Network")
	Set objADSI = CreateObject("ADSystemInfo")
		
	sCurPath = CreateObject("Scripting.FileSystemObject").GetAbsolutePathName(".")
	ServerPath = "\\area52.afnoapps.usaf.mil\March_AFB\Logon_Scripts\BaseScript\FORM4394"
	StrNewUsersPath = "\\rivfs21\4394forms\"
	StrLocalLogon = "local.txt"
	StrNewFormFile = ServerPath & "\form4394.xfdl"
	StrUserFormStatus = "userformstatus.txt"
	StrUserFormStatusMsg = "Form 4394 has been signed"

'	strLogOffScript = ServerPath & "\LogOff_Form4394.vbs"
	strInstructionsPath = ServerPath & "\Instructions.vbs"
	strConstentPath = ServerPath & "\Consent.txt"
	strSignedFileSize = 15000
	strSigned2FileSize = 16000
	strFormProcess = "masqform.exe"
	
	StrIAMessage = "Information Assurance Message"
	StrMessageNoticeConsent = "  AIR FORCE USER AGREEMENT STATEMENT -  NOTICE AND CONSENT PROVISION  "
	StrMessageFormOnFile = "You have already signed the 4394 Form on file. Thank you."
	StrMessageUnsignedFile = "You have not digitally signed AF Form 4394. " & Chr(10) & Chr(10) &" Please call your Comm Focal Point if you have any questions. You will now be logged off."
	StrMessageSignedFile = "Thank you for digitally signing AF Form 4394. You may now close the form."

	
	StrUsername = wshNetwork.Username

	StrInstructionsFile = ServerPath & "\Instructions.txt"
	StrInstructionsHdr = "User Consent Form Instructions:"

'endregion
'****************************************************************************************************************************
' Check to see if 4394 folder can be accessed
'****************************************************************************************************************************
If objFSO.FileExists(StrNewUsersPath & StrLocalLogon) = False  Then
	WScript.Quit
End If

'****************************************************************************************************************************
'Check for other file types such as .jpg, pdf, tiff docs that may have been manually saved to the server path.
'****************************************************************************************************************************
If NoExistingForm() Then

'**********************************************************************************************************************************************************
'Monitor current running process to determine if user has closed form out. If form has been closed, check to see if user digitally signed and saved form.
'**********************************************************************************************************************************************************
	On Error Resume Next
		strCount = 0
		strProcess="masqform.exe"
		strProcess=UCase(strProcess)
		
			strFilePath = StrNewUsersPath & StrUsername & ".xfdl"
			If objFSO.FileExists(strFilePath) = False Then
				objFSO.CopyFile StrNewFormFile,strFilePath
			End If	
		
		Set strFile = objFSO.GetFile(strFilePath)
		strFileSize = strFile.Size
	
		If strFileSize > strSignedFileSize Then 'Properly signed form on file
			'MsgBox StrMessageFormOnFile
			WScript.quit
		End If
		

		If strFileSize < strSigned2FileSize Then
			'wshShell.run "wscript " & sCurpath & "\form4394Logoff.vbs"
			Set objTextFile = objFSO.OpenTextFile(strConstentPath, ForReading)
			strConsent = objTextFile.ReadAll
			objTextFile.Close
			MsgBox strConsent,0,StrMessageNoticeConsent
			wshShell.run  strFilePath
			'*********************************************************
			'Open Instructionsclose***********************************
			Set objTextFile = objFSO.OpenTextFile _
   				(StrInstructionsFile, ForReading)

				strInstructions = objTextFile.ReadAll
				objTextFile.Close


			'MSGBOX strInstructions,4096,StrInstructionsHdr

			strInstructions = "<font color=red><b>" & strInstructions & "<b></font>"

			with HTABox("lightgrey", 600, 600, 1, 1)
  			.document.title = StrInstructionsHdr
  			.msg.innerHTML = strInstructions
			Do While strFileSize < strSigned2FileSize
				strProcessRunning="No"
				objFSO.GetFile(strFilePath)
				'MsgBox strFilePath
				strFileSize = strFile.Size
				WScript.sleep 300
				strCount = strCount + 1
				If strCount = 1000 Then
					'wshShell.Popup "You have not digitally signed AF Form 4394 you will now be logged off" ,300,"Computer Support" ,48
					'wshShell.run "shutdown -l -f"
					'wscript.quit
				End If
				'*********************************************************
				'Check for running process
				'*********************************************************
				strComputer="."
				Dim objWMIService, strWMIQuery

				strWMIQuery = "Select * from Win32_Process where name like '" & strProcess & "'"
	
				Set objWMIService = GetObject("winmgmts:" _
					& "{impersonationLevel=impersonate}!\\" _ 
						& strComputer & "\root\cimv2") 


				if objWMIService.ExecQuery(strWMIQuery).Count > 0 then
					strProcessRunning="Yes"
				else
					strProcessRunning="No"
				end if

				'Set colProcess = objWMIService.ExecQuery ("Select * from Win32_Process")
				'For Each objProcess In colProcess
				'	strProcessName=UCase(objProcess.name)
				'	Msgbox(strProcessName)
				'	Msgbox(strProcess)	
				'	If strProcessName = strProcess Then
				'		strProcessRunning="Yes"
				'	End If
				'Next
				
				If strProcessRunning="No" Then
					objFSO.GetFile(strFilePath)
					strFileSize = strFile.Size
					'*************************************************************************************
					'Log User Off if they closed the form but did not digitally sign the form.
					'*************************************************************************************
					If strFileSize < strSigned2FileSize Then
							If objFSO.FileExists(strFilePath & "0") Then
								WScript.quit
							End If
						wshShell.Popup StrMessageUnsignedFile,300,StrIAMessage ,48
						WScript.sleep 10000
						wshShell.run "shutdown -l -f"
						WScript.quit
						
					Else 
					End If
				End If
				'wscript.echo strcount
			Loop
			  .done.value = true
  			  .close
			end with
			If strFileSize > strSigned2FileSize Then
				msgbox StrMessageSignedFile, vbSystemModal
				Set objTextFile = objFSO.OpenTextFile _
					(Serverpath & StrUserFormStatus, 8, True)
				objTextFile.Write(VbCRLF & Date & "," & Time & wshNetwork.ComputerName & "," & wshNetwork.UserName & "," & StrUserFormStatusMsg)
				objTextFile.Close
				WScript.quit
				
			End If
		
		Else
			WScript.quit
		
		End If
		
End If	
'-------------------------------------------------------------------------------------------------------

Function NoExistingForm()
	
'****************************************************************************************************************************
'Check for other file types such as .jpg, pdf, tiff docs that may have been manually saved to the server path.
'Folder Structure and Filename convention: First_Char_of_Username\Username\Username.pdf
'	i.e., AFNet Username = 1234567890X, where 1234567890 = employeeNumber or EDI, X = employeeType (C, A, V, E, N, K)
'****************************************************************************************************************************

	Set objFS = CreateObject("Scripting.FileSystemObject")
	StrFoundExistingFile = True
		
	StrFilePath = StrNewUsersPath  & StrUsername
	strPDFFilePath = StrFilePath & ".pdf"
	strxfdl0FilePath = StrFilePath & ".xfdl.0"
	strtifFilePath = StrFilePath & ".tif"
	strjpgFilePath = StrFilePath & ".jpg"
	strxfdFilePath = StrFilePath & ".xfd"
	strxpsFilePath = StrFilePath & ".xps"
	strxfdlFilePath = StrFilePath & ".xfdl"
	'objFS.GetFile(strxfdlFilePath)
	'strxfdlFileSize = strxfdlFile.size 
		
	If objFSO.FileExists(strPDFFilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strxfdl0FilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strtifFilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strjpgFilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strxfdFilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strxpsFilePath) Then
		StrFoundExistingFile = False
	ElseIf objFSO.FileExists(strxfdlFilePath)  Then
		StrFoundExistingFile = False
	End If
			
	NoExistingForm = StrFoundExistingFile
End Function

' Author Tom Lavedas, June 2010
Function HTABox(sBgColor, h, w, l, t)
Dim IE, HTA

  randomize : nRnd = Int(1000000 * rnd)
  sCmd = "mshta.exe ""javascript:{new " _
       & "ActiveXObject(""InternetExplorer.Application"")" _
       & ".PutProperty('" & nRnd & "',window);" _
       & "window.resizeTo(" & w & "," & h & ");" _
       & "window.moveTo(" & l & "," & t & ")}"""

  with CreateObject("WScript.Shell")
    .Run sCmd, 1, False
    do until .AppActivate("javascript:{new ") : WSH.sleep 10 : loop
  end with ' WSHShell

  For Each IE In CreateObject("Shell.Application").windows
    If IsObject(IE.GetProperty(nRnd)) Then
      set HTABox = IE.GetProperty(nRnd)
      IE.Quit
      HTABox.document.title = "HTABox"
      HTABox.document.write _
               "<HTA:Application contextMenu=no border=thin " _
             & "minimizebutton=no maximizebutton=no sysmenu=no />" _
             & "<body scroll=no style='background-color:" _
             & sBgColor & ";font:normal 10pt Arial;" _
             & "border-Style:outset;border-Width:3px'" _
             & "onbeforeunload='vbscript:if not done.value then " _
             & "window.event.cancelBubble=true:" _
             & "window.event.returnValue=false:" _
             & "done.value=true:end if'>" _
             & "<input type=hidden id=done value=false>" _
             & "<center><span id=msg>&nbsp;</span><center></body>"
      Exit Function
    End If
  Next

' I can't imagine how this line can be reached, but just in case
  MsgBox "HTA window not found."
  wsh.quit

End Function

'end of file


  