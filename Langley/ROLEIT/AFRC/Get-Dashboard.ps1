<# Revision History
 #11 Jan 2021 - Michael Calabrese (1468714589) - Commented out lines 1216 & 1241 to prevent error messages to users after VirusScanEnterprise > Endpoint Security
#>

#region: Style
# Set position of form object
Function DrawPoint([int]$y,[int]$x) 
{
    $Location = New-Object System.Drawing.Point("$y","$x")
    return $Location
}

# Set dimensions of form object
Function DrawSize([int]$w,[int]$h)
{
    $Size = New-Object System.Drawing.Size("$w","$h")
    return $Size
}
#endregion

#Region: Backend Functions

## UPDATE LOG FILE
Function Update-Log
{
	Param ( [string]$logstring )
	
	$logstring = $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ': ' + $logstring
	Write-Host $logstring
	#Add-content $LogFile -value $logstring
}

## REPORT ERROR INFORMATION
Function Write-ErrorLog
{
	Update-Log "$('-' * 50)"
	Update-Log "-- SCRIPT PROCESSING CANCELLED"
	Update-Log "$('-' * 50)"
	Update-Log ""
	Update-Log "Error in $($_.InvocationInfo.ScriptName)"
	Update-Log ""
	Update-Log "$('-' * 50)"
	Update-Log "-- Error Information"
	Update-Log "$('-' * 50)"
	Update-Log ""
	Update-Log "Error Details: $($_)"
	Update-Log "Line Number: $($_.InvocationInfo.ScriptLineNumber)"
	Update-Log "Offset: $($_.InvocationInfo.OffsetInLine)"
	Update-Log "Command: $($_.InvocationInfo.MyCommand)"
	Update-Log "Line: $($_.InvocationInfo.Line)"
}

## GET REGISTRY VALUE
Function Get-RegValue
{
	Param ( 
		[string]$ComputerName,
		[string]$Hive,
		[string]$Key,
		[string]$Value,
		[string]$ValueType
	)
	
	Try
	{
		#Registry Hives
		Switch ($Hive)
		{
			'HKROOT' { [long]$Hive = 2147483648; Break }
			'HKCU' { [long]$Hive = 2147483649; Break }
			'HKLM' { [long]$Hive = 2147483650; Break }
			'HKU' { [long]$Hive = 2147483651; Break }
			'HKCC' { [long]$Hive = 2147483653; Break }
			'HKDD' { [long]$Hive = 2147483654; Break }
		}
		
		$sb = {
			Param ( 
				[string]$ComputerName,
				[long]$Hive,
				[string]$Key,
				[string]$Value,
				[string]$ValueType
			)
		
			$RegProv = [WMIClass]"\\$ComputerName\ROOT\DEFAULT:StdRegProv"
			
			Switch($ValueType)
			{
				'REG_SZ'
				{
					$RegValue = $RegProv.GetStringValue($Hive, $Key, $value)
					Break
				}
				'REG_EXPAND_SZ'
				{
					$RegValue = $RegProv.GetExpandedStringValue($Hive, $Key, $value)
					Break
				}
				'REG_BINARY'
				{
					$RegValue = $RegProv.GetBinaryValue($Hive, $Key, $value)
					Break
				}
				'REG_DWORD'
				{
					$RegValue = $RegProv.GetDWORDValue($Hive, $Key, $value)
					Break
				}
				'REG_MULTI_SZ'
				{
					$RegValue = $RegProv.GetMultiStringValue($Hive, $Key, $value)
					Break
				}
				'REG_QWORD'
				{
					$RegValue = $RegProv.GetQWORDValue($Hive, $Key, $value)
					Break
				}
			}
		
			If ($RegValue.ReturnValue -eq 0)
			{
				If (@($RegValue.Properties | Select-Object -ExpandProperty Name) -contains "sValue")
				{
					$RegValue.sValue
				}
				Else
				{
					$RegValue.uValue
				}
			}
		}
		
		$args = ($ComputerName,$Hive,$Key,$Value,$ValueType)
		$j = Start-Job -ScriptBlock $sb -ArgumentList $args
		Test-TimeOut $ComputerName 'Registry call timed out. Stopping Job.'
		
		$result = $j | Receive-Job
		$j | Remove-Job
		
		Return $result
	}
	
	Catch
	{
		Write-ErrorLog
	}
}


Function Test-Timeout
{
	Param ( 
		[string]$address,
		[string]$exception,
		[int]$timeout = '15',
		[switch]$psexec
	)
	
	$i = 0
	
	While ($j.State -ne 'Completed')  
	{
		If (($i -eq $timeout) -or ($j.State -ne 'Running'))
		{ 
#			Update-Log "-- Job timed out - Stopping Job... Please Wait"
			$j | Remove-Job -Force -ErrorAction Ignore
			
			$row = '"' + $address + '","' + $exception + '","","","",""'
			Add-Content -Path $ErrorLogFile -Value $row
			
			Break
		}
		
#		Update-Log "-- Running Job... Please Wait"
		Sleep 1
		$i++
	}
	
	If ($psexec)
	{
		Stop-Process psexec -Force -ErrorAction Ignore
	}
}

## FUNCTION TO READ INI CONFIG FILES
Function Get-IniContent 
{ 
    <# 
    .Synopsis 
        Gets the content of an INI file 
         
    .Description 
        Gets the content of an INI file and returns it as a hashtable 
         
    .Notes 
        Author    : Oliver Lipkau <oliver@lipkau.net> 
        Blog      : http://oliver.lipkau.net/blog/ 
        Date      : 2014/06/23 
        Version   : 1.1 
         
        #Requires -Version 2.0 
         
    .Inputs 
        System.String 
         
    .Outputs 
        System.Collections.Hashtable 
         
    .Parameter FilePath 
        Specifies the path to the input file. 
         
    .Example 
        $FileContent = Get-IniContent "C:\myinifile.ini" 
        ----------- 
        Description 
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent 
     
    .Example 
        $inifilepath | $FileContent = Get-IniContent 
        ----------- 
        Description 
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent 
     
    .Example 
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini" 
        C:\PS>$FileContent["Section"]["Key"] 
        ----------- 
        Description 
        Returns the key "Key" of the section "Section" from the C:\settings.ini file 
         
    .Link 
        Out-IniFile 
    #> 
     
    [CmdletBinding()] 
    Param( 
        [ValidateNotNullOrEmpty()] 
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})] 
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)] 
        [string]$FilePath 
    ) 
     
    Begin 
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"} 
         
    Process 
    { 
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Processing file: $Filepath" 
             
        $ini = @{} 
        switch -regex -file $FilePath 
        { 
            "^\[(.+)\]$" # Section 
            { 
                $section = $matches[1] 
                $ini[$section] = @{} 
                $CommentCount = 0 
            } 
            "^(;.*)$" # Comment 
            { 
                if (!($section)) 
                { 
                    $section = "No-Section" 
                    $ini[$section] = @{} 
                } 
                $value = $matches[1] 
                $CommentCount = $CommentCount + 1 
                $name = "Comment" + $CommentCount 
                $ini[$section][$name] = $value 
            }  
            "(.+?)\s*=\s*(.*)" # Key 
            { 
                if (!($section)) 
                { 
                    $section = "No-Section" 
                    $ini[$section] = @{} 
                } 
                $name,$value = $matches[1..2] 
                $ini[$section][$name] = $value 
            } 
        } 
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Processing file: $FileContent" 
        Return $ini 
    } 
         
    End 
        {Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"} 
}

#EndRegion: Backend Functions

#Region: GUI

# Generate Network Dashboard Form
function Get-Dashboard 
{
    # Create Form
    $gui.Dashboard = New-Object System.Windows.Forms.Form
    $gui.Dashboard.Text = "AFRC Network Dashboard v.2.0"
    $gui.Dashboard.StartPosition = 4
    $gui.Dashboard.ClientSize = "655,577"
	$gui.Dashboard.FormBorderStyle = 'FixedDialog'
    $gui.Dashboard.MaximizeBox = $false
	$gui.Dashboard.MinimizeBox = $false
	$gui.Dashboard.TopMost = $true

    $gui.btnClose = New-Object System.Windows.Forms.Button
    $gui.btnClose.Size = DrawSize(125)(23)
	$gui.btnClose.Location = DrawPoint(270)(550)
	$gui.btnClose.Text = 'Close Window'
	$gui.Dashboard.Controls.Add($gui.btnClose)
	
	$gui.btnClose.add_Click({
		$gui.Dashboard.Close()
	})

	#region: Tabs
	
	# Creating Tab Control
    $gui.tabContainer = New-Object System.Windows.Forms.TabControl
    $gui.tabContainer.Size = DrawSize(635)(183)
    $gui.tabContainer.Location = DrawPoint(10)(10)
    $gui.tabContainer.SelectedIndex = 0
    $gui.tabContainer.Anchor = 'top, left, right, bottom'
    $gui.Dashboard.Controls.Add($gui.tabContainer)

	$gui.tabUserInfo = New-Object System.Windows.Forms.TabPage
    $gui.tabUserInfo.Size = DrawSize(635)(183)
    $gui.tabUserInfo.Text = 'User'
    $gui.tabUserInfo.TabIndex = 0
    $gui.tabUserInfo.UseVisualStyleBackColor = $true
    $gui.tabContainer.Controls.Add($gui.tabUserInfo)
	
    $gui.tabNetworkInfo = New-Object System.Windows.Forms.TabPage
    $gui.tabNetworkInfo.Size = DrawSize(635)(183)
    $gui.tabNetworkInfo.Text = 'Network'
    $gui.tabNetworkInfo.TabIndex = 0
    $gui.tabNetworkInfo.UseVisualStyleBackColor = $true
    $gui.tabContainer.Controls.Add($gui.tabNetworkInfo)

    $gui.tabOsInfo = New-Object System.Windows.Forms.TabPage
    $gui.tabOsInfo.Size = DrawSize(635)(183)
    $gui.tabOsInfo.Text = 'Software'
    $gui.tabOsInfo.TabIndex = 1
    $gui.tabOsInfo.UseVisualStyleBackColor = $true
    $gui.tabContainer.Controls.Add($gui.tabOsInfo)
	
	#endregion: Tabs
	
	#region: Tab Content - User
	
	$gui.lblUserId = New-Object System.Windows.Forms.Label
	$gui.lblUserId.Size = DrawSize(90)(17)
	$gui.lblUserId.Location = DrawPoint(10)(10)
	$gui.lblUserId.Text = 'User ID'
	$gui.tabUserInfo.Controls.Add($gui.lblUserId)
	
	$gui.txtUserId = New-Object System.Windows.Forms.Label
	$gui.txtUserId.Size = DrawSize(500)(18)
	$gui.txtUserId.Location = DrawPoint(115)(10)
	$gui.txtUserId.BorderStyle = 'FixedSingle'
	$gui.txtUserId.BackColor = '#E3E3E3'
	$gui.txtUserId.ForeColor = '#000000'
	$Gui.txtUserId.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtUserId.Text = $Details.UserId
	$gui.tabUserInfo.Controls.Add($gui.txtUserId)
	
	$gui.lblUserName = New-Object System.Windows.Forms.Label
	$gui.lblUserName.Size = DrawSize(90)(17)
	$gui.lblUserName.Location = DrawPoint(10)(33)
	$gui.lblUserName.Text = 'Display Name'
	$gui.tabUserInfo.Controls.Add($gui.lblUserName)

	$gui.txtUserName = New-Object System.Windows.Forms.Label
	$gui.txtUserName.Size = DrawSize(500)(18)
	$gui.txtUserName.Location = DrawPoint(115)(33)
	$gui.txtUserName.BorderStyle = 'FixedSingle'
	$gui.txtUserName.BackColor = '#E3E3E3'
	$gui.txtUserName.ForeColor = '#000000'
	$Gui.txtUserName.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtUserName.Text = $Details.UserName
	$gui.tabUserInfo.Controls.Add($gui.txtUserName)
	
	$gui.lblLastLogon = New-Object System.Windows.Forms.Label
	$gui.lblLastLogon.Size = DrawSize(90)(17)
	$gui.lblLastLogon.Location = DrawPoint(10)(56)
	$gui.lblLastLogon.Text = 'Last Logon'
	$gui.tabUserInfo.Controls.Add($gui.lblLastLogon)

	$gui.txtLastLogon = New-Object System.Windows.Forms.Label
	$gui.txtLastLogon.Size = DrawSize(500)(18)
	$gui.txtLastLogon.Location = DrawPoint(115)(56)
	$gui.txtLastLogon.BorderStyle = 'FixedSingle'
	$gui.txtLastLogon.BackColor = '#E3E3E3'
	$gui.txtLastLogon.ForeColor = '#000000'
	$Gui.txtLastLogon.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtLastLogon.Text = $Details.LastLogon
	$gui.tabUserInfo.Controls.Add($gui.txtLastLogon)
	
	$gui.lblEmail = New-Object System.Windows.Forms.Label
	$gui.lblEmail.Size = DrawSize(90)(17)
	$gui.lblEmail.Location = DrawPoint(10)(79)
	$gui.lblEmail.Text = 'E-mail'
	$gui.tabUserInfo.Controls.Add($gui.lblEmail)

	$gui.txtEmail = New-Object System.Windows.Forms.Label
	$gui.txtEmail.Size = DrawSize(500)(18)
	$gui.txtEmail.Location = DrawPoint(115)(79)
	$gui.txtEmail.BorderStyle = 'FixedSingle'
	$gui.txtEmail.BackColor = '#E3E3E3'
	$gui.txtEmail.ForeColor = '#000000'
	$Gui.txtEmail.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtEmail.Text = $Details.Email
	$gui.tabUserInfo.Controls.Add($gui.txtEmail)
	
	$gui.lblMailServer = New-Object System.Windows.Forms.Label
	$gui.lblMailServer.Size = DrawSize(90)(17)
	$gui.lblMailServer.Location = DrawPoint(10)(102)
	$gui.lblMailServer.Text = 'Mail Server'
	$gui.tabUserInfo.Controls.Add($gui.lblMailServer)

	$gui.txtMailServer = New-Object System.Windows.Forms.Label
	$gui.txtMailServer.Size = DrawSize(500)(18)
	$gui.txtMailServer.Location = DrawPoint(115)(102)
	$gui.txtMailServer.BorderStyle = 'FixedSingle'
	$gui.txtMailServer.BackColor = '#E3E3E3'
	$gui.txtMailServer.ForeColor = '#000000'
	$Gui.txtMailServer.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtMailServer.Text = $Details.MailServer
	$gui.tabUserInfo.Controls.Add($gui.txtMailServer)
	
	$gui.lblIaTrainingDate = New-Object System.Windows.Forms.Label
	$gui.lblIaTrainingDate.Size = DrawSize(90)(17)
	$gui.lblIaTrainingDate.Location = DrawPoint(10)(125)
	$gui.lblIaTrainingDate.Text = 'IA Date'
	$gui.tabUserInfo.Controls.Add($gui.lblIaTrainingDate)

	$gui.txtIaTrainingDate = New-Object System.Windows.Forms.Label
	$gui.txtIaTrainingDate.Size = DrawSize(500)(18)
	$gui.txtIaTrainingDate.Location = DrawPoint(115)(125)
	$gui.txtIaTrainingDate.BorderStyle = 'FixedSingle'
	$gui.txtIaTrainingDate.BackColor = '#E3E3E3'
	$gui.txtIaTrainingDate.ForeColor = '#000000'
	$Gui.txtIaTrainingDate.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtIaTrainingDate.Text = $Details.IaTrainingDate
	$gui.tabUserInfo.Controls.Add($gui.txtIaTrainingDate)
	
	#EndRegion: Tab Content -User
	
	#region: Tab Content - Network
	
	$gui.lblComputerName = New-Object System.Windows.Forms.Label
	$gui.lblComputerName.Size = DrawSize(90)(17)
	$gui.lblComputerName.Location = DrawPoint(10)(10)
	$gui.lblComputerName.Text = 'Computer Name'
	$gui.tabNetworkInfo.Controls.Add($gui.lblComputerName)
	
	$gui.txtComputerName = New-Object System.Windows.Forms.Label
	$gui.txtComputerName.Size = DrawSize(500)(18)
	$gui.txtComputerName.Location = DrawPoint(115)(10)
	$gui.txtComputerName.BorderStyle = 'FixedSingle'
	$gui.txtComputerName.BackColor = '#E3E3E3'
	$gui.txtComputerName.ForeColor = '#000000'
	$Gui.txtComputerName.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtComputerName.Text = $Details.ComputerName
	$gui.tabNetworkInfo.Controls.Add($gui.txtComputerName)
	
	$gui.lblDomain = New-Object System.Windows.Forms.Label
	$gui.lblDomain.Size = DrawSize(90)(17)
	$gui.lblDomain.Location = DrawPoint(10)(33)
	$gui.lblDomain.Text = 'Domain'
	$gui.tabNetworkInfo.Controls.Add($gui.lblDomain)

	$gui.txtDomain = New-Object System.Windows.Forms.Label
	$gui.txtDomain.Size = DrawSize(500)(18)
	$gui.txtDomain.Location = DrawPoint(115)(33)
	$gui.txtDomain.BorderStyle = 'FixedSingle'
	$gui.txtDomain.BackColor = '#E3E3E3'
	$gui.txtDomain.ForeColor = '#000000'
	$Gui.txtDomain.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtDomain.Text = $Details.Domain
	$gui.tabNetworkInfo.Controls.Add($gui.txtDomain)
	
	$gui.lblLogonServer = New-Object System.Windows.Forms.Label
	$gui.lblLogonServer.Size = DrawSize(90)(17)
	$gui.lblLogonServer.Location = DrawPoint(10)(56)
	$gui.lblLogonServer.Text = 'Logon Server'
	$gui.tabNetworkInfo.Controls.Add($gui.lblLogonServer)

	$gui.txtLogonServer = New-Object System.Windows.Forms.Label
	$gui.txtLogonServer.Size = DrawSize(500)(18)
	$gui.txtLogonServer.Location = DrawPoint(115)(56)
	$gui.txtLogonServer.BorderStyle = 'FixedSingle'
	$gui.txtLogonServer.BackColor = '#E3E3E3'
	$gui.txtLogonServer.ForeColor = '#000000'
	$Gui.txtLogonServer.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtLogonServer.Text = $Details.LogonServer
	$gui.tabNetworkInfo.Controls.Add($gui.txtLogonServer)
	
	$gui.lblUpTime = New-Object System.Windows.Forms.Label
	$gui.lblUpTime.Size = DrawSize(90)(17)
	$gui.lblUpTime.Location = DrawPoint(10)(79)
	$gui.lblUpTime.Text = 'System Up Time'
	$gui.tabNetworkInfo.Controls.Add($gui.lblUpTime)

	$gui.txtUpTime = New-Object System.Windows.Forms.Label
	$gui.txtUpTime.Size = DrawSize(500)(18)
	$gui.txtUpTime.Location = DrawPoint(115)(79)
	$gui.txtUpTime.BorderStyle = 'FixedSingle'
	$gui.txtUpTime.BackColor = '#E3E3E3'
	$gui.txtUpTime.ForeColor = '#000000'
	$Gui.txtUpTime.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtUpTime.Text = $Details.UpTime
	$gui.tabNetworkInfo.Controls.Add($gui.txtUpTime)
	
	$gui.lblIpAddress = New-Object System.Windows.Forms.Label
	$gui.lblIpAddress.Size = DrawSize(90)(17)
	$gui.lblIpAddress.Location = DrawPoint(10)(102)
	$gui.lblIpAddress.Text = 'IP Address'
	$gui.tabNetworkInfo.Controls.Add($gui.lblIpAddress)

	$gui.txtIpAddress = New-Object System.Windows.Forms.Label
	$gui.txtIpAddress.Size = DrawSize(500)(18)
	$gui.txtIpAddress.Location = DrawPoint(115)(102)
	$gui.txtIpAddress.BorderStyle = 'FixedSingle'
	$gui.txtIpAddress.BackColor = '#E3E3E3'
	$gui.txtIpAddress.ForeColor = '#000000'
	$Gui.txtIpAddress.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtIpAddress.Text = $Details.IpAddress
	$gui.tabNetworkInfo.Controls.Add($gui.txtIpAddress)
	
	$gui.lblMacAddress = New-Object System.Windows.Forms.Label
	$gui.lblMacAddress.Size = DrawSize(90)(17)
	$gui.lblMacAddress.Location = DrawPoint(10)(125)
	$gui.lblMacAddress.Text = 'MAC Address'
	$gui.tabNetworkInfo.Controls.Add($gui.lblMacAddress)

	$gui.txtMacAddress = New-Object System.Windows.Forms.Label
	$gui.txtMacAddress.Size = DrawSize(500)(18)
	$gui.txtMacAddress.Location = DrawPoint(115)(125)
	$gui.txtMacAddress.BorderStyle = 'FixedSingle'
	$gui.txtMacAddress.BackColor = '#E3E3E3'
	$gui.txtMacAddress.ForeColor = '#000000'
	$Gui.txtMacAddress.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtMacAddress.Text = $Details.MacAddress
	$gui.tabNetworkInfo.Controls.Add($gui.txtMacAddress)
	
	#EndRegion: Tab Content - Network
	
    #region: Tab Content - Software
	
	$gui.lblSdc = New-Object System.Windows.Forms.Label
	$gui.lblSdc.Size = DrawSize(90)(17)
	$gui.lblSdc.Location = DrawPoint(10)(10)
	$gui.lblSdc.Text = 'SDC'
	$gui.tabOsInfo.Controls.Add($gui.lblSdc)
	
	$gui.txtSdc = New-Object System.Windows.Forms.Label
	$gui.txtSdc.Size = DrawSize(500)(18)
	$gui.txtSdc.Location = DrawPoint(115)(10)
	$gui.txtSdc.BorderStyle = 'FixedSingle'
	$gui.txtSdc.BackColor = '#E3E3E3'
	$gui.txtSdc.ForeColor = '#000000'
	$Gui.txtSdc.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtSdc.Text = $Details.Sdc
	$gui.tabOsInfo.Controls.Add($gui.txtSdc)
	
	$gui.lblOsInfo = New-Object System.Windows.Forms.Label
	$gui.lblOsInfo.Size = DrawSize(90)(17)
	$gui.lblOsInfo.Location = DrawPoint(10)(33)
	$gui.lblOsInfo.Text = 'OS'
	$gui.tabOsInfo.Controls.Add($gui.lblOsInfo)

	$gui.txtOsInfo = New-Object System.Windows.Forms.Label
	$gui.txtOsInfo.Size = DrawSize(500)(18)
	$gui.txtOsInfo.Location = DrawPoint(115)(33)
	$gui.txtOsInfo.BorderStyle = 'FixedSingle'
	$gui.txtOsInfo.BackColor = '#E3E3E3'
	$gui.txtOsInfo.ForeColor = '#000000'
	$Gui.txtOsInfo.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtOsInfo.Text = $Details.OsInfo
	$gui.tabOsInfo.Controls.Add($gui.txtOsInfo)
	
	$gui.lblIeVersion = New-Object System.Windows.Forms.Label
	$gui.lblIeVersion.Size = DrawSize(90)(17)
	$gui.lblIeVersion.Location = DrawPoint(10)(56)
	$gui.lblIeVersion.Text = 'IE Version'
	$gui.tabOsInfo.Controls.Add($gui.lblIeVersion)

	$gui.txtIeVersion = New-Object System.Windows.Forms.Label
	$gui.txtIeVersion.Size = DrawSize(500)(18)
	$gui.txtIeVersion.Location = DrawPoint(115)(56)
	$gui.txtIeVersion.BorderStyle = 'FixedSingle'
	$gui.txtIeVersion.BackColor = '#E3E3E3'
	$gui.txtIeVersion.ForeColor = '#000000'
	$Gui.txtIeVersion.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtIeVersion.Text = $Details.IeVersion
	$gui.tabOsInfo.Controls.Add($gui.txtIeVersion)
	
	$gui.lblOfficeVersion = New-Object System.Windows.Forms.Label
	$gui.lblOfficeVersion.Size = DrawSize(90)(17)
	$gui.lblOfficeVersion.Location = DrawPoint(10)(79)
	$gui.lblOfficeVersion.Text = 'Office Version'
	$gui.tabOsInfo.Controls.Add($gui.lblOfficeVersion)

	$gui.txtOfficeVersion = New-Object System.Windows.Forms.Label
	$gui.txtOfficeVersion.Size = DrawSize(500)(18)
	$gui.txtOfficeVersion.Location = DrawPoint(115)(79)
	$gui.txtOfficeVersion.BorderStyle = 'FixedSingle'
	$gui.txtOfficeVersion.BackColor = '#E3E3E3'
	$gui.txtOfficeVersion.ForeColor = '#000000'
	$Gui.txtOfficeVersion.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtOfficeVersion.Text = $Details.OfficeVersion
	$gui.tabOsInfo.Controls.Add($gui.txtOfficeVersion)
	
	$gui.lblDatFileVersion = New-Object System.Windows.Forms.Label
	$gui.lblDatFileVersion.Size = DrawSize(90)(17)
	$gui.lblDatFileVersion.Location = DrawPoint(10)(102)
	$gui.lblDatFileVersion.Text = 'AV Definition'
	$gui.tabOsInfo.Controls.Add($gui.lblDatFileVersion)

	$gui.txtDatFileVersion = New-Object System.Windows.Forms.Label
	$gui.txtDatFileVersion.Size = DrawSize(500)(18)
	$gui.txtDatFileVersion.Location = DrawPoint(115)(102)
	$gui.txtDatFileVersion.BorderStyle = 'FixedSingle'
	$gui.txtDatFileVersion.BackColor = '#E3E3E3'
	$gui.txtDatFileVersion.ForeColor = '#000000'
	$Gui.txtDatFileVersion.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtDatFileVersion.Text = $Details.datFileVersion
	$gui.tabOsInfo.Controls.Add($gui.txtDatFileVersion)
	
	$gui.lblDatInstallDate = New-Object System.Windows.Forms.Label
	$gui.lblDatInstallDate.Size = DrawSize(90)(17)
	$gui.lblDatInstallDate.Location = DrawPoint(10)(125)
	$gui.lblDatInstallDate.Text = 'Definition Date'
	$gui.tabOsInfo.Controls.Add($gui.lblDatInstallDate)

	$gui.txtDatInstallDate = New-Object System.Windows.Forms.Label
	$gui.txtDatInstallDate.Size = DrawSize(500)(18)
	$gui.txtDatInstallDate.Location = DrawPoint(115)(125)
	$gui.txtDatInstallDate.BorderStyle = 'FixedSingle'
	$gui.txtDatInstallDate.BackColor = '#E3E3E3'
	$gui.txtDatInstallDate.ForeColor = '#000000'
	$Gui.txtDatInstallDate.Font = New-Object System.Drawing.Font("Arial", 8)
	$gui.txtDatInstallDate.Text = $Details.datInstallDate
	$gui.tabOsInfo.Controls.Add($gui.txtDatInstallDate)
	
	#EndRegion: Tab Content - Software
	
	#Region: Group Box - FPCON
	
	$Gui.grpFpcon = New-Object System.Windows.Forms.GroupBox
	$Gui.grpFpcon.Text = 'FPCON'
	$gui.grpFpcon.Size = DrawSize(200)(80)
	$gui.grpFpcon.Location = DrawPoint(10)(205)
	$gui.Dashboard.Controls.Add($gui.grpFpcon)
	
	$gui.lblFpconReal = New-Object System.Windows.Forms.Label
	$gui.lblFpconReal.Size = DrawSize(75)(17)
	$gui.lblFpconReal.Location = DrawPoint(10)(25)
	$gui.lblFpconReal.Text = 'Real World'
	$gui.grpFpcon.Controls.Add($gui.lblFpconReal)
	
	$gui.lblFpconExcercise = New-Object System.Windows.Forms.Label
	$gui.lblFpconExcercise.Size = DrawSize(75)(17)
	$gui.lblFpconExcercise.Location = DrawPoint(10)(48)
	$gui.lblFpconExcercise.Text = 'Exercise'
	$gui.grpFpcon.Controls.Add($gui.lblFpconExcercise)
	
	$gui.txtFpconReal = New-Object System.Windows.Forms.Label
	$gui.txtFpconReal.Size = DrawSize(90)(18)
	$gui.txtFpconReal.Location = DrawPoint(100)(25)
	$gui.txtFpconReal.BorderStyle = 'FixedSingle'
	
	Switch ($Details.FpconReal)
	{
		'Normal' 	{ $gui.txtFpconReal.ForeColor = '#FFFFFF'; Break } # White
		'Alpha' 	{ $gui.txtFpconReal.ForeColor = '#000000'; Break } # Black
		'Bravo' 	{ $gui.txtFpconReal.ForeColor = '#FFFFFF'; Break } # White
		'Charlie' 	{ $gui.txtFpconReal.ForeColor = '#000000'; Break } # Black
		'Delta' 	{ $gui.txtFpconReal.ForeColor = '#FFFFFF'; Break } # White
		'None' 		{ $gui.txtFpconReal.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.FpconReal)
	{
		'Normal' 	{ $gui.txtFpconReal.BackColor = '#009900'; Break } # Green
		'Alpha' 	{ $gui.txtFpconReal.BackColor = '#FFA500'; Break } # Orange
		'Bravo' 	{ $gui.txtFpconReal.BackColor = '#0066FF'; Break } # Blue
		'Charlie' 	{ $gui.txtFpconReal.BackColor = '#FFFF00'; Break } # Yellow
		'Delta' 	{ $gui.txtFpconReal.BackColor = '#FF0000'; Break } # Red
		'None' 		{ $gui.txtFpconReal.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtFpconReal.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtFpconReal.Text = $Details.FpconReal.ToUpper()
	$Gui.txtFpconReal.TextAlign = 'MiddleCenter'
	$gui.grpFpcon.Controls.Add($gui.txtFpconReal)
	
	$gui.txtFpconExcer = New-Object System.Windows.Forms.Label
	$gui.txtFpconExcer.Size = DrawSize(90)(18)
	$gui.txtFpconExcer.Location = DrawPoint(100)(48)
	$gui.txtFpconExcer.BorderStyle = 'FixedSingle'
	
	Switch ($Details.FpconExcer)
	{
		'Normal' 	{ $gui.txtFpconExcer.ForeColor = '#FFFFFF'; Break } # White
		'Alpha' 	{ $gui.txtFpconExcer.ForeColor = '#000000'; Break } # Black
		'Bravo' 	{ $gui.txtFpconExcer.ForeColor = '#FFFFFF'; Break } # White
		'Charlie' 	{ $gui.txtFpconExcer.ForeColor = '#000000'; Break } # Black
		'Delta' 	{ $gui.txtFpconExcer.ForeColor = '#FFFFFF'; Break } # White
		'None' 		{ $gui.txtFpconExcer.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.FpconExcer)
	{
		'Normal' 	{ $gui.txtFpconExcer.BackColor = '#009900'; Break } # Green
		'Alpha' 	{ $gui.txtFpconExcer.BackColor = '#FFA500'; Break } # Orange
		'Bravo' 	{ $gui.txtFpconExcer.BackColor = '#0066FF'; Break } # Blue
		'Charlie' 	{ $gui.txtFpconExcer.BackColor = '#FFFF00'; Break } # Yellow
		'Delta' 	{ $gui.txtFpconExcer.BackColor = '#FF0000'; Break } # Red
		'None' 		{ $gui.txtFpconExcer.BackColor = '#707070'; Break } # Gray
	}
	
	$Gui.txtFpconExcer.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtFpconExcer.Text = $Details.FpconExcer.ToUpper()
	$Gui.txtFpconExcer.TextAlign = 'MiddleCenter'
	$gui.grpFpcon.Controls.Add($gui.txtFpconExcer)
	
	#EndRegion: Group Box - FPCON
	
	#Region: Group Box - INFOCON
	
	$Gui.grpInfocon = New-Object System.Windows.Forms.GroupBox
	$Gui.grpInfocon.Text = 'INFOCON'
	$gui.grpInfocon.Size = DrawSize(200)(80)
	$gui.grpInfocon.Location = DrawPoint(225)(205)
	$gui.Dashboard.Controls.Add($gui.grpInfocon)
	
	$gui.lblInfoconReal = New-Object System.Windows.Forms.Label
	$gui.lblInfoconReal.Size = DrawSize(75)(17)
	$gui.lblInfoconReal.Location = DrawPoint(10)(25)
	$gui.lblInfoconReal.Text = 'Real World'
	$gui.grpInfocon.Controls.Add($gui.lblInfoconReal)
	
	$gui.lblInfoconExcercise = New-Object System.Windows.Forms.Label
	$gui.lblInfoconExcercise.Size = DrawSize(75)(17)
	$gui.lblInfoconExcercise.Location = DrawPoint(10)(48)
	$gui.lblInfoconExcercise.Text = 'Exercise'
	$gui.grpInfocon.Controls.Add($gui.lblInfoconExcercise)
	
	$gui.txtInfoconReal = New-Object System.Windows.Forms.Label
	$gui.txtInfoconReal.Size = DrawSize(90)(18)
	$gui.txtInfoconReal.Location = DrawPoint(100)(25)
	$gui.txtInfoconReal.BorderStyle = 'FixedSingle'
	
	Switch ($Details.InfoconReal)
	{
		'5' 		{ $gui.txtInfoconReal.ForeColor = '#FFFFFF'; Break } # White
		'4' 		{ $gui.txtInfoconReal.ForeColor = '#000000'; Break } # Black
		'3' 		{ $gui.txtInfoconReal.ForeColor = '#FFFFFF'; Break } # White
		'2' 		{ $gui.txtInfoconReal.ForeColor = '#000000'; Break } # Black
		'1' 		{ $gui.txtInfoconReal.ForeColor = '#FFFFFF'; Break } # White
		'None' 		{ $gui.txtInfoconReal.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.InfoconReal)
	{
		'5' 		{ $gui.txtInfoconReal.BackColor = '#009900'; Break } # Green
		'4' 		{ $gui.txtInfoconReal.BackColor = '#FFA500'; Break } # Orange
		'3' 		{ $gui.txtInfoconReal.BackColor = '#0066FF'; Break } # Blue
		'2' 		{ $gui.txtInfoconReal.BackColor = '#FFFF00'; Break } # Yellow
		'1' 		{ $gui.txtInfoconReal.BackColor = '#FF0000'; Break } # Red
		'None' 		{ $gui.txtInfoconReal.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtInfoconReal.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtInfoconReal.Text = $Details.InfoconReal.ToUpper()
	$Gui.txtInfoconReal.TextAlign = 'MiddleCenter'
	$gui.grpInfocon.Controls.Add($gui.txtInfoconReal)
	
	$gui.txtInfoconExcer = New-Object System.Windows.Forms.Label
	$gui.txtInfoconExcer.Size = DrawSize(90)(18)
	$gui.txtInfoconExcer.Location = DrawPoint(100)(48)
	$gui.txtInfoconExcer.BorderStyle = 'FixedSingle'
	
	#"dark_gray":  "#808080",
    #"screen_colors":  "gray,dark_magenta",
    #"dark_green":  "#008000",
    #"blue":  "#0000ff",
    #"dark_yellow":  "#cc7722",
    #"red":  "#ff0000",
    #"magenta":  "#ff00ff",
    #"dark_red":  "#800000",
    #"yellow":  "#ffff00",
    #"dark_magenta":  "#012456",
    #"cyan":  "#00ffff",
    #"green":  "#00ff00",
    #"dark_blue":  "#000080",
    #"gray":  "#c0c0c0",
    #"white":  "#ffffff",
    #"black":  "#000000",
    #"dark_cyan":  "#008080"
	Switch ($Details.InfoconExcer)
	{
		'5' 		{ $gui.txtInfoconExcer.ForeColor = '#FFFFFF'; Break } # White
		'4' 		{ $gui.txtInfoconExcer.ForeColor = '#000000'; Break } # Black
		'3' 		{ $gui.txtInfoconExcer.ForeColor = '#FFFFFF'; Break } # White
		'2' 		{ $gui.txtInfoconExcer.ForeColor = '#000000'; Break } # Black
		'1' 		{ $gui.txtInfoconExcer.ForeColor = '#FFFFFF'; Break } # White
		'None'		{ $gui.txtInfoconExcer.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.InfoconExcer)
	{
		'5' 		{ $gui.txtInfoconExcer.BackColor = '#009900'; Break } # Green
		'4' 		{ $gui.txtInfoconExcer.BackColor = '#FFA500'; Break } # Orange
		'3' 		{ $gui.txtInfoconExcer.BackColor = '#0066FF'; Break } # Blue
		'2' 		{ $gui.txtInfoconExcer.BackColor = '#FFFF00'; Break } # Yellow
		'1' 		{ $gui.txtInfoconExcer.BackColor = '#FF0000'; Break } # Red
		'None' 		{ $gui.txtInfoconExcer.BackColor = '#707070'; Break } # Gray
	}
	
	$Gui.txtInfoconExcer.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtInfoconExcer.Text = $Details.InfoconExcer.ToUpper()
	$Gui.txtInfoconExcer.TextAlign = 'MiddleCenter'
	$gui.grpInfocon.Controls.Add($gui.txtInfoconExcer)
	
	#EndRegion: Group Box - FPCON
	
	#Region: Group Box - Homeland Security Theat Condition
	
	$Gui.grpHsThreatCon = New-Object System.Windows.Forms.GroupBox
	$Gui.grpHsThreatCon.Text = 'Homeland Security'
	$gui.grpHsThreatCon.Size = DrawSize(200)(80)
	$gui.grpHsThreatCon.Location = DrawPoint(440)(205)
	$gui.Dashboard.Controls.Add($gui.grpHsThreatCon)
	
	$gui.txtHsThreatCon = New-Object System.Windows.Forms.Label
	$gui.txtHsThreatCon.Size = DrawSize(140)(18)
	$gui.txtHsThreatCon.Location = DrawPoint(30)(35)
	$gui.txtHsThreatCon.BorderStyle = 'FixedSingle'
	
	Switch ($Details.HsThreatCon)
	{
		'Low' 		{ $gui.txtHsThreatCon.ForeColor = '#FFFFFF'; Break } # White
		'Guarded'	{ $gui.txtHsThreatCon.ForeColor = '#000000'; Break } # Black
		'Elevated'	{ $gui.txtHsThreatCon.ForeColor = '#FFFFFF'; Break } # White
		'High' 		{ $gui.txtHsThreatCon.ForeColor = '#000000'; Break } # Black
		'Severe'	{ $gui.txtHsThreatCon.ForeColor = '#FFFFFF'; Break } # White
		'Unknown'	{ $gui.txtHsThreatCon.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.HsThreatCon)
	{
		'Low' 		{ $gui.txtHsThreatCon.BackColor = '#009900'; Break } # Green
		'Guarded' 	{ $gui.txtHsThreatCon.BackColor = '#FFA500'; Break } # Orange
		'Elevated' 	{ $gui.txtHsThreatCon.BackColor = '#0066FF'; Break } # Blue
		'High' 		{ $gui.txtHsThreatCon.BackColor = '#FFFF00'; Break } # Yellow
		'Severe' 	{ $gui.txtHsThreatCon.BackColor = '#FF0000'; Break } # Red
		'Unknown' 	{ $gui.txtHsThreatCon.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtHsThreatCon.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtHsThreatCon.Text = $Details.HsThreatCon.ToUpper()
	$Gui.txtHsThreatCon.TextAlign = 'MiddleCenter'
	$gui.grpHsThreatCon.Controls.Add($gui.txtHsThreatCon)
	
	#EndRegion: Group Box - Homeland Security Theat Condition
	
	#Region: Group Box - Network Conditions
	
	$Gui.grpInfocon = New-Object System.Windows.Forms.GroupBox
	$Gui.grpInfocon.Text = 'Network Conditions'
	$gui.grpInfocon.Size = DrawSize(635)(57)
	$gui.grpInfocon.Location = DrawPoint(10)(295)
	$gui.Dashboard.Controls.Add($gui.grpInfocon)
	
	$gui.lblEntNetCon = New-Object System.Windows.Forms.Label
	$gui.lblEntNetCon.Size = DrawSize(120)(17)
	$gui.lblEntNetCon.Location = DrawPoint(10)(25)
	$gui.lblEntNetCon.Text = 'Enterprise Network'
	$gui.grpInfocon.Controls.Add($gui.lblEntNetCon)
	
	$gui.txtEntNetCon = New-Object System.Windows.Forms.Label
	$gui.txtEntNetCon.Size = DrawSize(100)(18)
	$gui.txtEntNetCon.Location = DrawPoint(140)(25)
	$gui.txtEntNetCon.BorderStyle = 'FixedSingle'
	
	Switch ($Details.EntNetCon)
	{
		'Normal' 	{ $gui.txtEntNetCon.ForeColor = '#FFFFFF'; Break } # White
		'Degraded' 	{ $gui.txtEntNetCon.ForeColor = '#000000'; Break } # Black
		'Outage' 	{ $gui.txtEntNetCon.ForeColor = '#FFFFFF'; Break } # White
		'Unknown'	{ $gui.txtEntNetCon.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.EntNetCon)
	{
		'Normal' 	{ $gui.txtEntNetCon.BackColor = '#009900'; Break } # Green
		'Degraded' 	{ $gui.txtEntNetCon.BackColor = '#FFFF00'; Break } # Yellow
		'Outage' 	{ $gui.txtEntNetCon.BackColor = '#FF0000'; Break } # Red
		'Unknown'	{ $gui.txtEntNetCon.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtEntNetCon.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtEntNetCon.Text = $Details.EntNetCon.ToUpper()
	$Gui.txtEntNetCon.TextAlign = 'MiddleCenter'
	$gui.grpInfocon.Controls.Add($gui.txtEntNetCon)
	
	$gui.lblEmail = New-Object System.Windows.Forms.Label
	$gui.lblEmail.Size = DrawSize(50)(17)
	$gui.lblEmail.Location = DrawPoint(255)(25)
	$gui.lblEmail.Text = 'E-mail'
	$gui.grpInfocon.Controls.Add($gui.lblEmail)
	
	$gui.txtEmail = New-Object System.Windows.Forms.Label
	$gui.txtEmail.Size = DrawSize(100)(18)
	$gui.txtEmail.Location = DrawPoint(315)(25)
	$gui.txtEmail.BorderStyle = 'FixedSingle'
	
	Switch ($Details.EmailState)
	{
		'Normal' 	{ $gui.txtEmail.ForeColor = '#FFFFFF'; Break } # White
		'Degraded' 	{ $gui.txtEmail.ForeColor = '#000000'; Break } # Black
		'Outage' 	{ $gui.txtEmail.ForeColor = '#FFFFFF'; Break } # White
		'Unknown'	{ $gui.txtEmail.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.EmailState)
	{
		'Normal' 	{ $gui.txtEmail.BackColor = '#009900'; Break } # Green
		'Degraded' 	{ $gui.txtEmail.BackColor = '#FFFF00'; Break } # Yellow
		'Outage' 	{ $gui.txtEmail.BackColor = '#FF0000'; Break } # Red
		'Unknown'	{ $gui.txtEmail.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtEmail.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtEmail.Text = $Details.EmailState.ToUpper()
	$Gui.txtEmail.TextAlign = 'MiddleCenter'
	$gui.grpInfocon.Controls.Add($gui.txtEmail)
	
	$gui.lblInternet = New-Object System.Windows.Forms.Label
	$gui.lblInternet.Size = DrawSize(90)(17)
	$gui.lblInternet.Location = DrawPoint(425)(25)
	$gui.lblInternet.Text = 'NIPR/Internet'
	$gui.grpInfocon.Controls.Add($gui.lblInternet)
	
	$gui.txtInternet = New-Object System.Windows.Forms.Label
	$gui.txtInternet.Size = DrawSize(100)(18)
	$gui.txtInternet.Location = DrawPoint(520)(25)
	$gui.txtInternet.BorderStyle = 'FixedSingle'
	
	Switch ($Details.Internet)
	{
		'Normal' 	{ $gui.txtInternet.ForeColor = '#FFFFFF'; Break } # White
		'Degraded' 	{ $gui.txtInternet.ForeColor = '#000000'; Break } # Black
		'Outage' 	{ $gui.txtInternet.ForeColor = '#FFFFFF'; Break } # White
		'Unknown'	{ $gui.txtInternet.ForeColor = '#C8C8C8'; Break } # Gray
	}
	
	Switch ($Details.Internet)
	{
		'Normal' 	{ $gui.txtInternet.BackColor = '#009900'; Break } # Green
		'Degraded' 	{ $gui.txtInternet.BackColor = '#FFFF00'; Break } # Yellow
		'Outage' 	{ $gui.txtInternet.BackColor = '#FF0000'; Break } # Red
		'Unknown'	{ $gui.txtInternet.BackColor = '#707070'; Break } # Gray
	}
		
	$Gui.txtInternet.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
	$gui.txtInternet.Text = $Details.Internet.ToUpper()
	$Gui.txtInternet.TextAlign = 'MiddleCenter'
	$gui.grpInfocon.Controls.Add($gui.txtInternet)
	
	#EndRegion: Group Box - Network Conditions
	
	#Region: Group Box - Network Advisory
	
	$Gui.grpNetAdvisory = New-Object System.Windows.Forms.GroupBox
	$Gui.grpNetAdvisory.Text = 'Network Advisory Notice'
	$gui.grpNetAdvisory.Size = DrawSize(312)(178)
	$gui.grpNetAdvisory.Location = DrawPoint(10)(362)
	$gui.Dashboard.Controls.Add($gui.grpNetAdvisory)
	
	$gui.txtNetAdvisory = New-Object System.Windows.Forms.TextBox
	$gui.txtNetAdvisory.Size = DrawSize(292)(143)
	$gui.txtNetAdvisory.Location = DrawPoint(10)(25)
	$gui.txtNetAdvisory.Text = $(Get-Content -Path $currentdir\NAs.txt | fl | Out-String)
	$gui.txtNetAdvisory.MultiLine = $True
	$gui.txtNetAdvisory.ScrollBars = 'Vertical'
	$gui.grpNetAdvisory.Controls.Add($gui.txtNetAdvisory)
	
	#EndRegion: Group Box - Network Advisory
	
	#Region: Group Box - Network Advisory
	
	$Gui.grpIaMessage = New-Object System.Windows.Forms.GroupBox
	$Gui.grpIaMessage.Text = 'Information Assurance Message'
	$gui.grpIaMessage.Size = DrawSize(312)(178)
	$gui.grpIaMessage.Location = DrawPoint(332)(362)
	$gui.Dashboard.Controls.Add($gui.grpIaMessage)
	
	$gui.txtIaMessage = New-Object System.Windows.Forms.TextBox
	$gui.txtIaMessage.Size = DrawSize(292)(143)
	$gui.txtIaMessage.Location = DrawPoint(10)(25)
	$gui.txtIaMessage.Text = $(Get-Content -Path $currentdir\HOT.txt | fl | Out-String)
	$gui.txtIaMessage.MultiLine = $True
	$gui.txtIaMessage.ScrollBars = 'Vertical'
	$gui.grpIaMessage.Controls.Add($gui.txtIaMessage)
	
	#EndRegion: Group Box - Network Advisory
	
	# Display Form
    $gui.Dashboard.ShowDialog()
}

#EndRegion: GUI

#Region: User Info

Function Get-UserInfo
{
	$strName = $env:UserName
	$strFilter = "(&(objectCategory=User)(samAccountName=$strName))"

	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.Filter = $strFilter

	$objPath = $objSearcher.FindOne()
	$objUser = $objPath.GetDirectoryEntry()
	
	If ($objuser.msexchhomeservername)
    {
        $mailServer = $objuser.msexchhomeservername -Split 'cn='
        $Details.MailServer = $mailServer[($mailServer.count - 1)]
		
    }
		$Details.MailServer = 'https://webmail.apps.mil/owa/us.af.mil'
	
	# Add values to details hash
	$Details.UserId 		= $Env:USERNAME
	$Details.UserName 		= $objUser.displayName
	$Details.LastLogon		= If ($objUser.lastLogon.value -ne $null) {$([datetime]::FromFileTime($objUser.ConvertLargeIntegerToInt64($objUser.lastLogon.value))).ToString('G')} Else {'Not Found'}
	$Details.Email 			= $objUser.mail
	$Details.IaTrainingDate	= If ($objUser.iaTrainingDate -ne $null) {$($objUser.iaTrainingDate).ToString('G')} Else {'Not Found'}
}

#EndRegion: User Info

#Region: System Info

Function Get-SysInfo
{
	# Calculate system uptime
	$wmi = Get-WmiObject -Class Win32_OperatingSystem
	$UpTime = $wmi.ConvertToDateTime($wmi.LocalDateTime) – $wmi.ConvertToDateTime($wmi.LastBootUpTime)
	
	# Get IP and MAC address
	$wmi = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" | Select DNSHostname,MACAddress,IPAddress
	$IpAddress = $wmi.IPAddress
	$MacAddress = $wmi.MACAddress
	
	# Add values to details hash
	$Details.ComputerName	= $Env:COMPUTERNAME
	$Details.Domain 		= $Env:USERDOMAIN
	$Details.LogonServer 	= $Env:LOGONSERVER
	$Details.UpTime 		= $UpTime.Days.ToString() + 'D ' + $UpTime.Hours.ToString() + 'H ' + $UpTime.Minutes.ToString() + 'M ' + $UpTime.Seconds.ToString() + 'S'
	$Details.IpAddress 		= $IpAddress
	$Details.MacAddress 	= $MacAddress
}

#EndRegion: System Info

#Region: Software Info

Function Get-SoftInfo
{
	# Get SDC Version
	$Hive = 'hklm'
	$Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation'
	$Value = 'Model'
	$ValueType = 'reg_sz'

	$Sdc = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
	
	# WMI: Get Computer System Info
	Try
	{
		$sb = {
			Get-WmiObject -query "SELECT Caption,OSArchitecture FROM win32_operatingsystem"
		}
		
		$j =  Start-Job -ScriptBlock $sb
		Test-TimeOut $address 'Failed to get computer system info. Job timed out.'
		
		$c = $j | Receive-Job
		$j | Remove-Job
		
		$Os =  $c.Caption
		$OsArch = $c.OSArchitecture
	}
	
	Catch
	{
		Write-ErrorLog
	}	
	
	## GET IE VERSION
	$Hive = 'hklm'
	$Key = 'SOFTWARE\Microsoft\Internet Explorer'
	$Value = 'svcVersion'
	$ValueType = 'reg_sz'

	$RegValue = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
	
	$version = 0
	If ($RegValue -match '(\d+)\.') {
		If ([int]$matches[1] -gt $version) {
			$version = $matches[1]
		}
	}
	
	If ([int]$version -gt 0) {
		$version = 'Internet Explorer ' + $version
	} else {
		$version = 'Not Found'
	}
				
	If ($version -eq 'Not Found') {
		$Value = 'Version'
		$RegValue = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
		
		$version = 0
		If ($RegValue -match '(\d+)\.') {
			If ([int]$matches[1] -gt $version) {
				$version = $matches[1]
			}
		}
			
		If ([int]$version -gt 0) {
			$version = 'Internet Explorer ' + $version
		} else {
			$version = 'Not Found'
		}
	}
	
	$IeVersion = $version
					
	## GET OFFICE VERSION
	Try
	{
		$version = 0
		
		$sb = {
			Param ( [string]$address )
			$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $address)
			$reg.OpenSubKey('software\Microsoft\Office').GetSubKeyNames() |% {
				If ($_ -match '(\d+)\.') {
					If ([int]$matches[1] -gt $version) {
						$version = $matches[1]
					}
				}
			}
		
			switch ($version) {
				10 {$version = 'Office XP'; break}
				11 {$version = 'Office 2003'; break}
				12 {$version = 'Office 2007'; break}
				14 {$version = 'Office 2010'; break}
				15 {$version = 'Office 2013'; break}
                16 {$version = 'Office 2016'; break}
				default {$version = 'Not Installed'; break}
			}
			
			$version
		}
		
		$j = Start-Job -ScriptBlock $sb -ArgumentList $address
		Test-Timeout $address 'Unable to get Office version. Job timed out.'
		
		$office = $j | Receive-Job
	}
	
	Catch
	{
		# Catch Errors
		Write-ErrorLog
	}
	
	## GET AV INFO
	$service = Get-Service McAfeeFramework -ErrorAction SilentlyContinue
	
	If ($service)
	{
		$exists = Test-Path -Path 'HKLM:\SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800'
			
        If ($exists -eq $true) {
			$Hive = 'hklm'
			$ValueType = 'reg_sz'
				
			$Key = 'SOFTWARE\Wow6432Node\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800'
			$Value = 'DATVersion'

			$datFileVersion = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
			
			$Value = 'DatInstallDate'

			$datInstallDate = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
			
			Try
			{
				$datInstallDate = [datetime]::ParseExact($datInstallDate, "yyyyMMddHHmmss", $null)
			}
				
			Catch
			{
				$datInstallDate = 'Invalid TimeDate'
				#Write-ErrorLog
			}
		} 
		Else 
		{
			$Hive = 'hklm'
			$ValueType = 'reg_sz'
				
			$Key = 'SOFTWARE\Network Associates\ePolicy Orchestrator\Application Plugins\VIRUSCAN8800'
			$Value = 'DATVersion'

			$datFileVersion = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
				
			$Value = 'DatInstallDate'

			$datInstallDate = Get-RegValue -ComputerName $Env:COMPUTERNAME -Hive $Hive -Key $Key -Value $Value -ValueType $ValueType
			
			Try
			{
				$datInstallDate = [datetime]::ParseExact($datInstallDate, "yyyyMMddHHmmss", $null)
			}
				
			Catch
			{
				$datInstallDate = 'Invalid TimeDate'
				#Write-ErrorLog
			}
		}
	}
	
	# Add values to details hash
	$Details.Sdc 			= $Sdc
	$Details.OsInfo 		= $Os + ' \ ' + $OsArch
	$Details.IeVersion 		= $IeVersion
	$Details.OfficeVersion 	= $office
	$Details.datFileVersion = If ($datFileVersion -ne $null) {$datFileVersion} Else {'Not Found'}
	$Details.datInstallDate = If ($datFileVersion -ne $null) {$datInstallDate.ToString('G')} Else {'Not Found'}
}

#EndRegion: Software Info

#Region: Info from ini File

Function Get-IniInfo
{
	$ini = Get-IniContent $iniFile
	
	$Details.FpconReal = $ini['Security']['FPCon']
	$Details.FpconExcer = $ini['Security']['ExerciseFPCon']
	$Details.InfoconReal = $ini['Security']['InfoCon']
	$Details.InfoconExcer = $ini['Security']['ExerciseINFOCon']
	$Details.HsThreatCon = $ini['Security']['HSThreatCon']
	$Details.EntNetCon = $ini['Connectivity']['EntNetCon']
	$Details.EmailState = $ini['Connectivity']['EMail']
	$Details.Internet = $ini['Connectivity']['Internet']
}

#EndRegion: Info from ini File

# get current directoy
$scriptpath 			= $MyInvocation.MyCommand.Path
$currentdir 			= Split-Path $scriptpath

# Set date for temp dir
$d 						= Get-Date
$d 						= $d.ToString("yyyyMMdd-HHmm")

# Error Action
$ErrorActionPreference 	= "Stop"							# Must be set for try/catch statments to work

# Define Log Files
$LogFile 				= $currentdir + "\log\$($Env:COMPUTERNAME)-Log-$d.txt"

# Define path to ini config file
$iniFile				= $currentdir + "\settings.ini"

# Set Synchronized (thread safe) objects
$script:Gui 			= [Hashtable]::Synchronized(@{})
$script:Details			= [Hashtable]::Synchronized(@{})

# Load required .Net assemblies into memory
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Enable enhanced visuals
[System.Windows.Forms.Application]::EnableVisualStyles()

# Populate details hashtable with user data
Get-UserInfo

# Populate details hashtable with system data
Get-SysInfo

# Populate details hashtable with software data
Get-SoftInfo

# Populate details hashtable with info from ini file
Get-IniInfo

# Display Network Dashboard
Get-Dashboard