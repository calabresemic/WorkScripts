#This will generate a new RDG file for the domain
#Created by Michael Calabrese (1468714589)

Function Create-AREA52RDGFile {
    [CmdletBinding()]

    Param(
        [Parameter(Mandatory)]
        [String]$RDManFile
        )

    #These functions were taken from RDCMan and modified to account for nested groups
    #https://www.powershellgallery.com/packages/RDCMan/1.0.0

    function New-RDCManFile{
  <#
      .SYNOPSIS
      Creates a new Remote Desktop Connection Manager File.

      .DESCRIPTION
      Creates a new Remote Desktop Connection Manager File for version 2.7
      which can then be modified.
      .PARAMETER  FilePath
      Input the path for the file you wish to Create.

      .PARAMETER  Name
      Input the name for the Structure within the file.

      .EXAMPLE
      PS C:\> New-RDCManFile -FilePath .\Test.rdg -Name RDCMan
      'If no output is generated the command was run successfully'
      This example shows how to call the Name function with named parameters.


      .INPUTS
      System.String

      .OUTPUTS
      Null
  #>
  Param(
    [Parameter(Mandatory = $true)]
    [String]$FilePath,
    
    [Parameter(Mandatory = $true)]
    [String]$Name,

    [Parameter(Mandatory = $false)]
    [Switch]$Force
  )
  BEGIN
  {
    [string]$template = @' 
<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.81" schemaVersion="3">
  <file>
    <credentialsProfiles />
    <properties>
      <expanded>True</expanded>
      <name></name>
    </properties>
    <displaySettings inherit="None">
      <liveThumbnailUpdates>True</liveThumbnailUpdates>
      <allowThumbnailSessionInteraction>False</allowThumbnailSessionInteraction>
      <showDisconnectedThumbnails>True</showDisconnectedThumbnails>
      <thumbnailScale>1</thumbnailScale>
      <smartSizeDockedWindows>True</smartSizeDockedWindows>
      <smartSizeUndockedWindows>True</smartSizeUndockedWindows>
    </displaySettings>
  </file>
  <connected />
  <favorites />
  <recentlyUsed />
</RDCMan>
'@ 
    $FilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
    if($Force -eq $true){Remove-Item $FilePath -Force -ErrorAction SilentlyContinue}
    if(Test-Path -Path $FilePath){
        Write-Error -Message 'File Already Exists'
        }
    else{
        $xml = New-Object -TypeName Xml
        $xml.LoadXml($template)
        }
  }
  PROCESS
  {
    $File = (@($xml.RDCMan.file.properties)[0]).Clone()
    $File.Name = $Name
    
    $xml.RDCMan.file.properties |
    Where-Object -FilterScript {
      $_.Name -eq ''
    } |
    ForEach-Object -Process {
      [void]$xml.RDCMan.file.ReplaceChild($File,$_)
    }
  }
  END
  {
    $xml.Save($FilePath)
  }
}

    function New-RDCManGroup{
  <#
      .SYNOPSIS
      Creates a new Group within your Remote Desktop Connection Manager File.

      .DESCRIPTION
      Creates a new Group within your Remote Desktop Connection Manager File for version 2.7.
      which can then be modified.
      .PARAMETER  FilePath
      Input the path for the file you wish to Create.

      .PARAMETER  Name
      Input the name for the Group you wish to create within the file.

      .EXAMPLE
      PS C:\> New-RDCManGroup -FilePath .\Test.rdg -Name RDCMan
      'If no output is generated the command was run successfully'
      This example shows how to call the Name function with named parameters.


      .INPUTS
      System.String

      .OUTPUTS
      Null
  #>
  Param(
    [Parameter(Mandatory = $true)]
    [String]$FilePath,
    
    [Parameter(Mandatory = $false)]
    [String]$ParentGroupName,

    [Parameter(Mandatory = $true)]
    [String]$Name
  )
  BEGIN
  {
    $FilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
    if(Test-Path -Path $FilePath)
    {
      $xml = New-Object -TypeName XML
      $xml.Load($FilePath)
    } 
    else
    {
      Write-Error -Exception $_.Exception
      throw $_.Exception
    }
  }
  PROCESS
  {
    $group = $xml.CreateElement('group')
    $grouproperties = $xml.CreateElement('properties')
      
    $groupname = $xml.CreateElement('name')
    $groupname.set_InnerXML($Name)
      
    $groupexpanded = $xml.CreateElement('expanded')
    $groupexpanded.set_InnerXML('False')
      
    [void]$grouproperties.AppendChild($groupname)
    [void]$grouproperties.AppendChild($groupexpanded)
    [void]$group.AppendChild($grouproperties)

    if($ParentGroupName){
        $ParentGroup = @($xml.RDCMan.file.group) | Where-Object -FilterScript {$_.properties.name -eq $ParentGroupName}
        [void]$ParentGroup.AppendChild($group)
        }
    else{
        [void]$xml.RDCMan.file.AppendChild($group)
        }
  }
  END
  {
    $xml.Save($FilePath)
  }
}

    function New-RDCManServer{
  <#
      .SYNOPSIS
      Creates a new Server within a group in your Remote Desktop Connection Manager File.

      .DESCRIPTION
      Creates a new server within the  Remote Desktop Connection Manager File.

      .PARAMETER  FilePath
      Input the path for the file you wish to append a new group.

      .PARAMETER  DisplayName
      Input the name DisplayName of the server.
      
      .PARAMETER  Server
      Input the FQDN, IP Address or Hostname of the server.

      .PARAMETER  GroupName
      Input the name DisplayName of the server.

      .EXAMPLE
      PS C:\> New-RDCManServer -FilePath .\Test.rdg -DisplayName RDCMan -Server '10.10.0.5' -Group Test
      'If no output is generated the command was run successfully'
      This example shows how to call the Name function with named parameters.

      .INPUTS
      System.String

      .OUTPUTS
      Null
  #>
  Param(
    [Parameter(Mandatory = $true)]
    [String]$FilePath,

    [Parameter(Mandatory = $true)]
    [String]$GroupName,

    [Parameter(Mandatory = $false)]
    [String]$ParentGroupName,

    [Parameter(Mandatory = $true)]
    [String]$Server,

    [Parameter(Mandatory = $true)]
    [String]$DisplayName
  )
  BEGIN
  {
    $FilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
    if(Test-Path -Path $FilePath)
    {
      $xml = New-Object -TypeName XML
      $xml.Load($FilePath)
    } 
    else
    {
      Write-Error -Exception $_.Exception
      throw $_.Exception
    }
  }
  PROCESS
  {
    $ServerNode = $xml.CreateElement('server')
    $serverproperties = $xml.CreateElement('properties')

    $servername = $xml.CreateElement('name')
    $servername.set_InnerXML($Server)
    
    $serverdisplayname = $xml.CreateElement('displayName')
    $serverdisplayname.set_InnerXML($DisplayName)
    
    [void]$serverproperties.AppendChild($servername)
    [void]$serverproperties.AppendChild($serverdisplayname)

    [void]$ServerNode.AppendChild($serverproperties)

    if($ParentGroupName){
        $ParentGroup = @($xml.RDCMan.file.group) | Where-Object -FilterScript {
            $_.properties.name -eq $ParentGroupName
            }
        $group = @($ParentGroup.group) | Where-Object -FilterScript {
            $_.properties.name -eq $groupname
            }
        }
    else{
        $group = @($xml.RDCMan.file.group) | Where-Object -FilterScript {
            $_.properties.name -eq $groupname
            }
        }
    [void]$group.AppendChild($ServerNode)
  }
  END
  {
    $xml.Save($FilePath)
  }
}

#An awful array of ANG Sites
$ANGSites=@"
AJXX-Andrews-ANG
AFTG-Alpena
AVND-Bangor
AXQD-Barnes
AYZZ-BattleCreek
BRKM-Birmingham
CEKT-BradleyField
CSUG-Buckley-ANG
CURU-Burlington
DDPG-Carswell-ANG
DJCF-ChannelIsland
DLAL-Charlotte
DPEV-Cheyenne
FAKZ-DannellyField
FFAJ-DesMoines
FMKZ-Duluth
FMKG-Duluth
FTDD-EggHarbor
FTQG-Eielson-ANG
FWJL-EllingtonField
GUQE-ForbesField
HKRV-FortSmith
HLLL-FortWayne
HAWS-Fresno
HTUX-GenMitchellField
JEGW-GowenField
JKSB-GreatFalls
GAUC-Griffiss
JTVE-Gulfport
KEMJ-Harrisburg
KKGA-HectorField
ZAWG-Horsham
LRXY-Jackson
LSFY-Jacksonville
LTVJ-JeffersonBarracks
LUXC-JoeFossField
MDVL-KeyField
MFUK-KingsleyField
MPLG-Lackland-ANG
NGCS-Lincoln
NKAG-LittleRock-ANG
NSQN-Louisville
PBXP-Mansfield
PCZG-March-ANG
PJMS-MartinStAirport
PJVY-Martinsburg
PRPG-McConnell-ANG
PSTE-McEntire
PSXE-McGheeTyson
PSXX-McGheeTyson-APC
PTFG-McGuire-ANG
PYKE-Memphis
QJVZ-Minot-ANG
QMSN-Moffett
RCKB-Muniz
RHEL-Nashville
RNSF-NewCastle
RQMA-NewOrleans
RVKG-NiagaraFalls-ANG
SPBU-Otis
SZDQ-Pease
TBBT-Peoria
TEWJ-Phoenix
JLSN-PittsburghIAP
TQJX-Portland
VVRK-SouthPortland
TWLR-QuonsetPoint
UCTE-Reno
NLZG-Rickenbacker
UHHG-Robins-ANG
USCG-SaltLakeCity
UZXF-Savannah
VDSE-Scotia
VDYG-Scott-ANG
VGLZ-Selfridge
VSRP-SiouxCity
VZUR-Springfield-IL
WAAR-Springfield-OH
WCJX-StJoseph
WDEY-StPaul
RSDQ-Stewart
WKVH-SuffolkCounty
KBJD-Syracuse
WPVJ-Tacoma
WTVR-TerreHaute
WNMT-Toledo
XGEN-TruaxField
XHDU-Tucson
XHZG-Tulsa
YAQF-VolkField
YZEU-WillRogers
LYBH-YeagerAirport
"@.Split("`n") | foreach {$_.trim()}

    $ADSites=(Get-ADReplicationSite -Filter { 
        (Name -notlike "*90*") -and
        (Name -notlike "*VPN*") -and
        (Name -notlike "*Medical*") -and
        (Name -notlike "*AFPEDC*") -and
        (Name -notlike "*CHES*") -and
        (Name -notlike "*RDC-DF*") -and
        (Name -notlike "*Gunter-AFIN*") -and
        (Name -notlike "*AZUR*") -and
        (Name -notlike "*ESUL*") -and
        (Name -notlike "*ASPR-*") -and
        (Name -notlike "*ALMY-*")
        }).Name | Sort-Object | %{
            if( ($_ -notin $ANGSites) -and ($_ -like "*-gsu-*") ){ ($_ -split '-gsu-')[1] }
            elseif($_ -notin $ANGSites){ $_ }
        }

    $AFNOSites=(Get-ADDomainController -Filter * -Server afnoapps.usaf.mil).Site | Select-Object -Unique

    New-RDCManFile -Name 'Directory Services COE' -FilePath $RDManFile -Force
    New-RDCManGroup -FilePath $RDManFile -Name 'ANG - 299 NOS - AREA52'
    New-RDCManGroup -FilePath $RDManFile -Name 'ACTIVE DUTY - AREA52'
    New-RDCManGroup -FilePath $RDManFile -Name 'AFNOAPPS DCs'

    $ANGSites | %{ New-RDCManGroup -FilePath $RDManFile -ParentGroupName 'ANG - 299 NOS - AREA52' -Name $_ }
    $ADSites | Sort-Object | %{New-RDCManGroup -FilePath $RDManFile -ParentGroupName 'ACTIVE DUTY - AREA52' -Name $_}
    $AFNOSites | Sort-Object | %{New-RDCManGroup -FilePath $RDManFile -ParentGroupName 'AFNOAPPS DCs' -Name $_}

    foreach($ANGSite in $ANGSites){
        $GEO=($ANGSite -Split '-')[0]
        $DCfltr="Name -like `"*$GEO-DC-*`""
        $HCfltr="Name -like `"*$GEO-HC-*`""
        $LCfltr="Name -like `"*$GEO-LC-*`""
        $RAfltr="Name -like `"*$GEO-RA-*`""
        $CAfltr="Name -like `"*$GEO-CA-*`""
        $Servers=@()
        $Servers+=Get-ADComputer -Filter $DCfltr -SearchBase 'OU=Domain Controllers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $HCfltr -SearchBase 'OU=DHCP,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $LCfltr -SearchBase 'OU=Log Collectors,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $RAfltr -SearchBase 'OU=DRA,OU=NETIQ,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $CAfltr -SearchBase 'OU=Certification Authority Servers,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        foreach($Server in ($Servers | Sort-Object) ){New-RDCManServer -FilePath $RDManFile -ParentGroupName 'ANG - 299 NOS - AREA52' -GroupName $ANGSite -Server $Server.DNSHostName.ToUpper() -DisplayName $Server.Name.ToUpper()}
        }

    foreach($ADSite in $ADSites){
        $GEO=($ADSite -Split '-')[0]
        $DCfltr="Name -like `"*$GEO-DC-*`""
        $HCfltr="Name -like `"*$GEO-HC-*`""
        $LCfltr="Name -like `"*$GEO-LC-*`""
        $RAfltr="Name -like `"*$GEO-RA-*`""
        $CAfltr="Name -like `"*$GEO-CA-*`""
        $GPTSfltr="Name -like `"*$GEO-GPTS-*`""
        $Servers=@()
        $Servers+=Get-ADComputer -Filter $DCfltr -SearchBase 'OU=Domain Controllers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $HCfltr -SearchBase 'OU=DHCP,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $LCfltr -SearchBase 'OU=Log Collectors,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $RAfltr -SearchBase 'OU=DRA,OU=NETIQ,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        $Servers+=Get-ADComputer -Filter $CAfltr -SearchBase 'OU=Certification Authority Servers,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
        if($ADSite -eq 'ZHTX-WrightPatterson-APC'){
            $Servers+=Get-ADComputer ZHTX-BS-003v | Select-Object Name,DNSHostName
            $Servers+=Get-ADComputer -Filter $GPTSfltr -SearchBase 'OU=GPA,OU=NETIQ,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
            }
        if($ADSite -eq 'VEJX-SCOTT-APC'){
            $Servers+=Get-ADComputer -Filter $GPTSfltr -SearchBase 'OU=GPA,OU=NETIQ,OU=SSC Member Servers,OU=AFNETOPS Servers,OU=Servers,DC=AREA52,DC=AFNOAPPS,DC=USAF,DC=MIL' | Select-Object Name,DNSHostName
            }
        foreach($Server in ($Servers | Sort-Object) ){New-RDCManServer -FilePath $RDManFile -ParentGroupName 'ACTIVE DUTY - AREA52' -GroupName $ADSite -Server $Server.DNSHostName.ToUpper() -DisplayName $Server.Name.ToUpper()}
        }

    foreach($AFNOSite in $AFNOSites){
        $GEO=($AFNOSite -Split '-')[0]
        $DCfltr="Name -like `"*$GEO-DC-*`""
        $AFNOServers=Get-ADComputer -Filter $DCfltr -SearchBase 'OU=Domain Controllers,DC=AFNOAPPS,DC=USAF,DC=MIL' -Server afnoapps.usaf.mil | Select-Object Name,DNSHostName
        foreach($AFNOServer in ($AFNOServers | Sort-Object) ){New-RDCManServer -FilePath $RDManFile -ParentGroupName 'AFNOAPPS DCs' -GroupName $AFNOSite -Server $AFNOServer.DNSHostName.ToUpper() -DisplayName $AFNOServer.Name.ToUpper()}
        }
    }