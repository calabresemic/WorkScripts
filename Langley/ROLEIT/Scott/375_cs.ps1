#==========================================================
# FileName:    375_CS.ps1
# Usage:       for login by all 375_CS Scott users to Area52 domain
#==========================================================

#==========================================================
# Created by Chris Mclain - 05 Jan 2021
#==========================================================


#==========================================================
# Map Network Drives
#==========================================================
Function Map-NetworkDrive($driveletter,$path){
	$psdrives = get-psdrive -PSProvider FileSystem

	if( $psdrives.Name.Contains($driveletter) ) {
		#driveletter is already mapped check if it is mapped to the correct location
		if ( $psdrives[$psdrives.Name.IndexOf($driveletter)].DisplayRoot -ne $path){
			#driveletter is mapped to wrong location, unmap and remap to correct location
			Remove-psdrive -name $driveletter
			new-psdrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global | Out-Null
		}
	}
	Else {
		#drive is not mapped
		new-psdrive -name $driveletter -psprovider FileSystem -root $path -Persist -Scope Global | Out-Null
	}
}

#---------------------------------------------------------
$adobj = ([adsisearcher]"Samaccountname=$env:Username").findone()
$groups = $adobj.properties.memberof | %{$_.split("=")[1].split(",")[0]}
#---------------------------------------------------------

#Maps Drives for all users
Map-NetworkDrive G "\\VDYD-FS-007P\375-CG\VEJX-375CG-G\375 CS new"
Map-NetworkDrive Y "\\VDYD-FS-007P\VEJX-FUNCTIONAL APPS\VEJX-FUNCTIONAL-A"

#----------------------------------------------------------

If("GLS_375 CS_SCPNS" -in $groups){
 
	 Map-NetworkDrive R "\\vdyd-fs-007p\375CS-SCON\375CS-SCON"
	 Map-NetworkDrive O "\\VDYD-FS-008V\SAFB\375 AMW\375 CS\SCONS"
}

#==========================================================
# Map Scott Secure Print
#==========================================================

Function Map-Printer($printer){
	Add-Printer –ConnectionName $printer
}

#----------------------------------------------------------

$SecurePrint = "\\vdyd-qs-001v\ScottSecurePrint"
Map-Printer $SecurePrint

#----------------------------------------------------------