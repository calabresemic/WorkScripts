# Creates service account with required flags
New-ADServiceAccount -name msa.AR52.RMAD$ -DNSHOSTName "msa.AR52.RMAD.area52.afnoapps.usaf.mil" -KerberosEncryptionType 'AES128,AES256' -PrincipalsAllowedToRetrieveManagedPassword "ZHTX-AS-003v$"

# Adds the remaining OSH compliant values
Set-ADServiceAccount -Identity msa.AR52.RMAD$ -Description "83 NOS RMAD service account" `
-Add @{"employeeType"="S";"extensionAttribute13"= "83nos.cyod@us.af.mil";"extensionAttribute3"="SVC";"l"="Enterprise";"o"="83 NOS";"physicalDeliveryOfficeName"="CYOD";"telephoneNumber"="312-764-7663";"msExchExtensionAttribute18"="WO0000000015199"}