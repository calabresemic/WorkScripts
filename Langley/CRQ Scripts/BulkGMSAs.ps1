#Created by SSgt Calabrese, Michael

# Import CSV with account information
$csv = Import-Csv '\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\CRQ Scripts\GMSAs.csv'

Foreach ($svc in $csv)
            
        {

            # Creates service account with required flags
            New-ADServiceAccount -name $svc.AcctName -DNSHOSTName ($svc.AcctName + ".area52.afnoapps.usaf.mil") -KerberosEncryptionType 'AES128,AES256' -PrincipalsAllowedToRetrieveManagedPassword $svc.PasswordRetrieval

            # Adds the remaining OSH compliant values
            Set-ADServiceAccount -Identity $svc.AcctName -Description $svc.Description `
            -Add @{"employeeType"="S";"extensionAttribute13"=$svc.email;"extensionAttribute3"="SVC";"l"=$svc.Base;"o"=$svc.Org;"physicalDeliveryOfficeName"=$svc.Office;"telephoneNumber"=$svc.Phone;"msExchExtensionAttribute18"=$svc.RequestNumber}
        }