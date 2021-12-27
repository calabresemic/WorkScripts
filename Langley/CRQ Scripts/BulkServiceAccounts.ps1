#Created by SrA Calabrese, Michael

# Import CSV with account information
$csv = Import-Csv '\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\ServiceAccounts.csv'

# This portion sets up the password generator

# Password command forces 2 sym / 2 num / 2 UPPER / 2 lower and randomizes last 8 
# Common error digits have been removed ex: oO0 ,. :;
Function Generate-Password {
    param ([Int]$numPasswords = 1)

    1..$numPasswords | ForEach-Object {
        $CharsD = [Char[]]"123456789" 
        $CharsL = [Char[]]"abcdefghjkmnpqrstuvxyz"
        $CharsU = [Char[]]"ABCDEFGHJKLMNPQRSTUVXYZ"
        $CharsS = [Char[]]"!@#$%^&*+=?"
        $CharsA = [Char[]]"!@#$%^&*+=?ABCDEFGHJKLMNPQRSTUVXYZabcdefghjkmnpqrstuvxyz123456789"
        $Password = ""
        $Password += ($CharsD | Get-Random -Count 2) -join ""
        $Password += ($CharsL | Get-Random -Count 2) -join ""
        $Password += ($CharsU | Get-Random -Count 2) -join ""
        $Password += ($CharsS | Get-Random -Count 2) -join ""
        $Password += ($CharsA | Get-Random -Count (8..12 | Get-Random)) -join ""
        $Password = ($Password.ToCharArray()| Sort-Object {Get-Random}) -join ""
        Write-Output $Password
        }
    }

Foreach ($svc in $csv)
            
        {
            # Create unique password for each account
            $password=Generate-Password

            # Creates service account with required flags
            New-ADUser -Name $svc.AcctName -PasswordNeverExpires $false -SmartcardLogonRequired $false -ChangePasswordAtLogon:$true -Enabled $true -Verbose `
            -AccountPassword (ConvertTo-SecureString -AsPlainText $password -Force) `
            -Path $svc.OU `
            -UserPrincipalName $svc.AcctName `
            -DisplayName $svc.AcctName `
            -Description $svc.Description `
            -Office $svc.Office `
            -Organization $svc.Org `
            -OfficePhone $svc.Phone `
            -EmailAddress $svc.Email `
            -LogonWorkstations $svc.LogonWorkstations `
            -OtherAttributes @{l=$svc.Base;EmployeeType="S";extensionAttribute13=$svc.Email;extensionAttribute3="SVC";"msExchExtensionAttribute18"=$svc.RequestNumber}
            
            # Adds Account to default group
            Add-ADGroupMember -Identity "GLS_AREA52_AdminServiceAccounts" -Members $svc.AcctName
            
            # Exports account and password to document so you can send to customer
            # DO NOT SEND CSV TO CUSTOMER
            [pscustomobject] @{Name=$svc.AcctName;Password=$password} | Export-Csv -NoTypeInformation -Append '\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\ServiceAccountResults.csv'


        }