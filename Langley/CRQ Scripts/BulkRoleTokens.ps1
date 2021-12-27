#Created by SrA Calabrese, Michael

# Import CSV with account information
$csv = Import-Csv '\\zhtx-bs-013v\CYOD\08--Personal Storage\Calabrese\DS_Scripts\RoleTokens.csv'

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
        #$Password #| clip.exe
        Add-Type -Assembly PresentationCore
        $clipText = $Password | Out-String -Stream
        [Windows.Clipboard]::SetText($clipText)
        }
    }

Foreach ($token in $csv)
            
        {
            # Create unique password for each account
            $password=Generate-Password

            # Creates service account with required flags
            New-ADUser -Name $token.AcctName -PasswordNeverExpires $false -SmartcardLogonRequired $true -ChangePasswordAtLogon:$false -Enabled $true -Verbose `
            -UserPrincipalName $token.UPN `
            -AccountPassword (ConvertTo-SecureString -AsPlainText $password -Force) `
            -Path $token.OU `
            -DisplayName $token.AcctName `
            -Description $token.Description `
            -Office $token.Office `
            -Organization $token.Org `
            -OfficePhone $token.Phone `
            -EmailAddress $token.Email `
            -LogonWorkstations $token.LogonWorkstations `
            -OtherAttributes @{l=$token.Base;EmployeeType="S";extensionAttribute13=$token.Email;extensionAttribute3="SVC"}
            


        }