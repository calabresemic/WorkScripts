$ou = gc 'C:\Users\1522878339A\Desktop\New Text Document.txt'
foreach($u in $ou){    
    Get-ADUser -SearchBase $u -Filter * -Properties * | select DisplayName,CN,Mail | where {$_.Mail -like "*.jp@us.af.mil"} | Export-CSV C:\Users\1522878339a\desktop\FNUsers.csv -append}