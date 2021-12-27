taskkill /IM EXCEL.EXE /F
taskkill /IM OUTLOOK.EXE /F
taskkill /IM WINWORD.EXE /F
taskkill /IM LYNC.EXE /F
taskkill /IM POWERPNT.EXE /F
taskkill /IM MSACCESS.EXE /F

if not exist "C:\NCCLogs\" mkdir C:\NCCLogs
Echo ====================================================================== >> C:\NCCLogs\Officelog.txt
Echo %date% %time% >> C:\NCCLogs\Officelog.txt

For %%a in (C:\PatcherNew\Patches\Updates\*.exe) Do (
        "%%a" /norestart /q
	echo %%a %errorlevel% >> C:\NCCLogs\Officelog.txt
) 

For %%a in (C:\PatcherNew\Patches\Updates\*.msp) Do (
        "%%a" /norestart /q
	echo %%a %errorlevel% >> C:\NCCLogs\Officelog.txt
)