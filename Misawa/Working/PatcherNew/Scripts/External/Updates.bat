if not exist "C:\NCCLogs\" mkdir C:\NCCLogs
Echo ====================================================================== >> C:\NCCLogs\Updatelog.txt
Echo %date% %time% >> C:\NCCLogs\Updatelog.txt

For %%a in (C:\PatcherNew\Patches\Updates\*.exe) Do (
        "%%a" /norestart /q
	echo %%a %errorlevel% >> C:\NCCLogs\Updatelog.txt
)

For %%a in (C:\PatcherNew\Patches\Updates\*.cab) Do (
	Dism.exe /online /add-package /packagepath:"%%a" /quiet /norestart
	echo %%a %errorlevel% >> C:\NCCLogs\Updatelog.txt
)

For %%a in (C:\PatcherNew\Patches\Updates\*.msp) Do (
        "%%a" /norestart /q
	echo %%a %errorlevel% >> C:\NCCLogs\Updatelog.txt
)

For %%a in (C:\PatcherNew\Patches\Updates\*.msu) Do (
	wusa.exe "%%a" /norestart /quiet
	echo %%a %errorlevel% >> C:\NCCLogs\Updatelog.txt
)