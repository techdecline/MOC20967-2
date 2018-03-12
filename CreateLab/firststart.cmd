powershell.exe -command { set-executionpolicy -executionpolicy Bypass -force }
powershell.exe -file c:\sys\firstrun.ps1 -executionpolicy Bypass
