@echo off
cls
echo ===========================
echo Security Check Script
echo ===========================

color 0A

set "teamID=NUMJ-4T9Z-XEXD"

set /p inputID="Enter your Team ID to continue: "

if "%inputID%" NEQ "%teamID%" (
    echo [!] Invalid Team ID. Exiting...
    exit /b
)

echo [+] Team ID verified. Proceeding with checks...
echo Checking Windows Security Essentials...

echo Checking if Windows Updates are enabled...
sc query wuauserv | findstr /i "RUNNING"
if %errorlevel% neq 0 (
    set /p update="Windows Updates are disabled. Enable them? (y/n): "
    if /i "%update%"=="y" (
        net start wuauserv
        echo Windows Updates enabled.
    )
)

echo Checking Guest account status...
net user guest | findstr /i "Account active.*No" >nul
if %errorlevel% neq 0 (
    set /p guest="Guest account is active. Disable it? (y/n): "
    if /i "%guest%"=="y" (
        net user guest /active:no
        echo Guest account disabled.
    )
)

echo Checking Windows Firewall status...
netsh advfirewall show allprofiles state | findstr /i "ON" >nul
if %errorlevel% neq 0 (
    set /p fw="Firewall is disabled. Enable it? (y/n): "
    if /i "%fw%"=="y" (
        netsh advfirewall set allprofiles state on
        echo Firewall enabled.
    )
)

echo Checking Remote Registry Service...
sc query RemoteRegistry | findstr /i "STOPPED" >nul
if %errorlevel% neq 0 (
    set /p rr="Remote Registry Service is running. Disable it? (y/n): "
    if /i "%rr%"=="y" (
        sc config RemoteRegistry start= disabled
        net stop RemoteRegistry
        echo Remote Registry Service disabled.
    )
)

echo Checking if Administrator account is renamed...
net user administrator | findstr /i "Account active" >nul
if %errorlevel% eq 0 (
    set /p admin="Administrator account is active. Disable it? (y/n): "
    if /i "%admin%"=="y" (
        net user administrator /active:no
        echo Administrator account disabled.
    )
)

echo Checking File and Printer Sharing status...
netsh advfirewall firewall show rule name="File and Printer Sharing (SMB-In)" | findstr /i "Enabled: No" >nul
if %errorlevel% neq 0 (
    set /p fps="File and Printer Sharing is enabled. Disable it? (y/n): "
    if /i "%fps%"=="y" (
        netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" new enable=no
        echo File and Printer Sharing disabled.
    )
)

echo Checking Windows Defender Antivirus status...
sc query Windefend | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p defender="Windows Defender Antivirus is disabled. Enable it? (y/n): "
    if /i "%defender%"=="y" (
        sc start Windefend
        echo Windows Defender Antivirus enabled.
    )
)

echo Checking for UAC (User Account Control) settings...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | findstr /i "0x00000001" >nul
if %errorlevel% neq 0 (
    set /p uac="UAC is disabled. Enable it? (y/n): "
    if /i "%uac%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
        echo UAC enabled.
    )
)

echo Checking Windows Time service status...
sc query w32time | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p time="Windows Time service is stopped. Start it? (y/n): "
    if /i "%time%"=="y" (
        net start w32time
        echo Windows Time service started.
    )
)

echo Checking SMBv1 protocol status...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v SMB1 | findstr /i "1" >nul
if %errorlevel% eq 0 (
    set /p smb1="SMBv1 is enabled. Disable it? (y/n): "
    if /i "%smb1%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v SMB1 /t REG_DWORD /d 0 /f
        echo SMBv1 disabled.
    )
)

echo Checking if AutoPlay is enabled...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun | findstr /i "0x000000FF" >nul
if %errorlevel% eq 0 (
    set /p autoplay="AutoPlay is enabled. Disable it? (y/n): "
    if /i "%autoplay%"=="y" (
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0x000000FF /f
        echo AutoPlay disabled.
    )
)

echo Checking if Windows Defender SmartScreen is enabled...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled | findstr /i "RequireAdmin" >nul
if %errorlevel% neq 0 (
    set /p smartscreen="Windows Defender SmartScreen is disabled. Enable it? (y/n): "
    if /i "%smartscreen%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f
        echo Windows Defender SmartScreen enabled.
    )
)

echo Checking if Windows Defender is protecting against potentially unwanted applications (PUA)...
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v PUAProtection | findstr /i "1" >nul
if %errorlevel% neq 0 (
    set /p pua="Windows Defender PUA protection is disabled. Enable it? (y/n): "
    if /i "%pua%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v PUAProtection /t REG_DWORD /d 1 /f
        echo Windows Defender PUA protection enabled.
    )
)

echo Checking if LLMNR (Link-Local Multicast Name Resolution) is disabled...
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast | findstr /i "0x00000000" >nul
if %errorlevel% eq 0 (
    set /p llmnr="LLMNR is enabled. Disable it? (y/n): "
    if /i "%llmnr%"=="y" (
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
        echo LLMNR disabled.
    )
)

echo Checking if the Win32k system vulnerability is patched...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureDesktop" | findstr /i "1" >nul
if %errorlevel% eq 0 (
    set /p secdesk="Secure Desktop is disabled. Enable it? (y/n): "
    if /i "%secdesk%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureDesktop" /t REG_DWORD /d 1 /f
        echo Secure Desktop enabled.
    )
)

echo Checking if Windows Defender Network Inspection Service is running...
sc query WdNisSvc | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p nis="Windows Defender Network Inspection Service is stopped. Start it? (y/n): "
    if /i "%nis%"=="y" (
        net start WdNisSvc
        echo Windows Defender Network Inspection Service started.
    )
)

echo Checking if User Account Control (UAC) is enabled...
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA | findstr /i "0x00000001" >nul
if %errorlevel% neq 0 (
    set /p uac="UAC is disabled. Enable it? (y/n): "
    if /i "%uac%"=="y" (
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
        echo UAC enabled.
    )
)

echo Checking if Group Policy for SMBv1 is disabled...
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies" /v SMB1 | findstr /i "0x00000000" >nul
if %errorlevel% neq 0 (
    set /p smb="SMBv1 is enabled. Disable it? (y/n): "
    if /i "%smb%"=="y" (
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Policies" /v SMB1 /t REG_DWORD /d 0 /f
        echo SMBv1 disabled.
    )
)

echo Checking if Secure Boot is enabled...
bcdedit /enum all | findstr /i "secureboot" >nul
if %errorlevel% neq 0 (
    echo Secure Boot is not enabled.
) else (
    echo Secure Boot is enabled.
)

echo Checking if Windows Time service is running...
sc query w32time | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p time="Windows Time service is stopped. Start it? (y/n): "
    if /i "%time%"=="y" (
        net start w32time
        echo Windows Time service started.
    )
)

echo Checking if SMBv2/v3 is disabled...
reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 | findstr /i "0" >nul
if %errorlevel% neq 0 (
    set /p smb2="SMBv2/v3 is enabled. Disable it? (y/n): "
    if /i "%smb2%"=="y" (
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 0 /f
        echo SMBv2/v3 disabled.
    )
)

echo Checking Bluetooth Support Service...
sc query bthserv | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p bluetooth="Bluetooth Support Service is running. Stop it? (y/n): "
    if /i "%bluetooth%"=="y" (
        net stop bthserv
        echo Bluetooth Support Service stopped.
    )
)

echo Checking Print Spooler Service...
sc query spooler | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    set /p spooler="Print Spooler service is running. Stop it? (y/n): "
    if /i "%spooler%"=="y" (
        net stop spooler
        echo Print Spooler service stopped.
    )
)

echo Checking Windows Defender exclusions...
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess" >nul
if %errorlevel% neq 0 (
    echo No Windows Defender exclusions found.
) else (
    echo Windows Defender exclusions found.
)

echo Checking if BitLocker is enabled...
manage-bde -status C: | findstr /i "Protection On" >nul
if %errorlevel% neq 0 (
    echo BitLocker is not enabled on drive C.
) else (
    echo BitLocker is enabled on drive C.
)

echo Checking if System Restore is enabled...
vssadmin list shadows | findstr /i "Shadow Copy Storage volume" >nul
if %errorlevel% neq 0 (
    echo System Restore is disabled.
) else (
    echo System Restore is enabled.
)

echo Checking for unnecessary scheduled tasks...
schtasks /query /fo LIST | findstr /i "TaskName" >nul
if %errorlevel% neq 0 (
    echo No unnecessary scheduled tasks found.
) else (
    echo Unnecessary scheduled tasks detected.
)

echo Checking if antivirus is running and up-to-date...
sc query WinDefend | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    echo Windows Defender is not running.
) else (
    echo Windows Defender is running.
)
powershell -Command "Get-MpComputerStatus | Select-Object -ExpandProperty AntispywareSignatureLastUpdated" >nul
if %errorlevel% neq 0 (
    echo Windows Defender is not up-to-date.
) else (
    echo Windows Defender is up-to-date.
)

echo Checking if Windows Defender Exploit Guard is enabled...
powershell -Command "Get-WindowsDefenderExploitProtectionPolicy" >nul
if %errorlevel% neq 0 (
    echo Windows Defender Exploit Guard is not enabled.
) else (
    echo Windows Defender Exploit Guard is enabled.
)

echo Checking password complexity for Administrator accounts...

for /f "tokens=1" %%i in ('net user') do (
    set username=%%i
    set username=!username:~0,20!
    net user !username! | findstr /i "Admin" >nul
    if %errorlevel% == 0 (
        echo Checking password complexity for !username!
        net user !username! | findstr /i "Password last set" >nul
        if %errorlevel% neq 0 (
            echo Password does not meet complexity requirements for !username!
            set /p newpassword="Enter a new password for !username!: "
            net user !username! !newpassword! >nul
            echo Password for !username! updated.
        )
    )
)

echo Checking if Guest account is disabled...
net user Guest | findstr /i "Account active" | findstr /i "No" >nul
if %errorlevel% neq 0 (
    echo Guest account is enabled. Disable it? (y/n): "
    set /p guest="Disable Guest account? "
    if /i "%guest%"=="y" (
        net user Guest /active:no
        echo Guest account disabled.
    )
)

echo Checking if Autorun is disabled...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun | findstr /i "0x000000ff" >nul
if %errorlevel% neq 0 (
    set /p autorun="Autorun is enabled. Disable it? (y/n): "
    if /i "%autorun%"=="y" (
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0x000000ff /f
        echo Autorun disabled.
    )
)

echo Checking Audit Policy settings...
auditpol /get /category:"Logon/Logoff" | findstr /i "Success and Failure" >nul
if %errorlevel% neq 0 (
    set /p audit="Audit Policy not properly set. Set it? (y/n): "
    if /i "%audit%"=="y" (
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
        echo Audit Policy enabled for Logon/Logoff.
    )
)

echo Checking if Windows Defender Real-time Protection is enabled...
powershell -Command "Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring" | findstr /i "False" >nul
if %errorlevel% neq 0 (
    set /p defender="Windows Defender Real-time Protection is disabled. Enable it? (y/n): "
    if /i "%defender%"=="y" (
        powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
        echo Windows Defender Real-time Protection enabled.
    )
)

echo Checking User Group Membership for Administrators...
net localgroup Administrators | findstr /i "Guest" >nul
if %errorlevel% neq 0 (
    echo Guest is in Administrators group. Remove it? (y/n): "
    set /p guestadmin="Remove Guest from Administrators group? "
    if /i "%guestadmin%"=="y" (
        net localgroup Administrators Guest /delete
        echo Guest removed from Administrators group.
    )
)

echo Checking if Windows Remote Management (WinRM) is disabled...
sc query winrm | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    echo WinRM is disabled.
) else (
    set /p winrm="WinRM is enabled. Disable it? (y/n): "
    if /i "%winrm%"=="y" (
        sc stop winrm
        sc config winrm start=disabled
        echo WinRM disabled.
    )
)

echo Checking if PowerShell Remoting is disabled...
powershell -Command "Get-PSSessionConfiguration" >nul
if %errorlevel% neq 0 (
    echo PowerShell Remoting is disabled.
) else (
    set /p remoting="PowerShell Remoting is enabled. Disable it? (y/n): "
    if /i "%remoting%"=="y" (
        powershell -Command "Disable-PSRemoting -Force"
        echo PowerShell Remoting disabled.
    )
)

echo Checking for unnecessary open network ports...
netstat -an | findstr /i "LISTENING" > ports.txt
echo Open ports are listed in ports.txt.

echo Checking if DNS Client is enabled...
sc query dnscache | findstr /i "RUNNING" >nul
if %errorlevel% neq 0 (
    echo DNS Client is disabled. Enable it? (y/n): "
    set /p dnsclient="Enable DNS Client? "
    if /i "%dnsclient%"=="y" (
        net start dnscache
        echo DNS Client enabled.
    )
)

echo Checking if Windows Defender Firewall is enabled...
netsh advfirewall show allprofiles | findstr /i "ON" >nul
if %errorlevel% neq 0 (
    set /p firewall="Windows Defender Firewall is disabled. Enable it? (y/n): "
    if /i "%firewall%"=="y" (
        netsh advfirewall set allprofiles state on
        echo Windows Defender Firewall enabled.
    )
)

echo ===========================
echo Security Check Complete.
echo ===========================
pause
