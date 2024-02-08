@echo off
cls

echo =========================================================================
echo                          Windows Optimization Script By Maor                  
echo =========================================================================

:restorepoint
set /p createRestorePoint=Create a restore point first? (y/n)
if /i "%createRestorePoint%"=="y" (
  wmic /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Optimization Script", 100, 7
  echo Restore point created.
) else if /i "%createRestorePoint%"=="n" (
  echo Not creating restore point.
) else (
  echo Invalid input. Please enter y or n.
  goto restorepoint  
)

:disableipv6
set /p disableIPV6=Disable IPv6? (y/n) 
if /i "%disableIPV6%"=="y" (
  netsh interface ipv6 set interface "Ethernet" disabled
  netsh interface ipv6 set interface "Wi-Fi" disabled
  echo IPv6 disabled.
) else if /i "%disableIPV6%"=="n" (
  echo Not disabling IPv6.
) else (
  echo Invalid input. Please enter y or n.
  goto disableipv6
)

:optimizenetwork
set /p optimizeNetwork=Optimize network settings? (y/n)
if /i "%optimizeNetwork%"=="y" (
  netsh int tcp set global autotuninglevel=normal
  netsh int tcp set global rss=enabled
  echo Network settings optimized.
) else if /i "%optimizeNetwork%"=="n" (
  echo Not optimizing network settings. 
) else (
  echo Invalid input. Please enter y or n.
  goto optimizenetwork
)

:cleartempfiles
set /p clearTempFiles=Clear temporary files? (y/n)
if /i "%clearTempFiles%"=="y" (
  del /s /q /f %temp%\*
  rd /s /q %temp% 
  md %temp%
  echo Temporary files cleared.
) else if /i "%clearTempFiles%"=="n" (
  echo Not clearing temporary files.
) else (
  echo Invalid input. Please enter y or n.
  goto cleartempfiles
)

:defraghdd
set /p defragHDD=Defragment hard disk? (y/n)
if /i "%defragHDD%"=="y" (
  defrag C: /U /V
  echo Hard disk defragmented.
) else if /i "%defragHDD%"=="n" (
  echo Not defragmenting hard disk.
) else (
  echo Invalid input. Please enter y or n.
  goto defraghdd
)

:disablegamemode
set /p disableGameMode=Disable Game Mode? (y/n)
if /i "%disableGameMode%"=="y" (
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
  echo Game Mode disabled.
) else if /i "%disableGameMode%"=="n" (
  echo Not disabling Game Mode.
) else (
  echo Invalid input. Please enter y or n.
  goto disablegamemode
)

:disablegamebar
set /p disableGameBar=Disable Game Bar? (y/n)
if /i "%disableGameBar%"=="y" (
  PowerShell -Command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
  reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d 0 /f
  echo Game Bar disabled.
) else if /i "%disableGameBar%"=="n" (
  echo Not disabling Game Bar.
) else (
  echo Invalid input. Please enter y or n.
  goto disablegamebar
)

:disableindexing
set /p disableIndexing=Disable indexing on all drives? (y/n)
if /i "%disableIndexing%"=="y" (
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f
  echo Indexing disabled on all drives.
) else if /i "%disableIndexing%"=="n" (
  echo Not disabling indexing.
) else (
  echo Invalid input. Please enter y or n.
  goto disableindexing
) 

:disablehibernation
set /p disableHibernation=Disable hibernation? (y/n)
if /i "%disableHibernation%"=="y" (
  powercfg -h off
  echo Hibernation disabled.
) else if /i "%disableHibernation%"=="n" (
  echo Not disabling hibernation.
) else (
  echo Invalid input. Please enter y or n.  
  goto disablehibernation
)

:disabletelemetry
set /p disableTelemetry=Disable telemetry and data collection? (y/n)  
if /i "%disableTelemetry%"=="y" (
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
  reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d 1 /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f 
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
  echo Telemetry and data collection disabled.
) else if /i "%disableTelemetry%"=="n" (
  echo Not disabling telemetry.
) else (
  echo Invalid input. Please enter y or n.
  goto disabletelemetry
)

:disabletips
set /p disableTips=Disable Windows tips/suggestions? (y/n)
if /i "%disableTips%"=="y" (
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f 
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
  echo Windows tips/suggestions disabled.
) else if /i "%disableTips%"=="n" (
  echo Not disabling Windows tips/suggestions.
) else (
  echo Invalid input. Please enter y or n.
  goto disabletips
) 

:disablehomegroup
set /p disableHomeGroup=Disable HomeGroup? (y/n)
if /i "%disableHomeGroup%"=="y" (
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableHomeGroup" /t REG_DWORD /d 0 /f
  echo HomeGroup disabled. 
) else if /i "%disableHomeGroup%"=="n" (
  echo Not disabling HomeGroup.
) else (
  echo Invalid input. Please enter y or n.
  goto disablehomegroup
)

:disablestickykeys
set /p disableStickyKeys=Disable sticky keys prompt? (y/n)
if /i "%disableStickyKeys%"=="y" (
  reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
  echo Sticky keys prompt disabled.
) else if /i "%disableStickyKeys%"=="n" (
  echo Not disabling sticky keys prompt.
) else (
  echo Invalid input. Please enter y or n.
  goto disablestickykeys
)

:disablesuperfetch
set /p disableSuperfetch=Disable Superfetch? (y/n)
if /i "%disableSuperfetch%"=="y" (
  sc config SysMain start=disabled
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
  echo Superfetch disabled.
) else if /i "%disableSuperfetch%"=="n" (
  echo Not disabling Superfetch.
) else (
  echo Invalid input. Please enter y or n.
  goto disablesuperfetch
)

:spooler
set /p disablespooler=Disable Spooler (y/n)
if /i "%disablespooler%"=="y" (
 PowerShell -Command net stop spooler
echo Spooler disabled.
) else if /i "%disablespooler%"=="n" (
echo Not disabling spooler
) else (
  echo Invalid input. Please enter y or n.
  goto spooler
)

:WindowsInsiderService 
set /p disableWindowsInsiderService= Disable Windows Insider Service (y/n)
if /i "%disableWindowsInsiderService%"=="y" (
PowerShell -Command Set-Service wisvc -StartupType Disabled
echo disabled Windows Insider Service.
) else if /i "%disableWindowsInsiderService%"=="n" (
echo Not disable Windows Insider Service
) else (
echo Invalid input. Please enter y or n. 
goto WindowsInsiderService
)

:DiagnosticServiceHost
set /p disableDiagnosticServiceHost= Disable Diagnostic Service Host (y/n)
if /i "%disableDiagnosticServiceHost%"=="y" (
PowerShell -Command "net stop DPS"
echo disabled Diagnostic Service Host.
) else if /i "%disableDiagnosticServiceHost%"=="n" (
echo Not disable Diagnostic Service Host
) else ( 
echo Invalid input. Please enter y or n.
goto DiagnosticServiceHost
)


echo Optimization complete! Thank You
pause
