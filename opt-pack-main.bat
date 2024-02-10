
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
    reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d 0 /f
    reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "Value" /t REG_DWORD /d 0 /f
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
 reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v PowerThrottlingOff /t REG_DWORD /d 00000001 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 00000000 /f
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

    schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
    schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Application Experience\MareBackup" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /DISABLE
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /DISABLE
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 4294967295 /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 30 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d 4 /f
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

:BITS
set /p disableBITS= Disable BITS (y/n)
if /i "%disableBITS%"=="y" (
    net stop wuauserv
    net stop cryptSvc
    net stop bits
    net stop msiserver
    echo disabled BITS.
) else if /i "%disableBITS%"=="n" (
    echo Not disable BITS
) else (
    echo Invalid input. Please enter y or n.
    goto BITS


echo Optimization complete! Thank You
pause 