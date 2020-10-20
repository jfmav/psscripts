
# *********************************************************************************
# * Reg Key`s 4 Current Users                                                     *
# *********************************************************************************
#Outlook SharedMailbox SendItems Store in SharedMailbox not in UserMailbox
New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences" -Name "DelegateSentItemsStyle" -Value "1" -PropertyType DWORD | Out-Null 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\Preferences" -Name "DelegateSentItemsStyle" -Value "1" | Out-Null 
#Seperate prozess for Folder-Explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "SeparateProcess" -PropertyType DWORD -Value "1" | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "SeparateProcess" -Value "1" | Out-Null 
#show full path in addressbar from Explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name "FullPath" -PropertyType DWORD -Value "1" | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name "FullPath" -Value "1" | Out-Null 
#show all file endings in Explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "HideFileEx" -PropertyType DWORD -Value "1" | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name "HideFileEx" -Value "1" | Out-Null 
#Do not notify while presentation

New-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name "NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING" -PropertyType DWORD -Value "1" | Out-Null 
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name "NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING" -Value "1" | Out-Null 
#Taskbar groups but only if Taskbar is full
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Value "1" -PropertyType DWORD -Force | Out-Null
#Teams delete Autostart
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "com.squirrel.Teams.Teams" | Out-Null
#Skype delete Autostart
Remove-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name "Lync" | Out-Null

#Auto config Outlook-Profiles
#Check Regkey Autodiscover If not exists create it
If (!(Test-Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover")) {
    New-Item -Path "HKCU:\Software\Microsoft\Office\16.0" -Name "Outlook" | Out-Null
    New-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook" -Name "AutoDiscover" | Out-Null
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" -Name "ZeroConfigExchange" -PropertyType DWORD -Value "1" -Force | Out-Null
}

#office WORD Show Personal Startpage @ programm-start
New-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\word\options" -Name "officestartdefaulttab" -PropertyType DWORD -Value "1" | Out-Null
Set-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\word\options" -Name "FullPath" -Value "1" | Out-Null 
#office Powerpoint Show Personal Startpage @ programm-start
New-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\powerpoint\options" -Name "officestartdefaulttab" -PropertyType DWORD -Value "1" | Out-Null
Set-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\powerpoint\options" -Name "FullPath" -Value "1" | Out-Null 
#office Excel Show Personal Startpage @ programm-start
New-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\excel\options" -Name "officestartdefaulttab" -PropertyType DWORD -Value "1" | Out-Null
Set-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\excel\options" -Name "FullPath" -Value "1" | Out-Null 
#firstrun popup office to choice "Office Open XML formats"
Set-ItemProperty -Path "HKCU:Software\Microsoft\Office\16.0\Common\General" -Name "ShownFileFmtPrompt" -Value "1" | Out-Null 

#start windows explorer in separate processes
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -PropertyType DWORD -Value '1' | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'SeparateProcess' -Value '1' | Out-Null 
#show always fullpath in Windows explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name 'FullPath' -PropertyType DWORD -Value '1' | Out-Null
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState' -Name 'FullPath' -Value '1' | Out-Null 
#disable copy warings mergeconflicts
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideMergeConflicts' -PropertyType DWORD -Value '0' | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideMergeConflicts' -Value '0' | Out-Null 
#show hide drives in windows explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -PropertyType DWORD -Value '0' | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -Value '0' | Out-Null 
#show all filetypes in windows explorer
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileEx' -PropertyType DWORD -Value '1' | Out-Null 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileEx' -Value '1' | Out-Null 
        


# *********************************************************************************
# * Additional OS Config                                                          *
# * disable Services &                                                            *
# * Delete not nessasary sheduled tasks &                                         *
# * =Privacy Settings                                                             *
# *********************************************************************************
#disable Services

#disable Xbox Accessory Management
Set-Service XboxGipSvc -StartupType Disabled
#disable Xbox Game Monitoring after 1809 not found
#Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\xbgm' -Name 'Start' -Value "4"
#disable Xbox Live Networking Service 
Set-Service XboxNetApiSvc -StartupType Disabled
#disable Xbox Live game-save
Set-Service XblGameSave -StartupType Disabled
#disable XBOXXbox Live Auth Manager
Set-Service XblAuthManager -StartupType Disabled
#disable MS ErrorReporting
Set-Service WerSvc -StartupType Disabled
#disable iSCSI Initiator services
Set-Service MSiSCSI -StartupType Disabled
#disable Fax functions
Set-Service Fax -StartupType Disabled
#disable BranchCache
Set-Service PeerDistSvc -StartupType Disabled
#disable diagnosis and tracking service
Set-Service Diagtrack -StartupType Disabled
#disable program compatibility assistant service
Set-Service PcaSvc -StartupType Disabled
#disable RetailDemo
Set-Service RetailDemo -StartupType Disabled
#disable Diagnose and Push Services
Set-Service Diagtrack -StartupType Disabled
Set-Service DmwApPushService -StartupType Disabled
#disable Onedrive Sync
#Set-Service OneSyncSvc -StartupType Disabled

#wait
Start-Sleep -Seconds 2
Write-Host ""
Write-Host ""

#Disable:Scheduled Tasks
#.
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\WinSAT" | Out-Null
#Xbox
Disable-ScheduledTask -TaskName "Microsoft\XblGameSave\XblGameSaveTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitor" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" | Out-Null
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\UPnP\UPnPHostConfig" | Out-Null
#Windows-Media-Player
#Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" | Out-Null
#auto-diagnosis
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Diagnosis\Scheduled" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" | Out-Null
#privacy
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Feedback\Siuf\DmClient" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Location\Notifications" | Out-Null
#cloud
#disable to join a cloud domain
Disable-ScheduledTask -TaskName "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" | Out-Null

#wait
Start-Sleep -Seconds 2
Write-Host ""
Write-host ""

#Config:Regkeys

#privacy
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "AITEnable" /D 0 /F			
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "DisableInventory" /D 1 /F
#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableWindowsConsumerFeatures" /D 1 /F
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "DoNotShowFeedbackNotifications" /D 1 /F
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T REG_DWORD /V "Enabled" /D 0 /F
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /V "PreventDeviceMetadataFromNetwork" /T REG_DWORD /D 1 /F
#cloud
#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableSoftLanding" /D 1 /F
#OS	
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /T REG_DWORD /V "EnableConfigFlighting" /D 0 /F
#Edge function activate do not track	
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /T REG_DWORD /V "DoNotTrack" /D 1 /F
#IE disable first-start Wizard
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' | Out-Null
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' | Out-Null
#Cortana disable cortana on LoginScreen	
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /T REG_DWORD /V "AllowCortanaAboveLock" /D 0 /F
#AppStore aktivate auto Update only Download
#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "AutoDownload" /D 2 /F
#disable program compatibility assistant
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisablePCA' -PropertyType DWORD -Value '1' | Out-Null
#disable FirstlogonAnimation
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -PropertyType DWORD -Value '0' | Out-Null
#disable quickaccess in File-Explorer
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'HubMode' -PropertyType DWORD -Value '1' | Out-Null
#disable oneDrive sync		
#Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSyncNGSC" /D 1 /F
#Reg Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /T REG_DWORD /V "DisableFileSync" /D 1 /F

# *********************************************************************************
# * Delete OneDrive full                                                          *
# *********************************************************************************

#Remove OneDrive (not guaranteed to be permanent - see https://support.office.com/en-US/article/Turn-off-or-uninstall-OneDrive-f32a17ce-3336-40fe-9c38-6efb09f944b0):
#New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Skydrive' | Out-Null
#New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableFileSync' -PropertyType DWORD -Value '1' | Out-Null
#New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableLibrariesDefaultSaveToSkyDrive' -PropertyType DWORD -Value '1' | Out-Null 

# *********************************************************************************
# * SystemControl RightClick                                                      *
# *********************************************************************************
#ADD Systemcontrol to rightClick on Desktop

New-Item -Path 'HKCR:\DesktopBackground\Shell' -Name 'Systemsteuerung' 
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name '(default)' -Value '@shell32.dll,-4161'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'icon' -Value 'control.exe'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'Position' -Value 'Bottom'
New-Item -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'command'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung\command' -Name '(default)' -Value 'control.exe'

# *********************************************************************************
# * Delete AdminShares                                                            *
# *********************************************************************************
Get-WmiObject Win32_Share -Property * | select name,type | Where-Object { $_.Type -like "*48" } | ForEach-Object {$_.Delete()}


# *********************************************************************************
# * Delete online apps                                                            *
# *********************************************************************************
#remove online apps
#Neue Version da alte Fehler wirft:
write-host "Entferne Online Applikationen ohne WindowsStore,WindowsCalculator,WindowsPhotos,MicrosoftStickyNotes" -ForegroundColor Gray
$onlineapps=Get-AppxProvisionedPackage -Online | where {$_.PackageName -NotLike "*Microsoft.WindowsStore*" -AND $_.PackageName -NotLike "*Microsoft.WindowsCalculator*" -AND $_.PackageName -NotLike "*Microsoft.*StickyNotes*" -AND $_.PackageName -NotLike "*Microsoft.RemoteDesktop*" -AND $_.PackageName -NotLike "*Microsoft.MSPaint*" -AND $_.PackageName -NotLike "*Microsoft.Windows.Photos*"}

#wait
$onlineapps | Out-Null
foreach ($Apps in $onlineapps) {
Write-host "Entferne Applikation: "$Apps.PackageName -ForegroundColor Gray
Remove-AppxProvisionedPackage -Online -Packagename $Apps.Packagename -erroraction silentlycontinue
Get-AppxPackage -AllUsers "$Apps.PackageName" | where {} | Remove-AppxPackage -AllUsers -erroraction silentlycontinue
Start-Sleep -Seconds 2
}

#wait
Start-Sleep -Seconds 120
Write-Host ""
Write-host ""

#config:AppXPackages 
#second start because not all will be disabled
$onlineapps=Get-AppxProvisionedPackage -Online | where {$_.PackageName -NotLike "*Microsoft.WindowsStore*" -AND $_.PackageName -NotLike "*Microsoft.WindowsCalculator*" -AND $_.PackageName -NotLike "*Microsoft.*StickyNotes*" -AND $_.PackageName -NotLike "*Microsoft.RemoteDesktop*" -AND $_.PackageName -NotLike "*Microsoft.MSPaint*" -AND $_.PackageName -NotLike "*Microsoft.Windows.Photos*"}

#wait
$onlineapps | Out-Null
foreach ($Apps in $onlineapps) {
Write-host "Entferne Applikation: "$Apps.PackageName -ForegroundColor Gray
Remove-AppxProvisionedPackage -Online -Packagename $Apps.Packagename -erroraction silentlycontinue
Get-AppxPackage -AllUsers "$Apps.PackageName" | where {} | Remove-AppxPackage -AllUsers -erroraction silentlycontinue
Start-Sleep -Seconds 2
}
# *********************************************************************************
# * Update Users SysParam                                                         *
# *********************************************************************************
start-process PowerShell.exe -windowstyle hidden {rundll32 user32.dll,UpdatePerUserSystemParameters} -PassThru
