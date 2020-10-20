<#
.SYNOPSIS
    PIT -->   PIT - PostInstallationTask
    Configure Windows 10 with Basic Steps
    Scriptlog in local Eventlog
.DESCRIPTION
    Task01:Create a own local ScriptFolder, this will be use to download tmp Files and store future own Applikations
    Task02:Create a own Eventlog for PIT`s
    Task03:Change Default-ALogin-Background(=lockscreen)
    Task04:Change Default Background
    Task05:activate more privacy and prevent to collect data and send it to MS
    Task06:Disable Xbox and Windows-Media-Player-Sharing BulidIn-Tasks
    Task07:Disable Auto-Diagnostic
    Task08:Disable Cortana on LockScreen
    Task09:Disable First-Logon-Annimation
    Task10:Disable program compatibility assistant
    Task11:AppStore aktivate auto Update only Download
    Task12:Configure IE&Edge; IE disable first-start Wizard; enable Edge function "do not track"	
    Task13:ADD Systemcontrol to rightClick on Desktop
    Task14:Set NTP-Settings to nearest RODC; auto Search nearest RODC
    Task15:Import own Startmenu XML
    Task16:Deaktivate Admin Share;Exclusion IPC$ and print$
.NOTES
    Name:        pit_configureOS.ps1
    Author:      JFmav
    Created:     2020-02-01
    Version:     0.1
#>
# *********************************************************************************
# * Dependensies                                                                  *
# *********************************************************************************
#future scriptpath & Download tmp folder
$tmpscript_path="C:"
$tmpscript_name="Private-HomeFolder"
New-Item -ItemType Directory -Force -Path ($tmpscript_path+"\"+$tmpscript_name)
#Map Regpaths
New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
#Admingroup definition de=Administratoren en=Administrators
$dcadmingroup="Administratoren"
#OWN Background Login Picturepath
$ownloginbackground_path=".\pics"
$ownloginbackground_name="background_LOGIN.png"
#Windows Default Background Login Picturepath
$defaultloginbackground_path = "C:\Windows\Web\Screen"
$defaultloginbackground_chache="C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly\LockScreen_Z\"
#OWN Wallpaper Picturepath
$ownbackground_path=".\pics"
$ownbackground_name="background.png"
#Windows Default Wallpaper Picturepath
$defaultbackground_path = "$env:windir\web\wallpaper\Windows"
$defaultbackground_name = "img0.jpg"
$defaultbackground_parentdir = "$env:WINDIR\web\wallpaper\"
#OWN Startmenu XML Path
$ownstartmenu_path=".\xml"
$ownstartmenu_name="StartLayout.xml"

# *********************************************************************************
# * functions                                                                     *
# *********************************************************************************
function playwithacl {
param($path,$name,$admingroup)
#$admingroup: DE-Administratoren EN-Administrators
$acl= Get-Acl ($path+"\"+$name)
$acl.SetOwner([System.Security.Principal.NTAccount] "$env:USERNAME")
#save new Owner 2 times
Set-Acl ($path+"\"+$name) $acl
Set-Acl ($path+"\"+$name) $acl
#now set Group ACL FullControll 4 Admins and System
$acl_filerights = [System.Security.AccessControl.FileSystemRights]"FullControl"
$acl_filerights_type =[System.Security.AccessControl.AccessControlType]::Allow 
$objUser_System = New-Object System.Security.Principal.NTAccount("SYSTEM") 
$objUser_Admin = New-Object System.Security.Principal.NTAccount($admingroup)
$acl_filerights_system = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser_System, $acl_filerights, $acl_filerights_type) 
$acl_filerights_admin = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser_admin, $acl_filerights, $acl_filerights_type)
$acl.AddAccessRule($acl_filerights_system) 
$acl.AddAccessRule($acl_filerights_admin)
#save new Owner 2 times
Set-Acl ($path+"\"+$name) $acl
Set-Acl ($path+"\"+$name) $acl
}

function eventlog {
param($status, $message, $EventlogName, $EventlogSource)
if ($status -eq "INFO") {Write-EventLog -LogName $EventlogName -Source $EventlogSource -Message "$($message | Out-String)" -EventId 0 -EntryType Information}
if ($status -eq "ERROR") {Write-EventLog -LogName $EventlogName -Source $EventlogSource -Message "$($message | Out-String)" -EventId 666 -EntryType Error}
}
# *********************************************************************************
# * Eventlog                                                                      *
# *********************************************************************************
#create eventlog
$NameEventlog = "Post-Install"
$NameEventSource = "PIT"
New-Eventlog -LogName $NameEventlog -Source $NameEventSource
#clear Errorcache
$error.Clear()
# *********************************************************************************
# * Querys                                                                        *
# *********************************************************************************
#get nearest RODC in NW
#get-wmiobject Win32_NTDomain --> very slow
#get rodc information over "nltest" Domain testing tool builedin 
eventlog -status "INFO" -message "Start-Windows10 Query RODC" -EventlogName $NameEventlog -EventlogSource $NameEventSource
$dclist = nltest /dclist:DomainName
$getcurrentsite=nltest /dsgetsite
$searchsiteindclist=$dclist -like ("*"+$getcurrentsite[0]+"*")
[string]$RODC_Name=$searchsiteindclist.trim().substring(0,25)
eventlog -status "INFO" -message ("Windows10 Query RODC "+$RODC_Name) -EventlogName $NameEventlog -EventlogSource $NameEventSource

# *********************************************************************************
# * Design Changes LoginBackground                                                *
# *********************************************************************************
eventlog -status "INFO" -message "Start-Windows10 OSDesign-Config LoginBackground" -EventlogName $NameEventlog -EventlogSource $NameEventSource

#Delete default loginBackgrounds
eventlog -status "INFO" -Message ("Windows10 OSDesign Get ACL and delete Files in"+$defaultloginbackground_path) -EventlogName $NameEventlog -EventlogSource $NameEventSource
If (Test-Path $ownloginbackground_path) {
    eventlog -status "INFO" -message "Windows10 OSDesign NW-Folder EQUAL TRUE" -EventlogName $NameEventlog -EventlogSource $NameEventSource
    foreach ($fileitem in Get-ChildItem $defaultloginbackground_path ){
        playwithacl -path ($defaultloginbackground_path) -name ($fileitem) -admingroup $dcadmingroup
        eventlog -status "INFO" -message "Windows10 OSDesign delete file $fileitem" -EventlogName $NameEventlog -EventlogSource $NameEventSource
        try {Remove-Item -Path ($defaultloginbackground_path+"\"+$fileitem)}
        catch {eventlog -status "ERROR" -message ("FAIL: Delete file"+$fileitem) -EventlogName $NameEventlog -EventlogSource $NameEventSource}
    }
#Delete lockscreen Chache 
#get temp access to Windows Chache Folders - after Restart ACls are recovered by windows it self
    eventlog -status "INFO" -message ("Windows10 OSDesign Get ACL and delete Files in "+$defaultloginbackground_chache+"*") -EventlogName $NameEventlog -EventlogSource $NameEventSource
    playwithacl -path "C:\ProgramData\Microsoft\Windows" -name "SystemData" -admingroup $dcadmingroup
    playwithacl -path "C:\ProgramData\Microsoft\Windows\SystemData" -name "S-1-5-18" -admingroup $dcadmingroup
    playwithacl -path "C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18" -name "ReadOnly" -admingroup $dcadmingroup
    playwithacl -path "C:\ProgramData\Microsoft\Windows\SystemData\S-1-5-18\ReadOnly" -name "LockScreen_Z" -admingroup $dcadmingroup
    foreach ($fileitem in Get-ChildItem $defaultloginbackground_chache) {
        eventlog -status "INFO" -message ("Windows10 OSDesign delete file "+$fileitem) -EventlogName $NameEventlog -EventlogSource $NameEventSource
        try {Remove-Item -Path ($defaultloginbackground_chache+$fileitem)}
        catch {eventlog -status "ERROR" -message ("FAIL: Delete file"+$fileitem) -EventlogName $NameEventlog -EventlogSource $NameEventSource }
    }
#copy new Login Window
    eventlog -status "INFO" -message ("Copy-Windows10 OSDesign Copy New LoginBackground and Rename it in img100.jpg") -EventlogName $NameEventlog -EventlogSource $NameEventSource
    try {Copy-Item -Path ($ownloginbackground_path+"\"+$ownloginbackground_name) -Destination ($defaultloginbackground_path+"\img100.jpg") -Force}
    Catch {eventlog -status "ERROR" -message "Fail: Copy-Windows10 OSDesign Own LoginBackground" -EventlogName $NameEventlog -EventlogSource $NameEventSource}
} else {eventlog -status "ERROR" -message "FAIL:Windows10 OSDesign NW-Folder EQUAL False" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

# *********************************************************************************
# * Design Changes Wallpaper                                                      *
# *********************************************************************************
eventlog -status "INFO" -message "Start-Windows10 OSDesign-Config DefaultBackground" -EventlogName $NameEventlog -EventlogSource $NameEventSource

playwithacl -path ($defaultbackground_path) -name ($defaultbackground_name) -admingroup $dcadmingroup

#rename and copy new background Image
eventlog -status "INFO" -message "Windows10 OSDesign Rename Default img0.jpg to old_img0.jpg" -EventlogName $NameEventlog -EventlogSource $NameEventSource
try {Rename-Item -Path ($defaultbackground_path+"\"+$defaultbackground_name) -NewName old_img0.jpg}
catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSDesign Rename Default img0.jpg to old_img0.jpg" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

eventlog -status "INFO" -message "Windows10 OSDesign Copy Own Background" -EventlogName $NameEventlog -EventlogSource $NameEventSource
If (Test-Path $ownloginbackground_path) {
    eventlog -status "INFO" -message "Windows10 OSDesign Copy NW-Folder EQUAL TRUE" -EventlogName $NameEventlog -EventlogSource $NameEventSource
    try {Copy-Item -Path ($ownloginbackground_path+"\"+$ownloginbackground_name) -Destination ($defaultbackground_path+"\img0.jpg") -Force}
    Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSDesign Copy own Background " -EventlogName $NameEventlog -EventlogSource $NameEventSource}
} else {eventlog -status "ERROR" -message "FAIL:Windows10 OSDesign Copy NW-Folder EQUAL False" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

# *********************************************************************************
# * Additional OS Config                                                          *
# * disable Services &                                                            *
# * Delete not nessasary sheduled tasks &                                         *
# * =Privacy Settings                                                             *
# *********************************************************************************
eventlog -status "INFO" -message "Start-Windows10 OSConfig Additional" -EventlogName $NameEventlog -EventlogSource $NameEventSource
#disable Services
eventlog -status "INFO" -message "Windows10 OSConfig Disable Services" -EventlogName $NameEventlog -EventlogSource $NameEventSource
#disable diagnosis and tracking service
Set-Service Diagtrack -StartupType Disabled
#disable program compatibility assistant service
Set-Service PcaSvc -StartupType Disabled

#Disable:Scheduled Tasks
eventlog -status "INFO" -message "Windows10 OSConfig Disable ScheduledTasks" -EventlogName $NameEventlog -EventlogSource $NameEventSource
#.
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\WinSAT" | Out-Null
#Xbox
Disable-ScheduledTask -TaskName "Microsoft\XblGameSave\XblGameSaveTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitor" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" | Out-Null
Disable-ScheduledTask -TaskName "\Microsoft\Windows\UPnP\UPnPHostConfig" | Out-Null
#Windows-Media-Player
Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary" | Out-Null
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

#Config:Regkeys
eventlog -status "INFO" -message "Windows10 OSConfig Config Regkeys" -EventlogName $NameEventlog -EventlogSource $NameEventSource
#privacy
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "AITEnable" /D 0 /F			
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /T REG_DWORD /V "DisableInventory" /D 1 /F
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableWindowsConsumerFeatures" /D 1 /F
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "DoNotShowFeedbackNotifications" /D 1 /F
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /T REG_DWORD /V "Enabled" /D 0 /F
Reg Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /V "PreventDeviceMetadataFromNetwork" /T REG_DWORD /D 1 /F
#cloud
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /T REG_DWORD /V "DisableSoftLanding" /D 1 /F
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
Reg Add	"HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /T REG_DWORD /V "AutoDownload" /D 2 /F
#disable program compatibility assistant
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisablePCA' -PropertyType DWORD -Value '1' | Out-Null
#disable FirstlogonAnimation
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableFirstLogonAnimation' -PropertyType DWORD -Value '0' | Out-Null
#disable quickaccess in File-Explorer
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'HubMode' -PropertyType DWORD -Value '1' | Out-Null


# *********************************************************************************
# * SystemControl RightClick                                                      *
# *********************************************************************************
#ADD Systemcontrol to rightClick on Desktop
eventlog -status "INFO" -message "Start-Windows10 OSConfig Add SystemControl RightClick" -EventlogName $NameEventlog -EventlogSource $NameEventSource
New-Item -Path 'HKCR:\DesktopBackground\Shell' -Name 'Systemsteuerung' 
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name '(default)' -Value '@shell32.dll,-4161'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'icon' -Value 'control.exe'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'Position' -Value 'Bottom'
New-Item -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung' -Name 'command'
New-ItemProperty -Path 'HKCR:\DesktopBackground\Shell\Systemsteuerung\command' -Name '(default)' -Value 'control.exe'

# *********************************************************************************
# * NTP Config to RODC                                                            *
# *********************************************************************************
eventlog -status "INFO" -message "Start-Windows10 OSConfig Set NTP-Settings to nearest RODC" -EventlogName $NameEventlog -EventlogSource $NameEventSource
#stop timeservice
try {Stop-Service w32time}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Stop-Service w32time" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

#set NTP-config in Reg
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name "1" -Value $RODC_Name
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP"

#start timeservice
try {start-Service w32time}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Start-Service w32time" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

#config NTP Server in timeservice
try {w32tm /config /manualpeerlist:$RODC_Name /syncfromflags:manual /reliable:yes /update}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Set-Service w32time Configuration" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

#wait
start-sleep -Seconds 5

#time-sync first time
try {w32tm /resync}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Time-Sync try" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

#set timezone to vienna
try {Get-TimeZone -ListAvailable | where {$_.DisplayName -like "*Wien*"} | Set-TimeZone}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig set timezone to vienna" -EventlogName $NameEventlog -EventlogSource $NameEventSource}


# *********************************************************************************
# * StartMenu                                                                     *
# *********************************************************************************
#importXML
eventlog -status "INFO" -message "Start-Windows10 OSConfig Add Own StartMenu" -EventlogName $NameEventlog -EventlogSource $NameEventSource
try {
Copy-Item -Path ($ownstartmenu_path+"\"+$ownstartmenu_name) -Destination ($tmpscript_path+"\"+$tmpscript_name+"\"+$ownstartmenu_name) -Force
Import-StartLayout –LayoutPath ($tmpscript_path+"\"+$tmpscript_name+"\"+$ownstartmenu_name) –MountPath C:\ -ErrorAction Stop
Remove-Item -Path ($tmpscript_path+"\"+$tmpscript_name+"\"+$ownstartmenu_name)
}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Add Own StartMenu" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

# *********************************************************************************
# * Delete AdminShares                                                            *
# *********************************************************************************
eventlog -status "INFO" -message "Start-Windows10 OSConfig Delete AdminShares" -EventlogName $NameEventlog -EventlogSource $NameEventSource
try {
Get-WmiObject Win32_Share -Property * | select name,type | Where-Object { $_.Type -like "*48" } | ForEach-Object {$_.Delete()}
}
Catch {eventlog -status "ERROR" -message "FAIL:Windows10 OSConfig Delete AdminShares" -EventlogName $NameEventlog -EventlogSource $NameEventSource}

# *********************************************************************************
# * GET-STATUS-LOG                                                                *
# *********************************************************************************
Write-Host "LOG:"
Get-EventLog -Source $NameEventSource -LogName $NameEventlog | Format-table
