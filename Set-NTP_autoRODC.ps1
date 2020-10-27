<#
.Synopsis
NTP auto Configuration nearest RODC

.DESCRIPTION
get list RODC from DomainName
get currentsite
search Site in RODC list
Stop timeservice
Set RegKey Datetime Server
start timeservice
wait and resync time
set time to german vienna

.NOTES   
Name       : Set-NTP_autoRODC.ps1
Author     : JFmav
Version    : 0.1
DateCreated: 27-10-2020
#>
# *********************************************************************************
# * Querys                                                                        *
# *********************************************************************************
#get nearest RODC in NW
#get-wmiobject Win32_NTDomain --> very slow
#get rodc information over "nltest" Domain testing tool builedin 
$dclist = nltest /dclist:mapeigroup
$getcurrentsite=nltest /dsgetsite
$searchsiteindclist=$dclist -like ("*"+$getcurrentsite[0]+"*")
[string]$RODC_Name=$searchsiteindclist.trim().substring(0,25)

#stop timeservice
Stop-Service w32time


#set NTP-config in Reg
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DateTime\Servers" -Name "1" -Value $RODC_Name
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Value "NTP"

#start timeservice
start-Service w32time


#config NTP Server in timeservice
w32tm /config /manualpeerlist:$RODC_Name /syncfromflags:manual /reliable:yes /update

#wait
start-sleep -Seconds 5

#time-sync first time
w32tm /resync 

#set timezone to vienna
Get-TimeZone -ListAvailable | where {$_.DisplayName -like "*Wien*"} | Set-TimeZone


