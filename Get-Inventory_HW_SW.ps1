<#
.Synopsis
Inventary Software and Hardware

.DESCRIPTION
This generates a list by querying the registry and returning the installed programs of a local computer.
This generates a list by WMI-Query and returning the computer nessesary properties.

.NOTES   
Name       : Get-localInventory
Author     : JFmav
Version    : 0.3
DateCreated: 2019-11-01
DateUpdated: 2019-11-13

#>
# *********************************************************************************
# * Depenencies                                                                   *
# *********************************************************************************
$ComputerName=$env:COMPUTERNAME
$csv_path="C:\ATMAPEIAUSTRIA_ITDATA\Inventur\"
$csv_path_HW=$csv_path + $ComputerName + "_" + "HW_Inventory_WmiData.csv"
$csv_path_SW=$csv_path + $ComputerName + "_" + "SW_Inventory_RegData.csv"
if (!(Test-Path -Path $csv_path)) { New-Item -ItemType directory -Path $csv_path }

# *********************************************************************************
# * Funktion - Generate HW Inventory                                              *
# *********************************************************************************
function get-HwInventoryLocalpc() {
$inventar = New-Object System.Object
$inventar | Add-Member -MemberType NoteProperty -Name "PC-Name" -Value "$ComputerName" -Force

#OS-info
$os = Get-WmiObject -Class Win32_OperatingSystem | select Manufacturer,BuildNumber,Version,OSArchitecture,MUILanguages,Description,CSName,LocalDateTime,LastBootUpTime
$os_manufacturrer=$os.Manufacturer
$os_version=$os.version
$os_build=$os.BuildNumber
$os_architcture=$os.OSArchitecture
$os_language=$os.MUILanguages
$os_lastbootuptime=$os.LastBootUpTime
$os_localdate=$os.LocalDateTime
$os_description=$os.Description
$os_Computername=$os.CSName
$os_domain=(Get-WmiObject -Class Win32_ComputerSystem).Domain

$inventar | Add-Member -MemberType NoteProperty -Name "os-name" -Value "$os_Computername" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-domain" -Value "$os_domain" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-description" -Value "$os_description" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-manufacturer" -Value "$os_manufacturrer" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-build" -Value "$os_build" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-architecture" -Value "$os_architcture" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-language" -Value "$os_language" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-lastbootuptime" -Value "$os_lastbootuptime" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "os-localdate" -Value "$os_localdate" -Force

#hw-info
$hw = Get-WmiObject -Class Win32_ComputerSystem | select Manufacturer,Model,NumberOfProcessors,@{Expression={$_.TotalPhysicalMemory / 1GB};Label="TotalPhysicalMemoryGB"}
$hw_model_wmi=Get-WmiObject Win32_ComputerSystemProduct | Select Vendor, Version
$hw_manufacturer = $hw.Manufacturer
$hw_model = $hw_model_wmi.Version
$hw_numberOfProcessors = $hw.NumberOfProcessors
$hw_ram = $hw.TotalPhysicalMemoryGB

$inventar | Add-Member -MemberType NoteProperty -Name "hw-manufacturer" -Value "$hw_manufacturer" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-model" -Value "$hw_model" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-numberOfProcessors" -Value "$hw_numberOfProcessors" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-ram" -Value "$hw_ram" -Force

$hw_cpu = Get-WmiObject win32_processor | select DeviceID,Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors
$hw_cpu_id = $hw_cpu.DeviceID
$hw_cpu_manufacturer = $hw_cpu.Manufacturer
$hw_cpu_name = $hw_cpu.Name
$hw_cpu_numberofcores = $hw_cpu.NumberOfCores
$hw_cpu_numberOflogicalprocessors = $hw_cpu.NumberOfLogicalProcessors

$inventar | Add-Member -MemberType NoteProperty -Name "hw-cpu-id" -Value "$hw_cpu_id" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-cpu-manufracturer" -Value "$hw_cpu_manufacturer" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-cpu-name" -Value "$hw_cpu_name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-cpu-numberofcores" -Value "$hw_cpu_numberofcores" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-cpu-numberOflogicalprocessor" -Value "$hw_cpu_numberOflogicalprocessors" -Force

$hw_hd = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | select DeviceID,FileSystem,VolumeName,@{Expression={$_.Size / 1GB};Label="SizeGB"},@{Expression={$_.FreeSpace / 1GB};Label="FeeSizeGB"}
$hw_hd_id = $hw_hd.DeviceID
#$hw_hd_name = $hw_hd.VolumeName
$hw_hd_totalsize = $hw_hd.SizeGB
$hw_hd_freessize = $hw_hd.FeeSizeGB

$inventar | Add-Member -MemberType NoteProperty -Name "hw-hd-id" -Value "$hw_hd_id" -Force
#$inventar | Add-Member -MemberType NoteProperty -Name "hw-hd-name" -Value "$hw_hd_name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-hd-totalsize" -Value "$hw_hd_totalsize" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-hd-freessize" -Value "$hw_hd_freessize" -Force

$hw_graph = Get-WmiObject -Class Win32_VideoController | select Name,@{Expression={$_.AdapterRAM / 1GB};Label="GraphicsRAM"}
$hw_graph_name = $hw_graph.Name
$hw_graph_ram = $hw_graph.GraphicsRAM

$inventar | Add-Member -MemberType NoteProperty -Name "hw-graph-name" -Value "$hw_graph_name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-graph-ram" -Value "$hw_graph_ram" -Force

$hw_sound = (Get-WmiObject -Class Win32_SoundDevice).Name

$inventar | Add-Member -MemberType NoteProperty -Name "hw-sound" -Value "$hw_sound" -Force

$hw_nw_wireless_aktiv=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Wireless*")) }) | select DHCPEnabled,ServiceName,Description
$hw_nw_wireless_aktiv_Name=$hw_nw_wireless_aktiv.Description
$hw_nw_wireless_aktiv_dhcp=$hw_nw_wireless_aktiv.DHCPEnabled
$hw_nw_wireless_aktiv_sname=$hw_nw_wireless_aktiv.ServiceName
try{
    $hw_nw_wireless_aktiv_ip4=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Wireless*")) }).IPAddress[0]
    $hw_nw_wireless_aktiv_ip6=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Wireless*")) }).IPAddress[1]
    $hw_nw_wireless_aktiv_mac=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Wireless*")) }).macaddress
} catch { #Write-Error $_
        }

$hw_nw_eth_aktiv=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Ethernet*")) }) | select DHCPEnabled,ServiceName,Description
$hw_nw_eth_aktiv_Name=$hw_nw_eth_aktiv.Description
$hw_nw_eth_aktiv_dhcp=$hw_nw_eth_aktiv.DHCPEnabled
$hw_nw_eth_aktiv_sname=$hw_nw_eth_aktiv.ServiceName
try{
    $hw_nw_eth_aktiv_ip4=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Ethernet*")) }).IPAddress[0]
    $hw_nw_eth_aktiv_ip6=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Ethernet*")) }).IPAddress[1]
    $hw_nw_eth_aktiv_mac=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*Ethernet*")) }).macaddress
} catch { #Write-Error $_
        }

$hw_nw_mobile_aktiv=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*mobile*")) }) | select DHCPEnabled,ServiceName,Description
$hw_nw_mobile_aktiv_Name=$hw_nw_mobile_aktiv.Description
$hw_nw_mobile_aktiv_dhcp=$hw_nw_mobile_aktiv.DHCPEnabled
$hw_nw_mobile_aktiv_sname=$hw_nw_mobile_aktiv.ServiceName
try{
    $hw_nw_mobile_aktiv_ip4=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*mobile*")) }).IPAddress[0]
    $hw_nw_mobile_aktiv_ip6=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*mobile*")) }).IPAddress[1]
    $hw_nw_mobile_aktiv_mac=(get-WmiObject Win32_NetworkAdapterConfiguration | where { (($_.IPEnabled -ne $null) -and ($_.DefaultIPGateway -ne $null) -and ($_.Description -like "*mobile*")) }).macaddress
} catch { #Write-Error $_
        }
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-dhcp" -Value "$hw_nw_eth_aktiv_dhcp" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-sname" -Value "$hw_nw_eth_aktiv_sname" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-Name" -Value "$hw_nw_eth_aktiv_Name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-ip4" -Value "$hw_nw_eth_aktiv_ip4" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-ip6" -Value "$hw_nw_eth_aktiv_ip6" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-eth-aktiv-mac" -Value "$hw_nw_eth_aktiv_mac" -Force

$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-dhcp" -Value "$hw_nw_wireless_aktiv_dhcp" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-sname" -Value "$hw_nw_wireless_aktiv_sname" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-name" -Value "$hw_nw_wireless_aktiv_Name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-ip4" -Value "$hw_nw_wireless_aktiv_ip4" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-ip6" -Value "$hw_nw_wireless_aktiv_ip6" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-wireless-aktiv-mac" -Value "$hw_nw_wireless_aktiv_mac" -Force

$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-dhcp" -Value "$hw_nw_mobile_aktiv_dhcp" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-sname" -Value "$hw_nw_mobile_aktiv_sname" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-Name" -Value "$hw_nw_mobile_aktiv_Name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-ip4" -Value "$hw_nw_mobile_aktiv_ip4" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-ip6" -Value "$hw_nw_mobile_aktiv_ip6" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "hw-nw-mobile-aktiv-mac" -Value "$hw_nw_mobile_aktiv_mac" -Force

#bios-info
$bios = Get-WmiObject Win32_Bios | select SerialNumber,Manufacturer,Name,Version,SMBIOSBIOSVersion
$bios_sn=$bios.SerialNumber
$bios_manufacturer=$bios.Manufacturer
$bios_name=$bios.Name
$bios_version=$bios.Version
$bios_smversion=$bios.SMBIOSBIOSVersion


$inventar | Add-Member -MemberType NoteProperty -Name "bios-sn" -Value "$bios_sn" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "bios-manufacturer" -Value "$bios_manufacturer" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "bios-name" -Value "$bios_name" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "bios-version" -Value "$bios_version" -Force
$inventar | Add-Member -MemberType NoteProperty -Name "bios-smversion" -Value "$bios_smversion" -Force

#hdd-info 
$hdd_list = Get-WmiObject -class win32_diskdrive | select DeviceId,FriendlyName,MediaType,Size,SerialNumber
$hdd_count=0
ForEach ($hdd_device in $hdd_list)
{
    $hdd_count=$hdd_count+1
    [string]$hdd_count_name="hdd-id"+$hdd_count
	$hdd_name = $hdd_device.FriendlyName
    [string]$hdd_name_name="hdd-id"+$hdd_count+"-name"
	$hdd_type = $hdd_device.MediaType
    [string]$hdd_type_name="hdd-id"+$hdd_count+"-type"
	$hdd_sn = $hdd_device.SerialNumber
    [string]$hdd_sn_name="hdd-id"+$hdd_count+"-sn"
    $hdd_winid = $hdd_device.DeviceId
    [string]$hdd_winid_name="hdd-id"+$hdd_count+"-winid"
    $hdd_size = $hdd_device.Size
    [string]$hdd_size_name="hdd-id"+$hdd_count+"-size"

    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_count_name" -Value "$hdd_count" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_winid_name" -Value "$hdd_winid" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_name_name" -Value "$hdd_name" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_type_name" -Value "$hdd_type" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_sn_name" -Value "$hdd_sn" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$hdd_size_name" -Value "$hdd_size" -Force	

}

#monitor-info
$mon_list = Get-WmiObject WmiMonitorID -Namespace root\wmi
$mon_count=0
ForEach ($mon_device in $mon_list)
{
    $mon_count=$mon_count+1
    [string]$mon_count_name="mon-id"+$mon_count
	$mon_manufacturer = ($mon_device.ManufacturerName -notmatch 0 | ForEach{[char]$_}) -join ""
    [string]$mon_manufacturer_name="mon-id"+$mon_count+"-manufacturer"
	$mon_type = ($mon_device.UserFriendlyName -notmatch 0 | ForEach{[char]$_}) -join ""
    [string]$mon_type_name="mon-id"+$mon_count+"-type"
	$mon_sn = ($mon_device.SerialNumberID -notmatch 0 | ForEach{[char]$_}) -join ""
    [string]$mon_sn_name="mon-id"+$mon_count+"-sn"

    $inventar | Add-Member -MemberType NoteProperty -Name "$mon_count_name" -Value "$mon_count" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$mon_manufacturer_name" -Value "$mon_manufacturer" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$mon_type_name" -Value "$mon_type" -Force
    $inventar | Add-Member -MemberType NoteProperty -Name "$mon_sn_name" -Value "$mon_sn" -Force	

}

#Dockingstation
 $dock=Get-WmiObject Win32_SystemEnclosure | select Manufacturer,Model,SerialNumber
 $dock_manufacturer=$dock.Manufacturer
 $dock_model=$dock.Model
 $dock_SN=$dock.SerialNumber
 $inventar | Add-Member -MemberType NoteProperty -Name "Dock-Manu" -Value "$dock_manufacturer" -Force
 $inventar | Add-Member -MemberType NoteProperty -Name "Dock-Model" -Value "$dock_model" -Force
 $inventar | Add-Member -MemberType NoteProperty -Name "Dock-SN" -Value "$dock_SN" -Force
            
#User-info
$username=$env:USERNAME

$inventar | Add-Member -MemberType NoteProperty -Name "user-logon" -Value "$username" -Force
$inventar
}

# *********************************************************************************
# * Funktion - Generate SW Inventory                                              *
# *********************************************************************************
function get-SwInventoryLocalpc() {
[array]$inventarSW = @()
if (((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture) -eq "32-Bit") {
$sw_list=(Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,UninstallString)
} else {
$sw_list=(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,UninstallString)
}
foreach ($swinventoryentry in $sw_list) {
$sw_displayname=$swinventoryentry.DisplayName
$sw_displayversion=$swinventoryentry.DisplayVersion
$sw_publisher=$swinventoryentry.Publisher
$sw_installdate=$swinventoryentry.InstallDate
$sw_uninstall=$swinventoryentry.UninstallString
try {
     if ($sw_displayname.Trim() -ne $null) {
        $temp = New-Object PSCustomObject
        $temp | Add-Member -MemberType NoteProperty -Name "PCname" -Value "$env:COMPUTERNAME"
        $temp | Add-Member -MemberType NoteProperty -Name "SW-Displayname" -Value "$sw_displayname"
        $temp | Add-Member -MemberType NoteProperty -Name "SW-DisplayVersion" -Value "$sw_displayversion" 
        $temp | Add-Member -MemberType NoteProperty -Name "SW-Publisher" -Value "$sw_publisher"
        $temp | Add-Member -MemberType NoteProperty -Name "SW-InstallDate" -Value "$sw_installdate"
        $temp | Add-Member -MemberType NoteProperty -Name "SW-UninstallString" -Value "$sw_uninstall"           
        $inventarSW +=$temp
        }
    } catch {}
}
$inventarSW
}


# *********************************************************************************
# * Main                                                                          *
# *********************************************************************************
#get-HwInventoryLocalpc | Out-GridView
get-HwInventoryLocalpc | Export-Csv -Path $csv_path_HW -NoTypeInformation
#get-SwInventoryLocalpc | Out-GridView
get-SwInventoryLocalpc | Export-Csv -Path $csv_path_SW -NoTypeInformation
