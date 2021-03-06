<#
.SYNOPSIS
    IP in Use Scan
.DESCRIPTION
 Scan IP-Addresses 
 Test-Connection with one attemed 
 output a list with "IP,Ping(true or false)


.NOTES
    Name:        get-IPScan.ps1
    Author:      JFmav
    Created:     2020-10-01
    Version:     0.1
#>
# *********************************************************************************
# * Definitions                                                                   *
# *********************************************************************************
$ipstart="172.16."
[int]$ipoctet3start=0
[int]$ipoctet3end=0
[int]$ipoctet4start=1
[int]$ipoctet4end=254
# *********************************************************************************
# * MAIN                                                                          *
# *********************************************************************************
$iplist = New-Object System.Collections.ArrayList
for ($i=$ipoctet3start; $i -lt $ipoctet3end; $i++){
    for ($a=$ipoctet4start; $a -lt $ipoctet4end; $a++){
    [string]$current_ip=$ipstart+$i+"."+$a
    Write-Host  $current_ip
    $test=Test-Connection $current_ip -Count 1 -ErrorAction SilentlyContinue
    if (($test) -ne $null) {
                $temp = New-Object System.Object
                $temp | Add-Member -MemberType NoteProperty -Name "IP" -Value "$current_ip"
                $temp | Add-Member -MemberType NoteProperty -Name "ping" -Value "$true" -Force             
     } else {
                     $temp = New-Object System.Object
                $temp | Add-Member -MemberType NoteProperty -Name "IP" -Value "$current_ip"
                $temp | Add-Member -MemberType NoteProperty -Name "ping" -Value "$false" -Force

     }
     $iplist.Add($temp) | Out-Null
  }

}
$iplist
