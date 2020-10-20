$privatenetworkshare="\\servername\sharename"
# *********************************************************************************
# * Funktion - Sync DATA 2 Wege                                                   *
# *********************************************************************************
function Start-FileSync2Ways() {
param([string]$source,[string]$dest,[string]$File)
if (Test-Path $source) {
                        if (Test-Path $dest) {
                                            #fistway
                                            robocopy /COPY:DAT /S /R:1 /W:1 $source $dest $File | Out-Null
                                            #catch{ write-host fail to copy from $source to $dest}
                                            #secondway
                                            robocopy /COPY:DAT /S /R:1 /W:1 $dest $source $File | Out-Null
                                            #catch{ Write-Host fail to copy from $dest to $source}                                            
                                            } else {
                                            New-Item -Path $dest.Substring(0,3) -Name $dest.Substring(3,9) -ItemType directory | Out-Null
                                            New-Item -Path $dest.Substring(0,13) -Name $dest.Substring(13) -ItemType directory | Out-Null
                                            #fistway
                                            robocopy /COPY:DAT /S /R:1 /W:1 $source $dest $File | Out-Null
                                            #catch{ write-host fail to copy from $source to $dest}
                                            #secondway
                                            robocopy /COPY:DAT /S /R:1 /W:1 $dest $source $File | Out-Null
                                            #catch{ Write-Host fail to copy from $dest to $source}   
                                            }
                        }
}

Start-FileSync2Ways "$env:USERPROFILE\AppData\Roaming\Microsoft\Signatures" "$privatenetworkshare"
