cls
Add-Type -AssemblyName System.Drawing
write-host "* written by JFmav                          *" -ForegroundColor Gray
write-host "*********************************************" -ForegroundColor Cyan
write-host "* Convert-All PictureFiles in Folder toJPG  *" -ForegroundColor Cyan
write-host "* Resize-these PictureFiles                 *" -ForegroundColor Cyan
write-host "* Delete-NameSpaces                         *" -ForegroundColor Cyan
write-host "*********************************************" -ForegroundColor Cyan
write-host "* BE CAREFUL!!!!                             *" -ForegroundColor Red
write-host "---------------------------------------------" -ForegroundColor Gray
[string]$n=Read-Host -Prompt "PLZ typeIn Folderpath"
[string]$x=Read-Host -Prompt "Do you want to Resize? (false,true)"
if ($x -eq $true) {
[int32]$height=Read-Host -Prompt "Picture height"
[int32]$wight=Read-Host -Prompt "Picture width"
}

foreach ($item in (Get-ChildItem $n | where { ! $_.PSIsContainer })) { 
write-host $item.name -ForegroundColor Cyan
write-host -ForegroundColor DarkYellow -NoNewline "entferne alle Leerzeichen im DateiNamen..."
$newname=$item.Name.substring(0,$item.Name.IndexOf(".")).replace(' ','')
#$newname
Rename-Item -Path ($n+"\"+$item.Name) -NewName ($newname+".jpg")
write-host -ForegroundColor DarkGreen "ok"

if ($height -ne $null -and $wight -ne $null) {
    $imgold = [System.Drawing.Bitmap]::FromFile($n+"\"+$item.Name)
    if ($imgold.Height -gt $height -or $imgold.Width -gt $wight) {
        write-host -ForegroundColor DarkYellow -NoNewline "Erstelle neues Bild mit der Größe $wight x $height..."
        $imgnewname=$item.Name.substring(0,($item.Name.Length-4))+"_"+$wight+"x"+$height+".jpg"

        $imgnew=$null
        #var must have int32
        $imgnew=New-Object System.Drawing.Bitmap($wight,$height)

        # Draw new image on the empty canvas
        $graph = [System.Drawing.Graphics]::FromImage($imgnew)
        $graph.DrawImage($imgold, 0, 0, $wight, $height)
        $imgnew.Save($n+"\"+$imgnewname)
        #close image sessions
        if ($imgnew){$imgnew.Dispose()}
        write-host -ForegroundColor DarkGreen "ok"

        #close image session
        if ($imgold){$imgold.Dispose()}
        write-host -ForegroundColor DarkYellow -NoNewline "Lösche Original-Vorlage(Bild)..."
        Remove-Item ($n+"\"+$newname+".jpg")
        write-host -ForegroundColor DarkGreen "ok"
        write-host -ForegroundColor DarkYellow -NoNewline "Umbenennen des neuen Bildes..."
        Rename-Item -Path ($n+"\"+$imgnewname) -NewName ($newname+".jpg")
        write-host -ForegroundColor DarkGreen  "ok"
    }
}

}


        #close image session
        if ($imgold){$imgold.Dispose()}
        if ($imgnew){$imgnew.Dispose()}
[System.GC]::Collect()
write-host "---------------------------------------------" -ForegroundColor Gray
write-host "Finised." -ForegroundColor Gray
write-host "---------------------------------------------" -ForegroundColor Gray
Start-Process explorer.exe $n

write-host "* Windows close automaticaly in 5 seconds    *" -ForegroundColor Red
Start-Sleep -Seconds 5
exit


