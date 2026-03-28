$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$env:USERPROFILE\Desktop\動画文字起こし.lnk")
$sc.TargetPath = "$env:USERPROFILE\video-transcriber\start.bat"
$sc.WorkingDirectory = "$env:USERPROFILE\video-transcriber"
$sc.IconLocation = "shell32.dll,21"
$sc.Save()
Write-Host "Desktop shortcut created"
