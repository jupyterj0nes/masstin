Output demo-hunt.mp4
Set Shell "pwsh"
Set FontSize 14
Set Width 1400
Set Height 760
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set Framerate 5
Hide
Type "cd <evidence dir>; function prompt { '> ' }; Remove-Item hunt.csv,hunt.md -ErrorAction SilentlyContinue; $env:PATH = '<masstin dir>;' + $env:PATH; Clear-Host"
Enter
Sleep 3s
Show
Type "masstin -a graph-hunt-csv -f lanl-timeline.csv --investigation-from '2015-01-08 00:00:00' --report hunt.md -o hunt.csv"
Sleep 1s
Enter
Sleep 45m
Sleep 8s
Type "Clear-Host; Get-Content hunt.csv -First 9 | ConvertFrom-Csv | Select rank,significant,origin,destination,account,signature | Format-Table -AutoSize"
Sleep 1s
Enter
Sleep 10s
