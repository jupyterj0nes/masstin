Output demo-hunt.gif
Output demo-hunt.mp4
Set Shell "pwsh"
Set FontSize 15
Set Width 1200
Set Height 640
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Hide
Type "cd D:\evidence; $env:PATH = '<masstin dir>;' + $env:PATH; function prompt { '> ' }; Clear-Host"
Enter
Sleep 3s
Show
Type "masstin -a graph-hunt-csv -f szechuan-timeline.csv --investigation-from '2020-09-19 00:00:00' --seed 194.61.24.102 --report hunt.md -o hunt.csv --overwrite"
Sleep 800ms
Enter
Sleep 7s
Type "Clear-Host; Get-Content hunt.md | Select-Object -Skip 14 -First 12"
Sleep 800ms
Enter
Sleep 7s
