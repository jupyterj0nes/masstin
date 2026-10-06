Output demo-hunt.gif
Output demo-hunt.mp4
Set Shell "pwsh"
Set FontSize 14
Set Width 1400
Set Height 760
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Hide
Type "cd <evidence dir>; function prompt { '> ' }; Remove-Item hunt.csv,hunt.md -ErrorAction SilentlyContinue; $env:PATH = '<masstin dir>;' + $env:PATH; Clear-Host"
Enter
Sleep 3s
Show
Type "masstin -a graph-hunt-csv -f szechuan-timeline.csv --investigation-from '2020-09-19 00:00:00' --seed 194.61.24.102 --report hunt.md -o hunt.csv"
Sleep 1s
Enter
Sleep 9s
Type "Clear-Host; Import-Csv hunt.csv | Select rank,origin,destination,signature,chain -First 5 | Format-Table -AutoSize"
Sleep 1s
Enter
Sleep 9s
