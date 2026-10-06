Output demo-parse.gif
Output demo-parse.mp4
Set Shell "pwsh"
Set FontSize 15
Set Width 1200
Set Height 900
Set Theme "Catppuccin Mocha"
Set TypingSpeed 55ms
Set PlaybackSpeed 0.6
Hide
Type "cd <evidence dir>; function prompt { '> ' }; Remove-Item timeline.csv -ErrorAction SilentlyContinue; $env:PATH = '<masstin dir>;' + $env:PATH; Clear-Host"
Enter
Sleep 3s
Show
Type "masstin -a parse-windows -d .\EVTX-to-MITRE-Attack -o timeline.csv"
Sleep 1s
Enter
Sleep 7s
Type "Import-Csv timeline.csv | Select time_created,event_id,logon_type,src_ip,target_user_name,dst_computer -First 10 | Format-Table"
Sleep 1s
Enter
Sleep 5s
