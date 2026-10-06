Output demo-parse.gif
Output demo-parse.mp4
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
Type "masstin -a parse-windows -d .\EVTX-to-MITRE-Attack -o timeline.csv --overwrite"
Sleep 800ms
Enter
Sleep 9s
Type "Import-Csv timeline.csv | Where event_id -in 4624,4648,1149 | Select time_created,event_id,logon_type,src_ip,target_user_name,dst_computer -First 8 | Format-Table"
Sleep 800ms
Enter
Sleep 6s
