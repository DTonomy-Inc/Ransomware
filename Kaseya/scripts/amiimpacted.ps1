
# put your servers in serverlist.txt
$serverListPath = 'c:\yourfolder\serverlist.txt'
$Servers = Get-content -Path $serverListPath 
Foreach ($Server in $Servers) { 
$Test = Test-Path -path "\\$Server\c$\kworking\agent.exe"
if ($Test -eq $True) { 
    Write-Host "Path exists on $Server." 
   } else { 
        Write-Host "Path NOT exist on $Server." 
    } 
}