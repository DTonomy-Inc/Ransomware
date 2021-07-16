Try{
    $Apps = (gci -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -Recurse | Get-ItemProperty | ?{$_.UninstallString -Match 'KASetup.exe'});
if ($apps){
    Foreach ($App in $apps) {
    cmd /c $apps.uninstallstring + "/qn"}
} 
else { 
    Write-Host 'NotInstalled'
}
} 
Catch {Write-Host 'Failed'}