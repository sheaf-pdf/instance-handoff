# Runs the test binaries at medium integrity, the level of a normal,
# unelevated desktop launch. GitHub's Windows runners run every step as an
# administrator with UAC off, at high integrity, so the other test steps
# cover only the elevated path.
#
# Each binary runs with the Basic User token that `runas /trustlevel:0x20000`
# uses: the same user, with Administrators deny-only and no admin
# privileges, and its integrity set to medium. Doctests are compiled as they
# run, so they stay with the other steps.

$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class Medium
{
    public const uint MEDIUM = 0x2000;

    const uint SAFER_SCOPEID_USER = 2;
    const uint SAFER_LEVELID_NORMALUSER = 0x20000;
    const uint SAFER_LEVEL_OPEN = 1;
    const int TokenIntegrityLevel = 25;
    const uint SE_GROUP_INTEGRITY = 0x20;
    const uint TOKEN_QUERY = 8;
    const uint CREATE_SUSPENDED = 4;
    const uint STARTF_USESTDHANDLES = 0x100;
    const uint HANDLE_FLAG_INHERIT = 1;
    const uint INFINITE = 0xFFFFFFFF;

    // TOKEN_MANDATORY_LABEL is one SID_AND_ATTRIBUTES.
    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars;
        public uint dwFillAttribute, dwFlags;
        public ushort wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferCreateLevel(uint scope, uint level, uint flags, out IntPtr handle, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferComputeTokenFromLevel(IntPtr level, IntPtr token, out IntPtr result, uint flags, IntPtr reserved);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SaferCloseLevel(IntPtr level);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
    [DllImport("advapi32.dll")]
    static extern uint GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(IntPtr token, int kind, ref SID_AND_ATTRIBUTES info, uint len);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr info, uint len, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder cmd, IntPtr processAttrs,
        IntPtr threadAttrs, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si,
        out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int which);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr mem);

    static void Check(bool ok, string call)
    {
        if (!ok)
        {
            throw new Exception(call + " failed: error " + Marshal.GetLastWin32Error());
        }
    }

    // A token's integrity level: the last sub-authority of its label.
    static uint Level(IntPtr token)
    {
        uint len;
        GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out len);
        IntPtr buf = Marshal.AllocHGlobal((int)len);
        try
        {
            Check(GetTokenInformation(token, TokenIntegrityLevel, buf, len, out len), "GetTokenInformation");
            IntPtr sid = Marshal.ReadIntPtr(buf);
            byte count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
            return (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    static uint ProcessLevel(IntPtr process)
    {
        IntPtr token;
        Check(OpenProcessToken(process, TOKEN_QUERY, out token), "OpenProcessToken");
        try
        {
            return Level(token);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    public static uint MyLevel()
    {
        return ProcessLevel(GetCurrentProcess());
    }

    static IntPtr Inheritable(IntPtr handle)
    {
        if (handle != IntPtr.Zero && handle != new IntPtr(-1))
        {
            SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        }
        return handle;
    }

    // Runs `commandLine` at medium, sharing this process's standard
    // handles, and returns its exit code. Fails unless the child's token
    // really is at medium before it starts.
    public static uint Run(string commandLine)
    {
        IntPtr level, token;
        Check(SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_NORMALUSER, SAFER_LEVEL_OPEN, out level, IntPtr.Zero),
            "SaferCreateLevel");
        try
        {
            Check(SaferComputeTokenFromLevel(level, IntPtr.Zero, out token, 0, IntPtr.Zero),
                "SaferComputeTokenFromLevel");
        }
        finally
        {
            SaferCloseLevel(level);
        }
        try
        {
            if (Level(token) != MEDIUM)
            {
                IntPtr sid;
                Check(ConvertStringSidToSid("S-1-16-8192", out sid), "ConvertStringSidToSid");
                try
                {
                    var label = new SID_AND_ATTRIBUTES { Sid = sid, Attributes = SE_GROUP_INTEGRITY };
                    uint len = (uint)Marshal.SizeOf(label) + GetLengthSid(sid);
                    Check(SetTokenInformation(token, TokenIntegrityLevel, ref label, len), "SetTokenInformation");
                }
                finally
                {
                    LocalFree(sid);
                }
            }

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = Inheritable(GetStdHandle(-10));
            si.hStdOutput = Inheritable(GetStdHandle(-11));
            si.hStdError = Inheritable(GetStdHandle(-12));
            PROCESS_INFORMATION pi;
            Check(CreateProcessAsUser(token, null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, true,
                CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi), "CreateProcessAsUser");
            try
            {
                uint got = ProcessLevel(pi.hProcess);
                if (got != MEDIUM)
                {
                    TerminateProcess(pi.hProcess, 1);
                    throw new Exception(String.Format("the child runs at level 0x{0:x}, not medium", got));
                }
                ResumeThread(pi.hThread);
                WaitForSingleObject(pi.hProcess, INFINITE);
                uint code;
                Check(GetExitCodeProcess(pi.hProcess, out code), "GetExitCodeProcess");
                return code;
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
        finally
        {
            CloseHandle(token);
        }
    }
}
'@

Write-Host ('This step runs at integrity level 0x{0:x}; the tests run at medium (0x2000).' -f [Medium]::MyLevel())

# Build at this level, then run each test binary (the library's unit tests
# and each file in tests/) at medium.
$exes = cargo test --locked --all-features --no-run --message-format=json |
    Where-Object { $_.StartsWith('{') } |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.executable } |
    ForEach-Object { $_.executable }
if ($LASTEXITCODE -ne 0) {
    throw 'building the tests failed'
}
if (-not $exes) {
    throw 'no test binaries were built'
}

$failed = @()
foreach ($exe in $exes) {
    Write-Host "Running $(Split-Path -Leaf $exe) at medium"
    $code = [Medium]::Run("`"$exe`"")
    if ($code -ne 0) {
        $failed += Split-Path -Leaf $exe
    }
}
if ($failed) {
    throw "failed at medium: $($failed -join ', ')"
}
