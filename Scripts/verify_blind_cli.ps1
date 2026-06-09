param(
    [ValidateSet("Debug", "Release", "ReleaseStaged")]
    [string]$Configuration = "Debug",
    [int]$TimeoutSeconds = 25,
    [switch]$Build,
    [switch]$ProbeTarget
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Platform = "x64"
$Bin = Join-Path $Root "bin\$Configuration\$Platform"
$BuildConfiguration = if ($Configuration -eq "ReleaseStaged") { "Release" } else { $Configuration }
$Runner = Join-Path $Bin "BlindRunner.exe"
$Target = Join-Path $Bin "BlindTestTarget.exe"
$BlindCmd = Join-Path $Root "blind.cmd"
if (-not (Test-Path $BlindCmd)) {
    $parentBlindCmd = Join-Path (Split-Path $Root -Parent) "blind.cmd"
    if (Test-Path $parentBlindCmd) {
        $BlindCmd = $parentBlindCmd
    }
}
$Diagnostics = Join-Path $Bin "BlindDiagnostics"
$Script:Passed = 0
$Script:Failed = 0
$Script:Skipped = 0

function Get-LatestVCToolsVersion {
    $candidateRoots = @()
    $programFiles = ${env:ProgramFiles}
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ($programFiles) {
        $candidateRoots += Join-Path $programFiles "Microsoft Visual Studio"
    }
    if ($programFilesX86) {
        $candidateRoots += Join-Path $programFilesX86 "Microsoft Visual Studio"
    }

    $versions = @()
    foreach ($root in $candidateRoots | Select-Object -Unique) {
        if (-not (Test-Path $root)) {
            continue
        }
        $versions += Get-ChildItem -Path $root -Directory -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\VC\\Tools\\MSVC\\[^\\]+$' -and (Test-Path (Join-Path $_.FullName "bin\Hostx64\x64\cl.exe")) } |
            ForEach-Object {
                [pscustomobject]@{
                    Version = $_.Name
                    Path = $_.FullName
                    SortVersion = [version]$_.Name
                }
            }
    }

    $latest = $versions | Sort-Object SortVersion -Descending | Select-Object -First 1
    if ($null -eq $latest) {
        return $null
    }
    return $latest.Version
}

$VCToolsVersion = $null
if ($Build) {
    $VCToolsVersion = Get-LatestVCToolsVersion
    if ($VCToolsVersion) {
        Write-Host "[env] forcing VCToolsVersion=$VCToolsVersion"
    }
}

function Quote-Arg([string]$Value) {
    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Quote-CmdArg([string]$Value) {
    if ($null -eq $Value) {
        return '""'
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Join-Args([string[]]$Items) {
    return (($Items | ForEach-Object { Quote-Arg $_ }) -join " ")
}

function Stop-BlindChildren {
    Get-Process BlindRunner, BlindTestTarget -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Invoke-CheckedProcess {
    param(
        [string]$Name,
        [string]$File,
        [string[]]$ProcessArgs = @(),
        [string]$RawArgumentLine = $null,
        [int[]]$ExpectedExitCodes = @(0),
        [int]$Timeout = $TimeoutSeconds
    )

    $argLine = if ($null -ne $RawArgumentLine) { $RawArgumentLine } else { Join-Args $ProcessArgs }
    if ([string]::IsNullOrWhiteSpace($argLine)) {
        throw "internal verifier error: empty argument line for $Name"
    }

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("blind-cli-verify-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $stdoutPath = Join-Path $tempRoot "stdout.txt"
    $stderrPath = Join-Path $tempRoot "stderr.txt"

    $commandLine = "$(Quote-CmdArg $File) $argLine >$(Quote-CmdArg $stdoutPath) 2>$(Quote-CmdArg $stderrPath)"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = "/d /s /c `"$commandLine`""
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $false
    $psi.RedirectStandardError = $false
    $psi.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($psi)

    if (-not $process.WaitForExit($Timeout * 1000)) {
        try { $process.Kill() } catch {}
        try { $process.WaitForExit(1000) | Out-Null } catch {}
        Stop-BlindChildren
        $stdout = ""
        $stderr = ""
        try { $stdout = Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue } catch {}
        try { $stderr = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue } catch {}
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw "TIMEOUT [$Name] after ${Timeout}s`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
    }

    $stdout = ""
    $stderr = ""
    try { $stdout = Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue } catch {}
    try { $stderr = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue } catch {}
    $combined = $stdout + $stderr
    $exitCode = $process.ExitCode
    $process.Dispose()
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue

    if ($ExpectedExitCodes -notcontains $exitCode) {
        throw "EXIT [$Name] expected $($ExpectedExitCodes -join ',') got $exitCode`nARGS: $argLine`nOUTPUT:`n$combined"
    }

    [pscustomobject]@{
        Name = $Name
        ExitCode = $exitCode
        Output = $combined
    }
}

function Pass([string]$Name) {
    $Script:Passed++
    Write-Host "[PASS] $Name"
}

function Fail([string]$Name, [string]$Message) {
    $Script:Failed++
    Write-Host "[FAIL] $Name"
    Write-Host $Message
}

function Skip([string]$Name, [string]$Message) {
    $Script:Skipped++
    Write-Host "[SKIP] $Name"
    Write-Host $Message
}

function Assert-Contains($Result, [string]$Pattern, [string]$Message) {
    if ($Result.Output -notmatch $Pattern) {
        throw "$Message`nPattern: $Pattern`nOutput:`n$($Result.Output)"
    }
}

function Assert-NotContains($Result, [string]$Pattern, [string]$Message) {
    if ($Result.Output -match $Pattern) {
        throw "$Message`nPattern: $Pattern`nOutput:`n$($Result.Output)"
    }
}

function Run-Test([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        Pass $Name
    }
    catch {
        Fail $Name $_.Exception.Message
        Stop-BlindChildren
    }
}

function Run-Skip([string]$Name, [string]$Reason) {
    Skip $Name $Reason
}

function Run-Runner([string]$Name, [string]$RunnerArgLine, [int[]]$ExpectedExitCodes = @(0), [int]$Timeout = $TimeoutSeconds) {
    Invoke-CheckedProcess -Name $Name -File $Runner -RawArgumentLine $RunnerArgLine -ExpectedExitCodes $ExpectedExitCodes -Timeout $Timeout
}

if ($Build) {
    $projects = @(
        "VCXProj\BLIND.vcxproj",
        "VCXProj\BlindRunner.vcxproj",
        "VCXProj\BlindTestTarget.vcxproj",
        "VCXProj\BlindLaunchGateTarget.vcxproj",
        "VCXProj\BlindSdkHost.vcxproj"
    )
    foreach ($project in $projects) {
        $projectPath = Join-Path $Root $project
        Write-Host "[build] $project"
        $buildArgs = "$(Quote-CmdArg $projectPath) /p:Configuration=$BuildConfiguration /p:Platform=$Platform /m"
        if ($Configuration -eq "ReleaseStaged") {
            $stagedOutDir = $Bin
            $buildArgs += " /p:OutDir=$(Quote-Arg $stagedOutDir)"
        }
        if ($VCToolsVersion) {
            $buildArgs += " /p:VCToolsVersion=$VCToolsVersion"
        }
        Invoke-CheckedProcess -Name "build $project" -File "msbuild.exe" `
            -RawArgumentLine $buildArgs `
            -ExpectedExitCodes @(0) -Timeout 120 | Out-Null
    }
}
else {
    Write-Host "[build] skipped; using existing $Bin binaries"
}

$ProbeModeAvailable = $Build -or $ProbeTarget
if (-not $ProbeModeAvailable) {
    Write-Host "[probe] target probe modes skipped; pass -Build or -ProbeTarget after rebuilding BlindTestTarget.exe"
}

if (-not (Test-Path $Runner)) { throw "Missing runner: $Runner" }
if (-not (Test-Path $Target)) { throw "Missing target: $Target" }

$Dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($null -ne $Dumpbin) {
    Run-Test "BLIND optional DLL imports stay lazy" {
        $dll = Join-Path $Bin "BLIND.dll"
        $r = Invoke-CheckedProcess -Name "dumpbin imports" -File $Dumpbin.Source -RawArgumentLine "/imports $(Quote-CmdArg $dll)"
        Assert-NotContains $r "(?im)^\s*(WS2_32|DNSAPI|ADVAPI32|AMSI|WINHTTP|WININET|SECUR32|CRYPT32|NCRYPT|OLE32|COMBASE)\.dll\b" "BLIND.dll has an eager import for an optional hook DLL"
    }
}
else {
    Run-Skip "BLIND optional DLL imports stay lazy" "dumpbin.exe is not on PATH"
}

Run-Test "CLI help" {
    $r = Run-Runner "help" "--cli --help"
    Assert-Contains $r "blind <target\.exe>" "help did not include CLI target-first usage"
    Assert-Contains $r "Help aliases:" "help did not document aliases"
    Assert-Contains $r "Rule options" "help did not document rule options"
    Assert-Contains $r "--sym" "help did not document symbol resolution"
    Assert-Contains $r "--syms" "help did not document symbol alias"
    Assert-Contains $r "--sym-path" "help did not document explicit symbol paths"
    Assert-Contains $r "--r, --regs" "help did not document register snapshots"
    Assert-Contains $r "--behavior" "help did not document behavior mode"
    Assert-Contains $r "--behavior-stacks" "help did not document behavior stack summaries"
    Assert-Contains $r "--when" "help did not document behavior conditions"
    Assert-Contains $r "--color" "help did not document console coloring"
    Assert-Contains $r "--disable-lg" "help did not document disabling the default launch gate"
    Assert-Contains $r "--mm" "help did not document manual-map injection"
    Assert-Contains $r "role-tagged" "help did not document stack frame role tags"
    Assert-Contains $r "new console" "help did not mention target console separation"
}

Run-Test "help aliases" {
    $aliases = @("--cli help", "--cli -h", "--cli /?", "help")
    foreach ($alias in $aliases) {
        $r = Run-Runner "help alias $alias" $alias
        Assert-Contains $r "BLIND - owned-process" "help alias '$alias' did not print detailed help"
        Assert-Contains $r "Examples:" "help alias '$alias' did not include examples"
    }
}

Run-Test "blind.cmd help works" {
    $env:BLIND_CONFIG = $Configuration
    try {
        $r = Invoke-CheckedProcess -Name "blind.cmd help" -File $BlindCmd -RawArgumentLine "help"
    }
    finally {
        Remove-Item Env:\BLIND_CONFIG -ErrorAction SilentlyContinue
    }
    Assert-Contains $r "BLIND - owned-process" "blind.cmd help did not print detailed help"
}

Run-Test "command-focused help works" {
    $r = Run-Runner "help hooks" "--cli help hooks"
    Assert-Contains $r "BLIND help: hooks" "help hooks did not print the hook topic"
    Assert-Contains $r "--lhooks <list>" "hook topic did not document list syntax"
    $r = Run-Runner "help behavior" "--cli help behavior"
    Assert-Contains $r "BLIND help: behavior" "help behavior did not print the behavior topic"
    Assert-Contains $r "--behavior-stacks" "behavior topic did not document stack summaries"
}

Run-Test "parser rejects missing hook" {
    $r = Run-Runner "missing hook" "--cli $(Quote-CmdArg $Target) --cli-probe-direct" @(2)
    Assert-Contains $r "requires at least one --hook or --lhook" "missing hook was not rejected"
}

Run-Test "parser rejects action before hook" {
    $r = Run-Runner "action before hook" "--cli $(Quote-CmdArg $Target) --cli-probe-direct --deny --hook NtQueryInformationProcess" @(2)
    Assert-Contains $r "must follow --hook or --lhook" "action before hook was not rejected"
}

Run-Test "parser rejects registers before hook" {
    $r = Run-Runner "registers before hook" "--cli $(Quote-CmdArg $Target) --cli-probe-direct --r --hook NtQueryInformationProcess" @(2)
    Assert-Contains $r "must follow --hook or --lhook" "register capture before hook was not rejected"
}

Run-Test "parser rejects hook type before hook" {
    $r = Run-Runner "hook type before hook" "--cli $(Quote-CmdArg $Target) --cli-probe-direct --int3 --hook NtQueryInformationProcess" @(2)
    Assert-Contains $r "must follow --hook or --lhook" "hook type before hook was not rejected"
}

Run-Test "explicit hook does not print by default" {
    $r = Run-Runner "explicit no-log" "--cli $(Quote-CmdArg $Target) --hook NtCreateThreadEx"
    Assert-Contains $r "child exit=0x00000000" "target did not exit cleanly"
    Assert-NotContains $r "NtCreateThreadEx hit" "plain --hook printed a log-hook line"
}

Run-Test "log-hook prints caller module offset" {
    $r = Run-Runner "caller logging" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess"
    Assert-Contains $r "NtQueryInformationProcess hit" "log-hook did not print the API hit"
    Assert-Contains $r "caller=.*\+0x[0-9A-Fa-f]+" "caller did not resolve to module+offset"
    Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
}

Run-Test "stack trace prints frames" {
    $r = Run-Runner "stack trace" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --stack-trace"
    Assert-Contains $r "NtQueryInformationProcess hit" "stack-trace case did not print API hit"
    Assert-Contains $r "(?m)^\s+#00 " "stack frame #00 was not printed"
    Assert-Contains $r "\[internal\]" "stack frames did not label BLIND internals"
}

Run-Test "stack fabricate sanitizes BLIND frames" {
    $r = Run-Runner "stack fabricate" "--cli $(Quote-CmdArg $Target) --cli-probe-direct --lhook NtQueryInformationProcess --stack-trace --sym --sf"
    Assert-Contains $r "NtQueryInformationProcess hit" "stack-fabricate case did not print API hit"
    Assert-Contains $r "(?m)^\s+#00 \[app\]" "stack-fabricate did not promote the app caller to frame #00"
    Assert-NotContains $r "\[internal\].*BLIND\.dll" "stack-fabricate leaked BLIND-owned frames"
}

Run-Test "NT int3 hook type logs hits" {
    $r = Run-Runner "nt int3 hook" "--cli $(Quote-CmdArg $Target) --cli-probe-direct --lhook NtQueryInformationProcess --int3"
    Assert-Contains $r "NtQueryInformationProcess hit" "INT3 NT hook did not print the API hit"
    Assert-Contains $r "child exit=0x00000000" "INT3 NT hook target did not exit cleanly"
}

Run-Test "module IAT hook type logs loader hits" {
    $r = Run-Runner "module iat hook" "--cli $(Quote-CmdArg $Target) --lhook module:LoadLibraryW --iat" @(0) 40
    Assert-Contains $r "LoadLibraryW hit kind=module module=KERNELBASE" "IAT module hook did not log LoadLibraryW"
    Assert-Contains $r "path=`"version\.dll`"" "IAT module hook did not capture the loader path"
}

Run-Test "module shadow-IAT hook type logs loader hits" {
    $r = Run-Runner "module shadow iat hook" "--cli $(Quote-CmdArg $Target) --lhook module:LoadLibraryW --shadow-iat" @(0) 40
    Assert-Contains $r "LoadLibraryW hit kind=module module=KERNELBASE" "shadow-IAT module hook did not log LoadLibraryW"
    Assert-Contains $r "path=`"version\.dll`"" "shadow-IAT module hook did not capture the loader path"
}

Run-Test "list hooks apply rule options" {
    $r = Run-Runner "list hooks" "--cli $(Quote-CmdArg $Target) --lhooks [NtQueryInformationProcess,NtQueryInformationThread] --stack-trace"
    Assert-Contains $r "NtQueryInformationProcess hit" "list hook did not include NtQueryInformationProcess"
    Assert-Contains $r "NtQueryInformationThread hit" "list hook did not include NtQueryInformationThread"
    Assert-Contains $r "(?m)^\s+#00 " "list hook stack-trace option was not applied"
}

Run-Test "symbol stack trace keeps frames" {
    $r = Run-Runner "symbol stack trace" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --stack-trace --syms"
    Assert-Contains $r "NtQueryInformationProcess hit" "symbol stack-trace case did not print API hit"
    Assert-Contains $r "(?m)^\s+#00 " "symbol stack-trace frame #00 was not printed"
    Assert-Contains $r "\[system\]" "symbol stack trace did not label system frames"
}

Run-Test "register snapshot prints registers" {
    $r = Run-Runner "register snapshot" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --r"
    Assert-Contains $r "NtQueryInformationProcess hit" "register snapshot case did not print API hit"
    Assert-Contains $r "(?m)^\s+regs rip=0x[0-9A-Fa-f]+ rsp=0x[0-9A-Fa-f]+ .* rcx=0x[0-9A-Fa-f]+" "register snapshot was not printed"
}

Run-Test "behavior mode summarizes behavior" {
    $r = Run-Runner "behavior summary" "--cli $(Quote-CmdArg $Target) --behavior"
    Assert-Contains $r "\[blind:behavior\] final targets=[1-9]" "behavior final summary was not printed"
    Assert-Contains $r "\[blind:behavior\] memory target=self allocs=[1-9]" "behavior memory map did not summarize allocations"
    Assert-Contains $r "caller_region=" "behavior map did not label caller memory regions"
    Assert-Contains $r "\[blind:behavior\] thread target=self count=[1-9]" "behavior thread summary was not printed"
    Assert-NotContains $r "NtAllocateVirtualMemory hit" "behavior mode printed raw allocation spam without --raw"
    Assert-NotContains $r "\[target\]" "target output leaked into behavior BLIND output"
}

Run-Test "behavior condition alerts" {
    $condition = Quote-CmdArg "alloc.total>1kb"
    $r = Run-Runner "behavior condition" "--cli $(Quote-CmdArg $Target) --behavior --when $condition"
    Assert-Contains $r "\[blind:behavior\] alert alloc\.total target=self" "behavior alloc.total condition did not alert"
}

Run-Test "behavior stacks print representative frames" {
    $r = Run-Runner "behavior stacks" "--cli $(Quote-CmdArg $Target) --behavior --behavior-stacks 6"
    Assert-Contains $r "\[blind:behavior:stack\] region base=0x[0-9A-Fa-f]+" "behavior stack summary was not printed"
    Assert-Contains $r "frames=6/" "space-separated --behavior-stacks frame count was not honored"
    Assert-Contains $r "(?m)^\s+#00 " "behavior stack summary did not include frames"
    Assert-Contains $r "\[internal\]" "behavior stack summary did not label BLIND internals"
}

if ($ProbeModeAvailable) {
    Run-Test "behavior protects fold noisy log hook" {
        $r = Run-Runner "protect folding" "--cli $(Quote-CmdArg $Target) --cli-probe-protect-churn --lhook NtProtectVirtualMemory --stack-trace --sym" @(0) 40
        Assert-Contains $r "\[blind:behavior\] auto-enabled protect folding" "NtProtectVirtualMemory log-hook did not auto-enable behavior folding"
        Assert-Contains $r "\[blind:behavior\] final targets=[1-9].*protect_groups=[1-9]" "protect behavior final summary did not report protect groups"
        Assert-Contains $r "\[blind:behavior\] memory target=self .*protects=[1-9][0-9]*" "protect count was not summarized"
        Assert-Contains $r "\[blind:behavior\] protect target=self count=[1-9][0-9]* pages=[1-9][0-9]* .*->" "protect transitions were not grouped"
        Assert-Contains $r "caller_region=" "protect behavior mode did not include caller-region labels"
        Assert-Contains $r "\[blind:behavior:stack\] protect first=0x[0-9A-Fa-f]+" "folded protect stack summary was not printed"
        Assert-NotContains $r "NtProtectVirtualMemory hit" "protect behavior mode printed raw NtProtect spam without --raw"
    }

    Run-Test "duplicate folding shows repeat count" {
        $r = Run-Runner "duplicate folding" "--cli $(Quote-CmdArg $Target) --cli-probe-duplicates --lhook NtQueryInformationProcess"
        Assert-Contains $r "NtQueryInformationProcess x[2-9][0-9]* hit" "duplicate calls were not folded into x2/x3"
    }

    Run-Test "lazy AMSI group hooks after DLL load" {
        $r = Run-Runner "lazy amsi" "--cli $(Quote-CmdArg $Target) --cli-probe-lazy-amsi --lhook amsi --stack-trace --sym" @(0) 40
        Assert-Contains $r "AmsiInitialize hit kind=module module=amsi" "lazy AMSI group did not log AmsiInitialize"
        Assert-Contains $r "AmsiScanBuffer hit kind=module module=amsi" "lazy AMSI hook did not log AmsiScanBuffer"
        Assert-Contains $r "(?m)^\s+#00 " "lazy AMSI stack frames were not printed"
        Assert-Contains $r "\[internal\]" "lazy AMSI stack frames did not label BLIND internals"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "lazy ETW group hooks after DLL load" {
        $r = Run-Runner "lazy etw" "--cli $(Quote-CmdArg $Target) --cli-probe-lazy-etw --lhook etw" @(0) 40
        Assert-Contains $r "(EventRegister|EtwEventWrite) hit kind=module" "lazy ETW hook did not log EventRegister or EtwEventWrite"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "lazy Winsock group hooks direct GetProcAddress calls" {
        $r = Run-Runner "lazy winsock" "--cli $(Quote-CmdArg $Target) --cli-probe-lazy-winsock --lhook winsock" @(0) 40
        Assert-Contains $r "connect hit kind=winsock" "lazy Winsock hook did not log direct connect call"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "remote handles resolve target metadata" {
        $r = Run-Runner "remote handles" "--cli $(Quote-CmdArg $Target) --cli-probe-remote-handles --lhook NtOpenProcess --lhook NtOpenThread --lhook NtQueryVirtualMemory --lhook NtReadVirtualMemory --stack-trace --sym" @(0) 40
        Assert-Contains $r "NtOpenProcess hit .*target=remote\(pid=[0-9]+ name=BlindRunner\.exe\).*access=0x[0-9A-Fa-f]+\(.*VM_READ.*QUERY_LIMITED_INFORMATION.*\).*handle=0x[1-9A-Fa-f]" "NtOpenProcess did not resolve remote process name/access/handle"
        Assert-Contains $r "NtOpenThread hit .*owner=remote\(pid=[0-9]+ name=BlindRunner\.exe\).*access=0x[0-9A-Fa-f]+\(.*QUERY_LIMITED_INFORMATION.*\).*handle=0x[1-9A-Fa-f]" "NtOpenThread did not resolve remote thread owner/access/handle"
        Assert-Contains $r "NtQueryVirtualMemory hit .*target=remote\(pid=[0-9]+ name=BlindRunner\.exe\).*class=MemoryBasicInformation\(0\).*vad=" "NtQueryVirtualMemory did not print remote target/class/VAD"
        Assert-Contains $r "NtReadVirtualMemory hit .*target=remote\(pid=[0-9]+ name=BlindRunner\.exe\).*bytes=[1-9]" "NtReadVirtualMemory did not print remote target and actual bytes"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "behavior remote folds handles queries and reads" {
        $r = Run-Runner "behavior remote" "--cli $(Quote-CmdArg $Target) --cli-probe-remote-handles --behavior=remote --summary-interval 0 --behavior-stacks 4" @(0) 40
        Assert-Contains $r "\[blind:behavior\] final targets=[1-9].*handles=[1-9]" "behavior remote summary did not report remote handle groups"
        Assert-Contains $r "\[blind:behavior\] memory target=remote\(BlindRunner\.exe\).*queries=[1-9][0-9]*.*reads=[1-9][0-9]*.*opens=[1-9][0-9]*/[1-9][0-9]*.*risk=remote_io" "behavior remote target did not aggregate queries/reads/handles"
        Assert-Contains $r "\[blind:behavior\] handle kind=process target=remote\(BlindRunner\.exe\).*access=0x[0-9A-Fa-f]+\(.*VM_READ.*\).*risk=remote_process_read" "behavior remote process handle summary missing decoded access"
        Assert-Contains $r "\[blind:behavior\] region target=remote\(BlindRunner\.exe\).*queries=[1-9][0-9]*.*reads=[1-9][0-9]*.*read=[1-9]" "behavior remote VAD/read region was not folded"
        Assert-NotContains $r "NtQueryVirtualMemory hit .*target=remote" "behavior remote leaked raw NtQueryVirtualMemory scanner spam"
        Assert-NotContains $r "NtReadVirtualMemory hit .*target=remote" "behavior remote leaked raw NtReadVirtualMemory spam"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "guarded ntdll export access flags SSN resolution" {
        $r = Run-Runner "ntdll eat guard" "--cli $(Quote-CmdArg $Target) --cli-probe-ntdll-eat-read --lhook loader --stack-trace --sym" @(0) 40
        Assert-Contains $r "\[blind:detection\] resolving-system-service-call-numbers" "guarded ntdll EAT access did not produce the SSN-resolution detection"
        Assert-Contains $r "(?m)^\s+#00 " "ntdll EAT guard detection did not print a stack"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }

    Run-Test "direct syscall page is detected and dumped" {
        $r = Run-Runner "direct syscall page" "--cli $(Quote-CmdArg $Target) --cli-probe-direct-syscall --lhook NtProtectVirtualMemory --stack-trace --sym" @(0) 40
        Assert-Contains $r "\[blind:detection\] direct-syscall" "direct syscall page was not detected"
        Assert-Contains $r "ssn=0x1234" "direct syscall detection did not report the syscall number"
        Assert-Contains $r "sample=4C8BD1B8341200000F05C3" "direct syscall detection did not include the stub bytes"
        Assert-NotContains $r "\[target\]" "target output leaked into BLIND output"
    }
}
else {
    Run-Skip "duplicate folding shows repeat count" "requires rebuilt BlindTestTarget.exe with --cli-probe-duplicates"
    Run-Skip "lazy AMSI group hooks after DLL load" "requires rebuilt BlindTestTarget.exe with lazy probes"
    Run-Skip "lazy ETW group hooks after DLL load" "requires rebuilt BlindTestTarget.exe with lazy probes"
    Run-Skip "lazy Winsock group hooks direct GetProcAddress calls" "requires rebuilt BlindTestTarget.exe with lazy probes"
    Run-Skip "remote handles resolve target metadata" "requires rebuilt BlindTestTarget.exe with remote handle probe"
    Run-Skip "behavior remote folds handles queries and reads" "requires rebuilt BlindTestTarget.exe with remote handle probe"
    Run-Skip "guarded ntdll export access flags SSN resolution" "requires rebuilt BlindTestTarget.exe with guarded EAT probe"
    Run-Skip "direct syscall page is detected and dumped" "requires rebuilt BlindTestTarget.exe with direct syscall probe"
}

Run-Test "ignore-dll suppresses immediate caller" {
    $r = Run-Runner "ignore dll" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --ignore-dll KERNELBASE"
    Assert-Contains $r "child exit=0x00000000" "ignore-dll target did not exit cleanly"
    Assert-NotContains $r "NtQueryInformationProcess hit" "ignore-dll did not suppress KERNELBASE caller"
}

if ($ProbeModeAvailable) {
    Run-Test "private caller is visible without ignore-private" {
        $r = Run-Runner "private caller visible" "--cli $(Quote-CmdArg $Target) --cli-probe-private --lhook NtQueryInformationProcess"
        Assert-Contains $r "NtQueryInformationProcess hit" "private caller did not print API hit"
        Assert-Contains $r "caller=0x[0-9A-Fa-f]+" "private caller was not reported as a raw private address"
    }

    Run-Test "ignore-private suppresses private caller" {
        $r = Run-Runner "ignore private" "--cli $(Quote-CmdArg $Target) --cli-probe-private --lhook NtQueryInformationProcess --ignore-private"
        Assert-Contains $r "child exit=0x00000000" "ignore-private target did not exit cleanly"
        Assert-NotContains $r "NtQueryInformationProcess hit" "ignore-private did not suppress the private caller"
    }
}
else {
    Run-Skip "private caller is visible without ignore-private" "requires rebuilt BlindTestTarget.exe with --cli-probe-private"
    Run-Skip "ignore-private suppresses private caller" "requires rebuilt BlindTestTarget.exe with --cli-probe-private"
}

Run-Test "deny returns access denied" {
    $r = Run-Runner "deny" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --deny"
    Assert-Contains $r "denied status=0xC0000022" "deny did not print STATUS_ACCESS_DENIED"
    Assert-Contains $r "child exit=0x00000000" "target did not exit cleanly under deny"
}

Run-Test "silent-deny returns success and drops original" {
    $r = Run-Runner "silent deny" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess --silent-deny"
    Assert-Contains $r "silent-denied status=0x00000000" "silent-deny did not print success status"
    Assert-Contains $r "child exit=0x00000000" "target did not exit cleanly under silent-deny"
}

Run-Test "separator form works" {
    $r = Run-Runner "separator" "--cli --lhook NtQueryInformationProcess -- $(Quote-CmdArg $Target)"
    Assert-Contains $r "NtQueryInformationProcess hit" "separator form did not run the target probe"
}

Run-Test "launch gate is default" {
    $r = Run-Runner "default launch gate" "--cli $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess"
    Assert-Contains $r "launch_gate=1 guarded=0" "default CLI run did not enable the pre-entry launch gate"
    Assert-Contains $r "ready wait=0" "default launch gate did not wait for BLIND readiness before resume"
    Assert-Contains $r "child exit=0x00000000" "default launch gate target did not exit cleanly"
}

Run-Test "disable launch gate" {
    $r = Run-Runner "disable launch gate" "--cli --disable-lg $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess"
    Assert-Contains $r "launch_gate=0 guarded=0" "--disable-lg did not disable launch-gate mode"
    Assert-Contains $r "NtQueryInformationProcess hit" "--disable-lg run did not keep hooks functional"
    Assert-Contains $r "child exit=0x00000000" "--disable-lg target did not exit cleanly"
}

Run-Test "manual map keeps module out of loader list" {
    $r = Run-Runner "manual map" "--cli --mm $(Quote-CmdArg $Target) --lhook NtQueryInformationProcess"
    Assert-Contains $r "inject=manual-map" "--mm did not select manual-map injection mode"
    Assert-Contains $r "manual-map visible=0" "--mm did not keep BLIND out of the child loader module list"
    Assert-Contains $r "ready wait=0" "--mm did not wait for BLIND readiness before user code"
    Assert-Contains $r "NtQueryInformationProcess hit" "--mm hooks did not fire"
    Assert-Contains $r "child exit=0x00000000" "--mm target did not exit cleanly"
}

Run-Test "blind.cmd wrapper works" {
    $env:BLIND_CONFIG = $Configuration
    try {
        $r = Invoke-CheckedProcess -Name "blind.cmd" -File $BlindCmd -ProcessArgs @() -RawArgumentLine "$(Quote-CmdArg $Target) --lhook NtQueryInformationProcess"
    }
    finally {
        Remove-Item Env:\BLIND_CONFIG -ErrorAction SilentlyContinue
    }
    Assert-Contains $r "NtQueryInformationProcess hit" "blind.cmd wrapper did not reach CLI mode"
    Assert-NotContains $r "\[target\]" "target output leaked into blind.cmd output"
}

Run-Test "CLI no-debug does not create diagnostics bundle" {
    $before = if (Test-Path $Diagnostics) { @(Get-ChildItem $Diagnostics -Directory).Count } else { 0 }
    Run-Runner "no debug diagnostics" "--cli $(Quote-CmdArg $Target) --hook NtQueryInformationProcess" | Out-Null
    $after = if (Test-Path $Diagnostics) { @(Get-ChildItem $Diagnostics -Directory).Count } else { 0 }
    if ($after -ne $before) {
        throw "diagnostics bundle count changed without --debug: before=$before after=$after"
    }
}

Run-Test "CLI debug creates diagnostics bundle" {
    $before = if (Test-Path $Diagnostics) { @(Get-ChildItem $Diagnostics -Directory).Count } else { 0 }
    Run-Runner "debug diagnostics" "--cli $(Quote-CmdArg $Target) --debug --hook NtQueryInformationProcess" | Out-Null
    $after = if (Test-Path $Diagnostics) { @(Get-ChildItem $Diagnostics -Directory).Count } else { 0 }
    if ($after -le $before) {
        throw "diagnostics bundle was not created with --debug: before=$before after=$after"
    }
    $latest = Get-ChildItem $Diagnostics -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $summary = Join-Path $latest.FullName "summary.txt"
    if (-not (Test-Path $summary)) {
        throw "diagnostics summary was not written: $summary"
    }
    $summaryText = Get-Content $summary -Raw
    if ($summaryText -notmatch "host_log=.*blind-host[.]log") {
        throw "diagnostics summary did not include host log path: $summary"
    }
}

Write-Host "[summary] passed=$Script:Passed failed=$Script:Failed skipped=$Script:Skipped"
if ($Script:Failed -ne 0) {
    exit 1
}
exit 0
