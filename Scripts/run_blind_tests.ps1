param(
    [ValidateSet("Debug", "Release", "ReleaseStaged")]
    [string]$Configuration = "Release",
    [int]$TimeoutSeconds = 45,
    [switch]$NoBuild,
    [switch]$NoFormat,
    [switch]$NoVerifier,
    [switch]$NoMitigations,
    [switch]$NoConnectivity
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Platform = "x64"
$Bin = Join-Path $Root "bin\$Configuration\$Platform"
$env:BLIND_TEST_NO_NEW_CONSOLE = "1"
$Script:Passed = 0
$Script:Failed = 0
$Script:Skipped = 0

function Write-Section([string]$Name) {
    Write-Host ""
    Write-Host "== $Name =="
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

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    try {
        & $Body
        Pass $Name
    }
    catch {
        Fail $Name $_.Exception.Message
    }
}

function Quote-CmdArg([string]$Value) {
    if ($null -eq $Value) {
        return '""'
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Invoke-CapturedProcess {
    param(
        [string]$Name,
        [string]$File,
        [string]$ArgumentLine,
        [int[]]$ExpectedExitCodes = @(0),
        [int]$Timeout = $TimeoutSeconds
    )

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("blind-test-runner-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $stdoutPath = Join-Path $tempRoot "stdout.txt"
    $stderrPath = Join-Path $tempRoot "stderr.txt"
    try {
        $commandLine = "$(Quote-CmdArg $File) $ArgumentLine >$(Quote-CmdArg $stdoutPath) 2>$(Quote-CmdArg $stderrPath)"
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $psi.Arguments = "/d /s /c `"$commandLine`""
        $psi.WorkingDirectory = $Root
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $process = [System.Diagnostics.Process]::Start($psi)
        if (-not $process.WaitForExit($Timeout * 1000)) {
            try { $process.Kill() } catch {}
            throw "TIMEOUT after ${Timeout}s"
        }

        $stdout = Get-Content $stdoutPath -Raw -ErrorAction SilentlyContinue
        $stderr = Get-Content $stderrPath -Raw -ErrorAction SilentlyContinue
        $output = $stdout + $stderr
        if ($ExpectedExitCodes -notcontains $process.ExitCode) {
            throw "EXIT expected $($ExpectedExitCodes -join ',') got $($process.ExitCode)`n$output"
        }

        [pscustomobject]@{
            Name = $Name
            ExitCode = $process.ExitCode
            Output = $output
        }
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Assert-OutputContains($Result, [string]$Pattern, [string]$Message) {
    if ($Result.Output -notmatch $Pattern) {
        throw "$Message`nPattern: $Pattern`nOutput:`n$($Result.Output)"
    }
}

function Get-SourceFiles {
    Get-ChildItem -Path $Root -Recurse -File -Include *.cpp,*.h |
        Where-Object {
            $_.FullName -notmatch '\\(bin|obj|\.git)\\' -and
            $_.FullName -notmatch '\\VCXProj\\'
        } |
        Sort-Object FullName
}

function Write-HostPlatformReport {
    Write-Section "Host platform"
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    Write-Host ("os={0} version={1} build={2}" -f $os.Caption, $os.Version, $os.BuildNumber)
    Write-Host ("arch os={0} process={1} machine={2}" -f $os.OSArchitecture, $env:PROCESSOR_ARCHITECTURE, $computer.SystemType)
    Write-Host ("cpu={0} cores={1} logical={2} virtualization={3}" -f $cpu.Name, $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors, $cpu.VirtualizationFirmwareEnabled)
}

function Test-Formatting {
    if ($NoFormat) {
        Skip "clang-format dry-run" "disabled by -NoFormat"
        return
    }

    $clangFormat = Get-Command clang-format.exe -ErrorAction SilentlyContinue
    if ($null -eq $clangFormat) {
        Skip "clang-format dry-run" "clang-format.exe is not on PATH"
        return
    }

    $files = @(Get-SourceFiles)
    if ($files.Count -eq 0) {
        Skip "clang-format dry-run" "no C++ source files found"
        return
    }

    Invoke-Step "clang-format dry-run" {
        & $clangFormat.Source --dry-run --Werror -style=file @($files | ForEach-Object { $_.FullName })
        if ($LASTEXITCODE -ne 0) {
            throw "clang-format reported unformatted files"
        }
    }
}

function Invoke-CompiledVerifier {
    if ($NoVerifier) {
        Skip "compiled CLI verifier" "disabled by -NoVerifier"
        return
    }

    Invoke-Step "compiled CLI verifier" {
        $args = @("-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "verify_blind_cli.ps1"),
                  "-Configuration", $Configuration, "-TimeoutSeconds", $TimeoutSeconds, "-ProbeTarget")
        if (-not $NoBuild) {
            $args += "-Build"
        }

        & powershell.exe @args
        if ($LASTEXITCODE -ne 0) {
            throw "verify_blind_cli.ps1 failed with exit code $LASTEXITCODE"
        }
    }
}

function Test-Connectivity {
    if ($NoConnectivity) {
        Skip "connectivity smoke" "disabled by -NoConnectivity"
        return
    }

    $runner = Join-Path $Bin "BlindRunner.exe"
    $sdkHost = Join-Path $Bin "BlindSdkHost.exe"
    $target = Join-Path $Bin "BlindTestTarget.exe"
    if (-not (Test-Path $runner) -or -not (Test-Path $sdkHost) -or -not (Test-Path $target)) {
        Skip "connectivity smoke" "compiled binaries are missing under $Bin"
        return
    }

    Invoke-Step "runner pipe connectivity" {
        $r = Invoke-CapturedProcess -Name "runner pipe" -File $runner -ArgumentLine "--cli --color=never --timeout 20s $(Quote-CmdArg $target) --lhook NtQueryInformationProcess" -Timeout 30
        Assert-OutputContains $r "hook client connected" "runner did not accept a BLIND hook client connection"
        Assert-OutputContains $r "ready wait=0" "runner did not receive the ready notification"
        Assert-OutputContains $r "NtQueryInformationProcess hit" "runner did not receive the expected hook event"
        Assert-OutputContains $r "child exit=0x00000000" "runner child probe did not exit cleanly"
    }

    if ($Configuration -ne "Release") {
        Skip "SDK host pipe connectivity" "covered in Release; Debug injected child can exceed the smoke timeout"
        return
    }

    Invoke-Step "guarded launch-gate connectivity" {
        $r = Invoke-CapturedProcess -Name "guarded launch gate" -File $runner -ArgumentLine "--launch-gate --timeout 20s --color=never" -Timeout 30
        Assert-OutputContains $r "launch_gate=1 guarded=1" "guarded launch-gate mode was not enabled"
        Assert-OutputContains $r "child exit=0x00000000" "guarded launch-gate target did not exit cleanly"
    }

    Invoke-Step "SDK host pipe connectivity" {
        $pipe = "\\.\pipe\BLIND_SDK_TEST_$([Guid]::NewGuid().ToString("N"))"
        $r = Invoke-CapturedProcess -Name "sdk host" -File $sdkHost -ArgumentLine "--ready-any --pipe $(Quote-CmdArg $pipe) $(Quote-CmdArg $target) -- --cli-probe-direct" -Timeout 45
        Assert-OutputContains $r "BLIND client connected" "SDK host did not accept a BLIND client connection"
        Assert-OutputContains $r "ready wait=0" "SDK host did not receive the ready notification"
        Assert-OutputContains $r "events=[1-9]" "SDK host did not receive hook events"
        Assert-OutputContains $r "child_exit=0x00000000" "SDK host child probe did not exit cleanly"
    }
}

function Test-BinaryMitigations {
    if ($NoMitigations) {
        Skip "mitigation report" "disabled by -NoMitigations"
        return
    }

    Write-Section "Mitigation policy"
    $systemPolicy = Get-ProcessMitigation -System -ErrorAction SilentlyContinue
    if ($null -ne $systemPolicy) {
        Write-Host "[system]"
        ($systemPolicy | Format-List * | Out-String -Width 240).TrimEnd() | Write-Host
    }
    else {
        Write-Host "[system] Get-ProcessMitigation -System unavailable"
    }

    $dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
    if ($null -eq $dumpbin) {
        Skip "binary linker mitigation checks" "dumpbin.exe is not on PATH"
        return
    }

    $binaries = @(
        "BLIND.dll",
        "BlindRunner.exe",
        "BlindTestTarget.exe",
        "BlindLaunchGateTarget.exe",
        "BlindSdkHost.exe"
    ) | ForEach-Object { Join-Path $Bin $_ }

    foreach ($binary in $binaries) {
        if (-not (Test-Path $binary)) {
            Fail "mitigation headers $(Split-Path $binary -Leaf)" "missing binary: $binary"
            continue
        }

        Invoke-Step "mitigation headers $(Split-Path $binary -Leaf)" {
            $headers = & $dumpbin.Source /headers $binary 2>&1 | Out-String -Width 240
            foreach ($required in @("Dynamic base", "NX compatible")) {
                if ($headers -notmatch [regex]::Escape($required)) {
                    throw "missing linker mitigation '$required'"
                }
            }
            $hasCfg = $headers -match "Guard CF"
            $hasHighEntropy = $headers -match "High Entropy Virtual Addresses"
            Write-Host ("[mitigation] {0} aslr=1 nx=1 high_entropy_va={1} cfg={2}" -f (Split-Path $binary -Leaf), [int]$hasHighEntropy, [int]$hasCfg)
        }

        $imagePolicy = Get-ProcessMitigation -Name (Split-Path $binary -Leaf) -ErrorAction SilentlyContinue
        if ($null -ne $imagePolicy) {
            Write-Host ("[image-policy] {0}" -f (Split-Path $binary -Leaf))
            ($imagePolicy | Format-List * | Out-String -Width 180).TrimEnd() | Write-Host
        }
    }
}

Write-HostPlatformReport
Write-Section "Format"
Test-Formatting
Write-Section "Compiled tests"
Invoke-CompiledVerifier
Write-Section "Connectivity"
Test-Connectivity
Test-BinaryMitigations

Write-Host ""
Write-Host "[summary] passed=$Script:Passed failed=$Script:Failed skipped=$Script:Skipped"
if ($Script:Failed -ne 0) {
    exit 1
}
exit 0
