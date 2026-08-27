<#
.SYNOPSIS
    Windows Server HA (フェールオーバー) 切り替え検証用ハートビートスクリプト

.DESCRIPTION
    指定パス (共有ディスク上を想定) へ一定間隔で時刻情報を追記し続けます。
    両ノードで常時稼働させ、指定パスへ書き込めた側を Active、書き込めない側を
    Standby として自動的に役割を判定します。Standby 側は一切書き込みを行いません。

    共有ディスクがフェールオーバーすると、旧 Active は書き込み失敗 -> Standby に遷移し、
    新 Active は書き込み成功 -> Active に遷移します。出力 CSV のタイムスタンプ断絶を
    Analyze モードで解析することで、切り替えに要したラグを算出できます。

    ・スクリプト配置場所と出力先 (TargetPath) は独立しています。
    ・ローカルログ (役割遷移の記録) は各ノードのローカルディスクに出力されます。
      共有ディスクが見えない状態でも記録が残るため、検知タイミングの分析に使用します。

.PARAMETER Mode
    Run       : ハートビートループを実行 (タスク/サービスから呼ばれる実体)
    Install   : タスクスケジューラ (既定) または NSSM でサービス登録
    Uninstall : 登録解除
    Start     : 登録済みタスク/サービスの開始
    Stop      : 登録済みタスク/サービスの停止
    Status    : 登録状態・稼働状態・直近ログの表示
    Analyze   : 出力 CSV を解析し、フェールオーバー断絶時間を算出

.PARAMETER TargetPath
    時刻情報を書き出す CSV のフルパス。共有ディスク上を指定します。
    例: E:\hacheck\heartbeat.csv

.PARAMETER IntervalSeconds
    書き込み間隔 (秒)。既定 10。UTC エポック基準で刻みを揃えるため、
    両ノードのタイムスタンプが同一時刻に整列します。

.PARAMETER LocalLogDir
    ローカルログ出力先。既定はスクリプト配置ディレクトリ配下の logs。
    必ずローカルディスク上を指定してください (共有ディスク不可)。

.PARAMETER AccessTimeoutSeconds
    1 回の書き込み試行のタイムアウト (秒)。既定 5。
    SMB パス等で I/O がハングした場合でもこの時間で見切って Standby と判定します。

.PARAMETER GapFactor
    Analyze 時、Interval * GapFactor を超える間隔を「断絶」と判定します。既定 1.5。

.EXAMPLE
    # 両ノードで登録 (SYSTEM アカウント / OS 起動時に自動開始)
    .\HAHeartbeat.ps1 -Mode Install -TargetPath E:\hacheck\heartbeat.csv -StartNow

.EXAMPLE
    # 状態確認
    .\HAHeartbeat.ps1 -Mode Status -TargetPath E:\hacheck\heartbeat.csv

.EXAMPLE
    # 切り替えラグの解析
    .\HAHeartbeat.ps1 -Mode Analyze -TargetPath E:\hacheck\heartbeat.csv

.EXAMPLE
    # 登録解除
    .\HAHeartbeat.ps1 -Mode Uninstall

.NOTES
    要 PowerShell 5.1 以上 / Install・Uninstall は管理者権限が必要です。
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Run', 'Install', 'Uninstall', 'Start', 'Stop', 'Status', 'Analyze')]
    [string]$Mode = 'Status',

    [string]$TargetPath,

    [ValidateRange(1, 3600)]
    [int]$IntervalSeconds = 10,

    [string]$LocalLogDir = (Join-Path $PSScriptRoot 'logs'),

    [string]$TaskName = 'HAHeartbeat',

    [ValidateRange(1, 300)]
    [int]$AccessTimeoutSeconds = 5,

    # Standby 中の生存ログをこのサイクル数ごとに 1 行出力 (役割遷移は常に記録)
    [int]$StandbyLogInterval = 30,

    [double]$GapFactor = 1.5,

    # Install 用
    [string]$RunAsUser = 'SYSTEM',
    [string]$RunAsPassword,
    [switch]$StartNow,

    # NSSM を使って「本物の Windows サービス」として登録する場合
    [switch]$UseNssm,
    [string]$NssmPath = 'C:\nssm\nssm.exe',
    [string]$ServiceName = 'HAHeartbeat'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CsvHeader   = 'TimestampUtc,TimestampLocal,ComputerName,Sequence,ProcessId,WriteMs'
$script:LocalLogFile = $null
$script:PendingRunspaces = New-Object System.Collections.ArrayList

#--------------------------------------------------------------------------
# 共通ヘルパ
#--------------------------------------------------------------------------

function Initialize-LocalLog {
    param([string]$Dir)

    if (-not (Test-Path -LiteralPath $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
    $name = '{0}_{1}_{2}.log' -f 'HAHeartbeat', $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd')
    $script:LocalLogFile = Join-Path $Dir $name
}

function Write-LocalLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'EVENT')][string]$Level = 'INFO'
    )

    $tab  = [char]9
    $line = ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'),
             [DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss.fff'),
             $Level,
             $env:COMPUTERNAME,
             $Message) -join $tab

    if ($script:LocalLogFile) {
        try {
            # BOM 付き UTF-8。BOM はファイル新規作成時のみ書き込まれるため追記は安全。
            # BOM を付けることで Get-Content / メモ帳 / Excel から文字化けせず読める。
            [System.IO.File]::AppendAllText(
                $script:LocalLogFile,
                $line + [Environment]::NewLine,
                (New-Object System.Text.UTF8Encoding($true)))
        }
        catch {
            # ローカルログにすら書けない場合は握りつぶして継続 (計測を止めない)
        }
    }

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'EVENT' { Write-Host $line -ForegroundColor Cyan }
        default { Write-Host $line }
    }
}

function Test-Administrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw '管理者権限が必要です。PowerShell を「管理者として実行」で起動し直してください。'
    }
}

function Assert-TargetPath {
    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        throw '-TargetPath が指定されていません。例: -TargetPath E:\hacheck\heartbeat.csv'
    }
    if (-not [System.IO.Path]::IsPathRooted($TargetPath)) {
        throw '-TargetPath は絶対パスで指定してください。'
    }
}

function Remove-CompletedRunspaces {
    $done = @($script:PendingRunspaces | Where-Object {
            $_.Handle.IsCompleted -or $_.Shell.InvocationStateInfo.State -ne 'Running'
        })
    foreach ($p in $done) {
        try { $p.Shell.Dispose() } catch { }
        $script:PendingRunspaces.Remove($p) | Out-Null
    }
}

#--------------------------------------------------------------------------
# 書き込み (タイムアウト付き)
#   別ランスペースで実行し、I/O ハング時も AccessTimeoutSeconds で見切る。
#   この書き込み試行そのものがアクセス可否判定 = Active/Standby 判定になる。
#--------------------------------------------------------------------------

function Invoke-TimedWrite {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string]$Header,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $worker = {
        param($p, $l, $h)

        $dir = [System.IO.Path]::GetDirectoryName($p)
        if (-not [System.IO.Directory]::Exists($dir)) {
            throw "出力先ディレクトリにアクセスできません: $dir"
        }

        $enc = New-Object System.Text.UTF8Encoding($false)

        if (-not [System.IO.File]::Exists($p)) {
            try {
                $fs0 = [System.IO.File]::Open($p,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::Read)
                $sw0 = New-Object System.IO.StreamWriter($fs0, $enc)
                $sw0.WriteLine($h)
                $sw0.Flush()
                $sw0.Dispose()
            }
            catch [System.IO.IOException] {
                # 同時生成の競合は無視して追記へ
            }
        }

        # FileShare.Read: 他ノード/他プロセスからの同時書き込みを排除しつつ参照は許可
        $fs = [System.IO.File]::Open($p,
            [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read)
        try {
            $sw = New-Object System.IO.StreamWriter($fs, $enc)
            $sw.WriteLine($l)
            $sw.Flush()
            $sw.Dispose()
        }
        finally {
            $fs.Dispose()
        }
    }

    $result = [pscustomobject]@{ Success = $false; TimedOut = $false; Error = $null }

    $shell = [PowerShell]::Create()
    $null = $shell.AddScript($worker).AddArgument($Path).AddArgument($Line).AddArgument($Header)
    $handle = $shell.BeginInvoke()

    if ($handle.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        try {
            $null = $shell.EndInvoke($handle)
            $result.Success = $true
        }
        catch {
            $result.Error = $_.Exception.Message
        }
        finally {
            try { $shell.Dispose() } catch { }
        }
    }
    else {
        $result.TimedOut = $true
        $result.Error = "書き込みタイムアウト ({0} 秒)" -f $TimeoutSeconds
        try { $null = $shell.BeginStop($null, $null) } catch { }
        # Dispose がブロックしうるため保留リストへ回し、後続サイクルで回収
        $null = $script:PendingRunspaces.Add([pscustomobject]@{ Shell = $shell; Handle = $handle })
    }

    return $result
}

#--------------------------------------------------------------------------
# Run: ハートビートループ
#--------------------------------------------------------------------------

function Invoke-RunMode {
    Assert-TargetPath
    Initialize-LocalLog -Dir $LocalLogDir

    $pid_ = $PID
    Write-LocalLog -Level 'EVENT' -Message ("SCRIPT START pid={0} target='{1}' interval={2}s timeout={3}s script='{4}'" -f `
            $pid_, $TargetPath, $IntervalSeconds, $AccessTimeoutSeconds, $PSCommandPath)

    $role            = 'Unknown'
    $seq             = 0
    $standbyCycles   = 0
    $consecFailures  = 0
    $lastActiveUtc   = $null
    $roleSinceUtc    = [DateTime]::UtcNow
    $intervalTicks   = [TimeSpan]::FromSeconds($IntervalSeconds).Ticks

    while ($true) {
        # UTC エポック基準で刻みを整列 (全ノードが同一時刻に打刻される)
        $nowTicks  = [DateTime]::UtcNow.Ticks
        $nextTicks = ([long][math]::Floor($nowTicks / $intervalTicks) + 1) * $intervalTicks
        $waitMs    = [int]([TimeSpan]::FromTicks($nextTicks - $nowTicks).TotalMilliseconds)
        if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }

        Remove-CompletedRunspaces

        $seq++
        $utcNow   = [DateTime]::UtcNow
        $localNow = [DateTime]::Now

        $line = '{0},{1},{2},{3},{4},{5}' -f `
            $utcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'),
            $localNow.ToString('yyyy-MM-ddTHH:mm:ss.fff'),
            $env:COMPUTERNAME,
            $seq,
            $pid_,
            0

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $res = Invoke-TimedWrite -Path $TargetPath -Line $line -Header $script:CsvHeader `
            -TimeoutSeconds $AccessTimeoutSeconds
        $sw.Stop()

        if ($res.Success) {
            #---------------- Active ----------------
            if ($role -ne 'Active') {
                $prev = $role
                $downSec = if ($lastActiveUtc) {
                    [math]::Round(($utcNow - $lastActiveUtc).TotalSeconds, 3)
                } else { $null }
                $heldSec = [math]::Round(($utcNow - $roleSinceUtc).TotalSeconds, 3)

                Write-LocalLog -Level 'EVENT' -Message (
                    "ROLE CHANGE {0} -> ACTIVE : seq={1} 直前役割の継続={2}s 自ノード無書込期間={3}s" -f `
                        $prev, $seq, $heldSec, $(if ($null -ne $downSec) { $downSec } else { 'n/a' }))

                $role          = 'Active'
                $roleSinceUtc  = $utcNow
                $consecFailures = 0
                $standbyCycles  = 0
            }
            $lastActiveUtc = $utcNow
        }
        else {
            #---------------- Standby ----------------
            $consecFailures++
            if ($role -ne 'Standby') {
                $prev = $role
                $heldSec = [math]::Round(($utcNow - $roleSinceUtc).TotalSeconds, 3)

                Write-LocalLog -Level 'EVENT' -Message (
                    "ROLE CHANGE {0} -> STANDBY : seq={1} 直前役割の継続={2}s 理由='{3}'{4}" -f `
                        $prev, $seq, $heldSec, $res.Error,
                        $(if ($res.TimedOut) { ' (TIMEOUT)' } else { '' }))

                $role         = 'Standby'
                $roleSinceUtc = $utcNow
                $standbyCycles = 0
            }

            $standbyCycles++
            if ($StandbyLogInterval -gt 0 -and ($standbyCycles % $StandbyLogInterval) -eq 0) {
                Write-LocalLog -Level 'INFO' -Message (
                    "STANDBY 継続中 seq={0} 連続失敗={1} 経過={2}s (書き込みは行っていません)" -f `
                        $seq, $consecFailures,
                        [math]::Round(($utcNow - $roleSinceUtc).TotalSeconds, 1))
            }
        }
    }
}

#--------------------------------------------------------------------------
# Install / Uninstall / Start / Stop
#--------------------------------------------------------------------------

function Get-RunArgumentString {
    $scriptPath = $PSCommandPath
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden')
    $null = $sb.Append(' -File "').Append($scriptPath).Append('"')
    $null = $sb.Append(' -Mode Run')
    $null = $sb.Append(' -TargetPath "').Append($TargetPath).Append('"')
    $null = $sb.Append(' -IntervalSeconds ').Append($IntervalSeconds)
    $null = $sb.Append(' -LocalLogDir "').Append($LocalLogDir).Append('"')
    $null = $sb.Append(' -AccessTimeoutSeconds ').Append($AccessTimeoutSeconds)
    $null = $sb.Append(' -StandbyLogInterval ').Append($StandbyLogInterval)
    $sb.ToString()
}

function Get-PowerShellExePath {
    Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

function Install-Heartbeat {
    Assert-Administrator
    Assert-TargetPath

    $psExe   = Get-PowerShellExePath
    $argStr  = Get-RunArgumentString

    if (-not (Test-Path -LiteralPath $LocalLogDir)) {
        New-Item -ItemType Directory -Path $LocalLogDir -Force | Out-Null
    }

    if ($UseNssm) {
        if (-not (Test-Path -LiteralPath $NssmPath)) {
            throw "NSSM が見つかりません: $NssmPath  (-NssmPath で指定してください)"
        }

        & $NssmPath install $ServiceName $psExe $argStr | Out-Null
        & $NssmPath set $ServiceName DisplayName    "HA Heartbeat Writer" | Out-Null
        & $NssmPath set $ServiceName Description    "HA 切り替え検証用ハートビート (指定パスへ ${IntervalSeconds} 秒間隔で打刻)" | Out-Null
        & $NssmPath set $ServiceName Start          SERVICE_AUTO_START | Out-Null
        & $NssmPath set $ServiceName AppExit Default Restart | Out-Null
        & $NssmPath set $ServiceName AppRestartDelay 5000 | Out-Null
        & $NssmPath set $ServiceName AppStdout (Join-Path $LocalLogDir 'service_stdout.log') | Out-Null
        & $NssmPath set $ServiceName AppStderr (Join-Path $LocalLogDir 'service_stderr.log') | Out-Null

        Write-Host "サービス '$ServiceName' を登録しました (NSSM / 自動起動)。" -ForegroundColor Green
        if ($StartNow) {
            Start-Service -Name $ServiceName
            Write-Host "サービスを開始しました。" -ForegroundColor Green
        }
        return
    }

    # --- 既定: タスクスケジューラ ---
    # PowerShell スクリプトを sc.exe で直接サービス登録すると SCM に応答を返せず
    # エラー 1053 で起動失敗するため、標準機能で確実に常駐できるタスクを使用する。

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "既存タスク '$TaskName' を上書きします。" -ForegroundColor Yellow
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
    }

    $action = New-ScheduledTaskAction -Execute $psExe -Argument $argStr

    $triggers = @(
        (New-ScheduledTaskTrigger -AtStartup)
    )

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    if ($RunAsUser -eq 'SYSTEM' -or $RunAsUser -eq 'NT AUTHORITY\SYSTEM') {
        $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' `
            -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
            -Settings $settings -Principal $principal `
            -Description 'HA 切り替え検証用ハートビート (Active 側のみ指定パスへ打刻)' `
            -Force | Out-Null
    }
    elseif ($RunAsPassword) {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
            -Settings $settings -User $RunAsUser -Password $RunAsPassword -RunLevel Highest `
            -Description 'HA 切り替え検証用ハートビート (Active 側のみ指定パスへ打刻)' `
            -Force | Out-Null
    }
    else {
        throw "-RunAsUser に SYSTEM 以外を指定する場合は -RunAsPassword も指定してください。"
    }

    Write-Host "タスク '$TaskName' を登録しました (OS 起動時に自動開始 / 実行アカウント: $RunAsUser)。" -ForegroundColor Green
    Write-Host "  出力先        : $TargetPath"
    Write-Host "  間隔          : ${IntervalSeconds} 秒"
    Write-Host "  ローカルログ  : $LocalLogDir"

    if ($StartNow) {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "タスクを開始しました。" -ForegroundColor Green
    }
    else {
        Write-Host "今すぐ開始する場合: .\HAHeartbeat.ps1 -Mode Start" -ForegroundColor Cyan
    }
}

function Uninstall-Heartbeat {
    Assert-Administrator
    $removed = $false

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        if ((Test-Path -LiteralPath $NssmPath)) {
            & $NssmPath remove $ServiceName confirm | Out-Null
        }
        else {
            & sc.exe delete $ServiceName | Out-Null
        }
        Write-Host "サービス '$ServiceName' を削除しました。" -ForegroundColor Green
        $removed = $true
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "タスク '$TaskName' を登録解除しました。" -ForegroundColor Green
        $removed = $true
    }

    if (-not $removed) {
        Write-Host "登録済みのタスク/サービスは見つかりませんでした。" -ForegroundColor Yellow
    }
}

function Start-Heartbeat {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) { Start-Service -Name $ServiceName; Write-Host "サービスを開始しました。" -ForegroundColor Green; return }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) { Start-ScheduledTask -TaskName $TaskName; Write-Host "タスクを開始しました。" -ForegroundColor Green; return }

    throw "登録済みのタスク/サービスが見つかりません。先に -Mode Install を実行してください。"
}

function Stop-Heartbeat {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) { Stop-Service -Name $ServiceName -Force; Write-Host "サービスを停止しました。" -ForegroundColor Green; return }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) { Stop-ScheduledTask -TaskName $TaskName; Write-Host "タスクを停止しました。" -ForegroundColor Green; return }

    throw "登録済みのタスク/サービスが見つかりません。"
}

#--------------------------------------------------------------------------
# Status
#--------------------------------------------------------------------------

function Show-Status {
    Write-Host "===== ノード: $env:COMPUTERNAME =====" -ForegroundColor Cyan

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "[サービス] $ServiceName : $($svc.Status) / スタートアップ=$($svc.StartType)"
    }

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host "[タスク] $TaskName : $($task.State)"
        Write-Host "  前回実行 : $($info.LastRunTime)  (結果コード: $($info.LastTaskResult))"
        Write-Host "  実行内容 : $($task.Actions[0].Execute) $($task.Actions[0].Arguments)"
    }
    if (-not $svc -and -not $task) {
        Write-Host "[登録] 未登録です。" -ForegroundColor Yellow
    }

    if ($TargetPath) {
        Write-Host ""
        Write-Host "[出力先] $TargetPath"
        $dir = [System.IO.Path]::GetDirectoryName($TargetPath)
        if ([System.IO.Directory]::Exists($dir)) {
            Write-Host "  ディレクトリ : アクセス可 -> このノードは ACTIVE 想定" -ForegroundColor Green
            if (Test-Path -LiteralPath $TargetPath) {
                $last = Get-Content -LiteralPath $TargetPath -Tail 5 -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Host "  --- 直近 5 行 ---"
                $last | ForEach-Object { Write-Host "  $_" }
            }
        }
        else {
            Write-Host "  ディレクトリ : アクセス不可 -> このノードは STANDBY 想定" -ForegroundColor Yellow
        }
    }

    $logDir = $LocalLogDir
    if (Test-Path -LiteralPath $logDir) {
        $latest = Get-ChildItem -LiteralPath $logDir -Filter 'HAHeartbeat_*.log' |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            Write-Host ""
            Write-Host "[ローカルログ] $($latest.FullName)"
            Write-Host "  --- 直近の役割遷移 (EVENT) ---"
            Get-Content -LiteralPath $latest.FullName -Encoding UTF8 |
                Where-Object { $_ -match "`tEVENT`t" } |
                Select-Object -Last 10 |
                ForEach-Object { Write-Host "  $_" -ForegroundColor Cyan }
        }
    }
}

#--------------------------------------------------------------------------
# Analyze: 切り替えラグの算出
#--------------------------------------------------------------------------

function Invoke-Analyze {
    Assert-TargetPath

    if (-not (Test-Path -LiteralPath $TargetPath)) {
        throw "出力ファイルが見つかりません (このノードから共有ディスクが見えていない可能性): $TargetPath"
    }

    $rows = @(Import-Csv -LiteralPath $TargetPath -Encoding UTF8 | ForEach-Object {
            [pscustomobject]@{
                Utc      = [datetime]::ParseExact($_.TimestampUtc, 'yyyy-MM-ddTHH:mm:ss.fffZ',
                            [cultureinfo]::InvariantCulture,
                            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                            [System.Globalization.DateTimeStyles]::AssumeUniversal)
                Local    = $_.TimestampLocal
                Node     = $_.ComputerName
                Sequence = [int]$_.Sequence
                Pid      = $_.ProcessId
            }
        })
    $rows = @($rows | Sort-Object Utc)

    if ($rows.Count -lt 2) {
        Write-Host "解析可能なレコードが不足しています (件数: $($rows.Count))。" -ForegroundColor Yellow
        return
    }

    $threshold = $IntervalSeconds * $GapFactor

    Write-Host "===== ハートビート解析 =====" -ForegroundColor Cyan
    Write-Host "対象ファイル : $TargetPath"
    Write-Host "レコード数   : $($rows.Count)"
    Write-Host "期間 (UTC)   : $($rows[0].Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')) - $($rows[-1].Utc.ToString('yyyy-MM-dd HH:mm:ss.fff'))"
    Write-Host "書込間隔     : ${IntervalSeconds} 秒 / 断絶判定閾値: ${threshold} 秒"
    Write-Host ""

    $events = New-Object System.Collections.ArrayList

    for ($i = 1; $i -lt $rows.Count; $i++) {
        $prev = $rows[$i - 1]
        $cur  = $rows[$i]
        $gap  = ($cur.Utc - $prev.Utc).TotalSeconds
        $nodeChanged = ($prev.Node -ne $cur.Node)

        if ($gap -gt $threshold -or $nodeChanged) {
            $kind = if ($nodeChanged -and $gap -gt $threshold) { 'FAILOVER' }
                    elseif ($nodeChanged)                      { 'NODE-SWITCH (無断絶)' }
                    else                                       { 'GAP (同一ノード)' }

            $null = $events.Add([pscustomobject]@{
                    Type          = $kind
                    LastWriteUtc  = $prev.Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    LastNode      = $prev.Node
                    NextWriteUtc  = $cur.Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    NextNode      = $cur.Node
                    GapSeconds    = [math]::Round($gap, 3)
                    LostBeats     = [math]::Max(0, [int][math]::Round($gap / $IntervalSeconds) - 1)
                })
        }
    }

    if ($events.Count -eq 0) {
        Write-Host "断絶・ノード切り替わりは検出されませんでした。" -ForegroundColor Green
    }
    else {
        Write-Host "--- 検出イベント ---" -ForegroundColor Yellow
        $events | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

        $failovers = @($events | Where-Object { $_.Type -like 'FAILOVER*' })
        if ($failovers.Count -gt 0) {
            $gaps = $failovers | ForEach-Object { $_.GapSeconds }
            $measured = $gaps | Measure-Object -Average -Maximum -Minimum
            Write-Host "--- フェールオーバー サマリ ---" -ForegroundColor Cyan
            Write-Host ("  発生回数        : {0} 回" -f $failovers.Count)
            Write-Host ("  最大断絶時間    : {0} 秒" -f [math]::Round($measured.Maximum, 3))
            Write-Host ("  最小断絶時間    : {0} 秒" -f [math]::Round($measured.Minimum, 3))
            Write-Host ("  平均断絶時間    : {0} 秒" -f [math]::Round($measured.Average, 3))
            Write-Host ""
            Write-Host ("  ※ 断絶時間には最大 {0} 秒の書込間隔による誤差が含まれます。" -f $IntervalSeconds) -ForegroundColor DarkGray
            Write-Host "     より正確な検知時刻は各ノードのローカルログの ROLE CHANGE 行を参照してください。" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    Write-Host "--- ノード別 書き込み区間 ---" -ForegroundColor Cyan
    $segments = New-Object System.Collections.ArrayList
    $segStart = $rows[0]
    for ($i = 1; $i -lt $rows.Count; $i++) {
        if ($rows[$i].Node -ne $rows[$i - 1].Node) {
            $null = $segments.Add([pscustomobject]@{
                    Node          = $segStart.Node
                    FromUtc       = $segStart.Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    ToUtc         = $rows[$i - 1].Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    DurationSec   = [math]::Round(($rows[$i - 1].Utc - $segStart.Utc).TotalSeconds, 1)
                })
            $segStart = $rows[$i]
        }
    }
    $null = $segments.Add([pscustomobject]@{
            Node        = $segStart.Node
            FromUtc     = $segStart.Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
            ToUtc       = $rows[-1].Utc.ToString('yyyy-MM-dd HH:mm:ss.fff')
            DurationSec = [math]::Round(($rows[-1].Utc - $segStart.Utc).TotalSeconds, 1)
        })
    $segments | Select-Object Node, FromUtc, ToUtc, DurationSec |
        Format-Table -AutoSize | Out-String -Width 200 | Write-Host
}

#--------------------------------------------------------------------------
# エントリポイント
#--------------------------------------------------------------------------

switch ($Mode) {
    'Run'       { Invoke-RunMode }
    'Install'   { Install-Heartbeat }
    'Uninstall' { Uninstall-Heartbeat }
    'Start'     { Start-Heartbeat }
    'Stop'      { Stop-Heartbeat }
    'Status'    { Show-Status }
    'Analyze'   { Invoke-Analyze }
}
