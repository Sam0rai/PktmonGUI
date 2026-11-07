# PktmonGUI headless / remote mode

## Context

PktmonGUI is a portable WPF exe for pktmon: .NET 4.7.2, one file through Costura, `WinExe`, x64, manifest set to `requireAdministrator`. The goal is to copy it to a remote host (GPO, SCCM, WinRM, SMB/PsExec) and run it with flags and no UI: record a capture, attribute packets to processes, convert to pcapng, and hand back one zip.

The service layer (`Services/`, `Pktmon/`, `Pcap/`, `Attribution/`, `Parsing/`, `Model/`) is already free of WPF. What depends on the UI is the orchestration around it: building options (`CaptureViewModel.BuildOptions`), preflight (`PreflightViewModel`), and conversion from .etl to pcapng (`FilesViewModel.RunPlanAsync`).

**User decisions:**
- **Lifecycle:** one resident process. It ends on `--duration`, on a later `--stop`, or on Ctrl+C, and `--detach` lets it outlive a WinRM shell or a GPO script timeout. Attribution stays on.
- **Output:** record locally, zip to `<HOST>-<ts>.zip`, then optionally `--collect` to a share.
- **Console:** keep one GUI-subsystem exe. Write a run log, `result.json` and a documented exit code, and write to stdout when it is available.
- **Extras:** a `--cleanup` action and `tools/Invoke-RemotePktmon.ps1` for fanning out over WinRM. etl2txt is out of scope.

**Headless records in Record mode only.** Live mode fills `CaptureSession.Incoming` and `AttributionEngine._pending`, and only the UI pump drains them. Record mode never calls `Observe`.

## CLI surface (`Headless/Usage.cs` holds the exact text)

```
PktmonGUI.exe [--capture] <options>          record a capture (implied by any capture option)
PktmonGUI.exe --stop [--timeout 15m]         stop the headless capture, wait for its result
PktmonGUI.exe --status                       running capture, last result, leftovers
PktmonGUI.exe --cleanup [--force] [--purge]  stop leftovers and restore the machine's filters
PktmonGUI.exe --list-adapters                what --comp can select
PktmonGUI.exe --help | --version
PktmonGUI.exe                                GUI (interactive sessions only)

--duration <90s|10m|2h|1h30m|hh:mm:ss|0>   default: until --stop/Ctrl+C (24h cap with --detach)
--comp nics|default|<id|MAC|name/description substring or wildcard>[,...]   default: nics
--filter "<pktmon filter add args>"  (repeatable)   --preset <dns|rdp|smb|ldap-kerberos|tcp-syn|tcp-rst|icmp|cdp-lldp|arp|dhcp|https> (repeatable)
--filters-file <json>   --keep-filters   --pkt-size <bytes, 0=full>   --type all|flow|drop
--file-size <MB, default 512>   --log-mode circular|multi-file   --no-attribution   --no-pcap
--out <local folder, default %ProgramData%\PktmonGUI\runs>   --collect <folder|\\srv\share>   --keep-local
--log <file>   --detach   --force   --timeout <time>   --json   --quiet
hidden: --detached-child --run-folder <path>   (used by --detach)   --dump-etw ... (existing fixture mode)
```

**Parsing and defaults:**
- Flags are case-insensitive, and `--flag=value` works too.
- The value after `--filter` is always taken verbatim, even when it starts with `-`.
- An unknown flag, or a conflict, prints the usage and exits 2. It never falls back to the GUI.
- **`--comp nics` is the default.** Choosing a single NIC can silently miss traffic on cluster or storage networks. Hyper-V duplicates are documented.
- **With no user filters and foreign filters present** (for example Defender's `SenseNdr*`), the default is to snapshot, clear, and restore at the end. `--keep-filters` opts out, and combining it with rules is a usage error.
- **Rule names** get the prefix `PktmonGUI <name|n>`, so `OwnerGuess` (`Services/SnapshotService.cs:134`) can identify leftovers.
- **`--keep-local` is off by default:**
  - The unzipped run folder is deleted once the zip is verified.
  - The local zip is deleted once a collect is verified.
  - Nothing is deleted without a verified copy.
- **`--force`** stops a foreign or orphaned pktmon session. It never overrides a live headless run.

### Exit codes (`Headless/ExitCodes.cs`, precedence 8 > 1 > 5 > 6 > 0)

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | failed |
| 2 | usage |
| 3 | unsupported: not elevated, build < 19041, no pktmon, access denied, disk |
| 4 | busy: a live headless run, or pktmon is running and `--force` wasn't given |
| 5 | collect failed (zip kept) |
| 6 | done with warnings: conversion failed (.etl kept), pktmon ended externally, low disk, filters changed during the capture |
| 7 | nothing to stop / leftovers found |
| 8 | machine not restored (run `--cleanup`) |
| 9 | timed out waiting |

A caller that isn't elevated gets Win32 error 740 from `CreateProcess`, because of the manifest; document this.

## Entry point

- **New `src/PktmonGUI/Program.cs`,** plus `<StartupObject>PktmonGUI.Program</StartupObject>` in the csproj:
  - `[STAThread] static int Main(args)` handles, in order: `--dump-etw` (moved verbatim from `App.xaml.cs:22-34`); any arguments, which go to `Headless.HeadlessProgram.Run`; no arguments while `!Environment.UserInteractive`, which prints the usage and exits 2; otherwise `new App(); InitializeComponent(); Run()`.
  - Each branch is a `[MethodImpl(NoInlining)]` trampoline, so the headless path never loads PresentationFramework. Costura's module initializer still runs first.
- **csproj:** add framework references `System.Management`, `System.IO.Compression` and `System.IO.Compression.FileSystem`. These come from the GAC and are not embedded.
- **`App.xaml.cs`:** delete the `--dump-etw` block. `tools/Capture-*Fixture.ps1` and `Spike-PktMonProvider.ps1` keep working unchanged.
- **`HeadlessProgram.Run`:**
  1. Registers its own handlers for `AppDomain.UnhandledException` and `UnobservedTaskException`.
  2. Runs the body with `Task.Run(...).GetAwaiter().GetResult()`, so pool threads have a null SynchronizationContext.
  3. Holds the mutex on the main thread.
  4. Ends with `Environment.Exit(code)`.

## Capture lifecycle (`Headless/CaptureCommand.cs`)

**State root: `%ProgramData%\PktmonGUI\`.** It holds `headless.json` (state), `cli-settings.json`, `snapshots\`, `runs\`, `bin\` and `cli.log`. The folder is the same for SYSTEM, every admin and WinRM, and it is local even when the exe runs from UNC.
- Create it with a protected DACL: SYSTEM and Administrators get full control.
- If it exists as a reparse point, or belongs to a foreign owner, exit 3.

Steps:
1. **Parse** (exit 2) and set up console output.
2. **Check the machine** with `SystemChecks`: admin rights, OS build ≥ 19041, and `PktmonRunner.PktmonExists` (`Pktmon/PktmonRunner.cs:66`). Failure exits 3.
3. **Take the mutex** `Global\PktmonGUI-Headless` with an explicit ACL, using `WaitOne(0)`. If it's held, exit 4. An `AbandonedMutexException` is logged and the run continues.
4. **Create the run folder** `<out>\<HOST>-<yyyyMMdd-HHmmss>\`, or use `--run-folder` from a detach parent.
   - Open the `RunLog` and write `result.json` with status Starting.
   - If `headless.json` shows a non-terminal phase and its process is dead (checked by PID and start time), run `CleanupCommand.RecoverAsync(adopt: true)` first.
   - Then write the new state: pid, start time, user, command line, run folder, `Phase=Starting`.
5. **Build services** with `new AppServices(null, new SettingsStore(dataFolder, "cli-settings.json"), runFolder)`. This uses the new overloads, and the GUI's `settings.json` is never touched. Call `RunLog.Attach(services.Log)`.
6. **Check `pktmon status`** via `StatusParser.Parse` (`Parsing/StatusParser.cs`).
   - A session whose log file is under our runs folder and has no live owner is orphaned: stop it.
   - Stop any other session only with `--force`; otherwise exit 4.
   - Stop leftover ETW sessions (`PktmonGUI-Attribution`, `PktmonGUI-Packets`) unless another `PktmonGUI.exe` is running.
7. **Check free disk space.** Below file-size + 1 GB, exit 3; below 3 × file-size, warn. If `--collect` is set, probe the share with a write and delete (a failure is a warning).
8. **Resolve components** with `ComponentResolver.LoadAsync(true)` (`Services/ComponentResolver.cs:28`) and `ComponentSelector.Resolve(...)`. `default` means `PickDefaults(new string[0])` (line 101). Write `components.txt`, and warn if an adapter is Wi-Fi.
9. **Apply filters.**
   - Write `filters-before.txt` from `Filters.ReadAsync()`.
   - Rules given: `Filters.ApplyAsync(rules, true, true)` (`Services/FilterService.cs:68`).
   - No rules but filters exist: `ClearAsync(true, true)`.
   - `--keep-filters`: `ruleSet` is the machine's own rules, as in `CaptureViewModel.cs:536`.
   - The snapshot is saved before anything is cleared.
10. **Build `CaptureOptions`:** `Mode=Record`, `AllNics` or `ComponentIds`, `Type`, `PacketSize`, `FileName=<runFolder>\<run>.etl`, `FileSizeMb`, `LogMode`. Then call `Validate()`.
11. **Start** with `Session.StartAsync(options, Components.All, ruleSet, attributeProcesses: !NoAttribution)` (`Services/CaptureSession.cs:74`). On failure, restore filters, write the result and exit 1. On success, set `Phase=Running` and `StopAtUtc`, and print "Recording…; stop with PktmonGUI.exe --stop".
12. **Wait** (`Headless/StopSignals.cs`) for the first `StopReason` among:
    - `Task.Delay(duration)`;
    - the `Global\PktmonGUI-Headless-Stop` event, which has an explicit ACL so an admin can `Set()` it when SYSTEM created it;
    - Ctrl+C or Ctrl+Break, through `SetConsoleCtrlHandler`. A second press takes the fast path.
    - CLOSE or SHUTDOWN, which takes the fast path within about 5 s. LOGOFF is ignored.
    - a check every 15 s: `pktmon status` (`log:false`) shows the session gone or not ours (reason: PktmonEndedExternally), or free space is under 1 GB (reason: LowDisk);
    - a check every 60 s: `filter list` differs from what we applied. This only warns.
13. **Stop.**
    - While the session is still up, save `pktmon counters --drop-reason` to `counters.txt` and `--json` to `counters.json`.
    - Then `etl = await Session.StopAsync("headless: "+reason)`. This saves `.meta.json` and `.attribution.json`.
14. **Restore the machine before the slow work:** `services.RestoreMachineFiltersAsync()` (new). A failure means exit 8. On the fast path, stop here: `result.json` gets status Interrupted and the `.etl` is kept.
15. **Convert,** unless `--no-pcap:` for each `*.etl` in the run folder (so multi-file captures are covered), call `EtlConverter.ToPcapngAsync(runner, etl, <etl>.pcapng, AttributionSnapshot.PathFor(etl))`. A failure means exit 6 and the .etl is kept.
16. **Write `result.json`** (`Headless/RunResult.cs`). It holds:
    - status, exit code, host, user, times and stop reason;
    - the start command line, components, and filters (mode, snapshot, restored);
    - files, packet and drop counts, `CommentResult`, attribution stats (ETW lost/error, flows evicted);
    - warnings and errors.
17. **Zip.**
    - `ZipFile.CreateFromDirectory(runFolder, <out>\<run>.zip.partial, Optimal, includeBaseDirectory:true)`, then rename it and verify with `OpenRead` (entry count and SHA-256).
    - Delete the folder unless `--keep-local`.
    - The run log is opened, appended to and closed on every write, so it never blocks the zip. After zipping it switches to `cli.log`.
18. **Collect.**
    - Copy to `<dest>\<run>.zip.partial`, rename (adding `-2` if the name is taken), and verify the length. Try 3 times, 5/15/30 s apart.
    - If access is denied, add a hint: as SYSTEM, grant the computer account on the share; from a network logon token (S-1-5-2), it is a double hop, so pull with `Copy-Item -FromSession`.
    - A failure means exit 5 and the local zip is kept.
19. **Finish:** set `Phase=Finished` and `LastResult`, print a summary (or JSON), release the mutex, and exit with `Worst(...)`.

**Crash safety:**
- `try/finally` wraps steps 11–18, so the restore (14) and `result.json` (16) always happen.
- The headless `UnhandledException` handler calls `EmergencyStop()`, capped at 20 s: `pktmon stop`, stop attribution, restore filters, and write result `Crashed`.
- After a hard kill, the non-terminal `headless.json` and the unrestored snapshot act as the marker. The next run, `--status` (exit 7) or `--cleanup` recovers.

## Other actions

- **`--detach`** (`Headless/Detacher.cs`):
  1. **Parent checks:** it does the full parse and the checks behind exit codes 2 and 3, plus a quick busy check that exits 4.
  2. **The parent names the run folder itself,** so it knows where results will land.
  3. **Local copy of the exe:** if the exe isn't on a local fixed drive (UNC, SYSVOL), it is copied to `%ProgramData%\PktmonGUI\bin\`. The copy is skipped when the hash matches. If that file is in use, the copy gets a timestamped name.
  4. **Child arguments:** `BuildChildArgs` is pure. It removes `--detach`/`--timeout`, adds `--detached-child --run-folder <p>`, and quotes with `PktmonCommand.QuoteArg`.
  5. **Launch:**
     - **Primary:** WMI `Win32_Process.Create` (System.Management). The child is outside the caller's job and keeps the same identity. `ShowWindow=0`.
     - **Fallback:** `CreateProcessW(bInheritHandles:FALSE, CREATE_BREAKAWAY_FROM_JOB|CREATE_NEW_PROCESS_GROUP|CREATE_NO_WINDOW)`. Handles must not be inherited, or a remote pipeline would hang on stdout.
     - **Both fail while `IsProcessInJob`:** exit 1 with guidance.
  6. **Waiting for the child:** poll `headless.json` for `Pid==child && Phase==Running` (exit 0; print PID, run folder, stop time and zip). If the child exits first, take its exit code. On timeout, exit 9.
  7. **Child behavior:** the child never touches the console or stdout. With no `--duration`, it defaults to 24h.
- **`--stop`** (`StopCommand.cs`):
  1. Open the stop event with `TryOpenExisting`. If it's missing, report the last result or a dead owner and exit 7.
  2. Otherwise `Set()` it, then wait on the PID (checking name and start time), falling back to polling `Phase`.
  3. Exit with `LastResult.ExitCode`, or 9 on timeout.
- **`--status`** (`StatusCommand.cs`) reports:
  - the headless run: phase, PID, run folder, elapsed time, .etl size;
  - `pktmon status`, and whether the session is ours;
  - leftover ETW sessions, unrestored snapshots, our own filters still on the machine, and stale state;
  - the last result and recent zips.

  Exit 0 when idle and clean, 4 while running, 7 when leftovers exist.
- **`--cleanup`** (`CleanupCommand.cs`, which also exposes `RecoverAsync`). It exits 4 if a live owner exists. Otherwise:
  1. `pktmon stop`, only if the session is ours, or with `--force`.
  2. Stop the leftover ETW sessions.
  3. Restore the newest unrestored snapshot, but only if the current filters are empty or ours. If foreign filters were re-added, report it (exit 8), or restore with `--force`. Dismiss older snapshots.
  4. If nothing was restored, remove our own filters.
  5. Clear the applied marker in `cli-settings.json`.
  6. With `--purge`, delete `runs\*` and stale `bin\` copies.

  It exits 0, 4 or 8. GUI snapshots live beside the GUI exe and are out of reach; document this.
- **`--list-adapters`:** a table of id, connection name, name, MAC, IPv4, link and Wi-Fi status, plus what `default` would pick.

## Console output (`Headless/ConsoleOutput.cs`, `Headless/HeadlessNative.cs`)

The P/Invokes needed: `AttachConsole(-1)`, `GetStdHandle`, `GetFileType`, `GetConsoleMode`, `GetConsoleOutputCP`/`GetACP`, `CreateFileW("CONOUT$")`, `WriteConsoleW`, `SetConsoleCtrlHandler` (with the delegate held in a static field), `IsProcessInJob`, `CreateProcessW` and `CloseHandle`.

A pure function, `Decide(fileType, isConsoleHandle, parentHasConsole)`, picks the output and is unit-tested:

| Situation | Where output goes | Encoding |
|---|---|---|
| stdout redirected to a pipe or file, parent has a console | the redirected handle | the console's code page |
| stdout redirected, no parent console (WinRM, SCCM, PsExec) | the redirected handle | ANSI (`GetACP`), since PowerShell decodes it that way |
| stdout is a console | `WriteConsoleW` | Unicode |
| no usable stdout, `AttachConsole` succeeds | `CONOUT$` via `WriteConsoleW` | Unicode |
| nothing available | the run log only | — |

Further rules:
- Code page 65001 means UTF-8 without a BOM.
- Nothing is written to stderr, because PowerShell 5.1 would wrap it as NativeCommandError.
- `--json` output uses `JavaScriptEncoder.Default`, which is pure ASCII.
- A write error, such as a broken pipe, disables the writer and never crashes the capture.

## Shared refactors (minimal; the GUI keeps working)

| File | Change |
|---|---|
| `Model/FilterRule.cs` | Add `TryParse(string, out FilterRule, out string error)` and `Parse(string)`. The grammar is the reverse of `ToArgs()` (78–96), with pktmon's long aliases confirmed by `pktmon filter add help`: `--mac[-address]`, `--vlan`, `--data-link[-protocol]`/`--ethertype`, `--dscp`, `--transport[-protocol]`/`--ip-protocol` (TCP flags follow), `--ip[-address]`, `--port`, `--heartbeat`, `--encap [port]`. A leading `pktmon filter add` is stripped, and the first bare token is the name. |
| `Model/ArgSplitter.cs` (new) | `Split(string)` with the same quoting rules as CommandLineToArgvW. |
| `Model/BuiltInPresets.cs` (new) | Move `BuiltIn` verbatim out of `ViewModels/FiltersViewModel.cs:426-445` (same class name, namespace `PktmonGUI.Model`). Add `Find(name)`, which matches slugs such as `ldap-kerberos` plus the aliases `tcp-syn`/`tcp-rst`, and `Slugs`. |
| `Model/RuleFile.cs` (new) | `ReadRules(json)` accepts a `Preset`, a `List<FilterRule>`, a `FilterSnapshot` or a `List<Preset>`, the same shapes as `FiltersViewModel.ImportJson`. |
| `Services/SystemChecks.cs` (new) | `IsAdministrator()` (moved from `MainViewModel.cs:46-53`, which now delegates), `OsInfo()` + `MinimumBuild` (from `PreflightViewModel.cs:147-166`), `StopLeftoverEtwSessions()` (from 235-242), `FreeBytes`, `IsSystem`, `IsNetworkLogon`. `PreflightViewModel` calls these. |
| `Services/EtlConverter.cs` (new) | `ToPcapngAsync(runner, etl, pcapng, sidecar)` wraps `PktmonCommand.Etl2Pcap` and `ProcessCommenter.Annotate`. `AddProcessComments(pcapng, sidecar)`: `FilesViewModel.cs:338-339` calls it. `ParseSummary(output)` reads "Packets total", drops, and the formatted file. |
| `Services/AppServices.cs` | (a) An `internal AppServices(ui, SettingsStore store, string workingFolder)` overload, which the public ctor chains to. (b) Extract `RestoreMachineFiltersAsync()` from `ShutdownAsync` (121–134), keeping its behavior and returning `{Action, Failures}`. (c) **Fix a bug** (details below the table). |
| `Services/SettingsStore.cs` | Add `internal SettingsStore(string dataFolder, string settingsFileName)`. |
| `Pktmon/CommandLog.cs` | Add the events `Added(entry)` and `Completed(entry, result)`, raised on the executing thread. Entries get a reference to the owning log. Lock `Post` when there's no UI context, since `ObservableCollection` isn't thread-safe. |
| `Attribution/FlowTable.cs`, `AttributionEngine.cs`, `Services/CaptureSession.cs` | **Existing bug:** `FlowTable.KeepClosed = 5 min` (line 19). Record-mode sidecars therefore lose flows that closed more than 5 minutes earlier, so a long capture gets "unknown" process comments. Fix: `Evict(now, keepClosed=false)` plus an `EvictedByCap` count, and `AttributionEngine.RetainClosedFlows`, which `CaptureSession.StartAsync` sets to true for Record mode. The 200k cap stays and becomes a warning. The existing `Evicts_long_closed_entries` test is unchanged. |
| `App.xaml.cs`, `PktmonGUI.csproj`, `Program.cs` | See "Entry point". |

**The `AppServices` bug fix (c):** as SYSTEM, `DefaultWorkingFolder()` falls back to `C:\Windows\Temp`. `IsSafeWorkingFolder` rejects that path, so `EnsureWorkingFolder` (line 103) throws. Running from UNC makes `DriveInfo` throw as well. The fix:
- a testable `DefaultWorkingFolder(exeDir, tempDir)`, which skips the drive probe for UNC and falls back to `%ProgramData%\PktmonGUI\work`;
- `EnsureWorkingFolder` tries its candidates in order and never throws.

**New `Headless/` files:**
- `HeadlessProgram`, `CliOptions` (a sealed class, since net472 has no `record`), `CliParser` (table-driven, so the usage text can be checked against it), `DurationParser`, `Usage`, `ExitCodes`;
- `HeadlessPaths`, `HeadlessState` (Load retries 3 times; Save uses `Json.Save`), `SyncObjects` (mutex and event with ACLs);
- `ComponentSelector`, `HeadlessFilters` (merges `--filter`, `--preset` and `--filters-file`, adds the name prefix, enforces at most 32 rules, runs `Validate`);
- `StopSignals`, `RunLog`, `ConsoleOutput`, `HeadlessNative`, `RunResult`;
- `CaptureCommand`, `StopCommand`, `StatusCommand`, `CleanupCommand`, `ListAdaptersCommand`, `Detacher`.

## `tools/Invoke-RemotePktmon.ps1`

**Parameters:**
- targets: `-ComputerName[]` or `-Session[]`, `-Credential`, `-UseSSL`, `-ThrottleLimit 32`;
- `-Action Start|Stop|Status|Collect|Cleanup|Run`;
- capture: `-Duration`, `-Filter[]`, `-Preset[]`, `-Comp`, `-ArgumentList[]`;
- paths: `-ExePath` (defaults to the Release output, as the other tools scripts do), `-RemoteFolder C:\ProgramData\PktmonGUI\bin`, `-Destination .\pktmon-results`;
- `-StopTimeout`, `-RemoveRemoteZip`, `-Purge`, `-RemoveExe`, `-UseAdminShare`.

**Actions:**
- **Start:** compare hashes, then `Copy-Item -ToSession` if the remote copy differs. Then run `--capture --detach --json ...` in parallel.
- **Running the exe remotely:** use `$o = & $exe @args 2>&1 | Out-String; $LASTEXITCODE`. With its output piped, PowerShell waits for a GUI-subsystem exe and sets the exit code. Then `ConvertFrom-Json`.
- **Stop:** `--stop --json --timeout`.
- **Status:** `--status --json`.
- **Collect:** take the zip path from `lastResult`, then `Copy-Item -FromSession` (or `\\host\C$` with `-UseAdminShare`), and verify length and SHA-256.
- **Cleanup:** `--cleanup --json [--purge]`.
- **Run:** Start, then poll, then Collect.

**Output:** one object per host (ComputerName, Action, ExitCode, Meaning, Phase, RemoteZip, LocalZip, Message) and a summary table. The script exits non-zero if any host failed. Its comment-based help covers the double hop, argument quoting in PowerShell 5.1, and `LocalAccountTokenFilterPolicy`.

## README: new "Headless / remote use" section

It covers:
- quick start, run-folder and zip layout, and the state files in `%ProgramData%\PktmonGUI`;
- the usage text and exit-code table;
- how to wait and get the exit code: `start "" /wait`, `Start-Process -Wait -PassThru`, or `& exe | Out-Host; $LASTEXITCODE`;
- filters (the pktmon syntax, presets, and the snapshot/clear/restore of foreign filters such as Defender's), `--comp`, and size math for long captures;
- **WinRM:** the single-host command, the fan-out script, the double hop, and `--detach`;
- **GPO:** GPP Files copies to `%ProgramData%\PktmonGUI\bin`, and a GPP Immediate Task runs as SYSTEM with "highest privileges" and "Apply once". Its "stop if runs longer than" setting must exceed the duration. Alternatively, use a startup script with `--detach`, because of the 600 s script wait.
- **SCCM:** hidden, with admin rights, and a max runtime of at least duration + 15 minutes;
- **PsExec:** `-s -c -f`;
- share ACLs for collect as SYSTEM, as a drop box: Domain Computers get create/write on this folder only, and CREATOR OWNER gets Modify;
- security notes: full packets contain secrets; EDR (WMI, ETW, zip-and-copy), where the answer is to sign the exe and allowlist it;
- troubleshooting;
- also update line 55 (headless keeps its state in ProgramData) and the Build/Test section.

## Tests (xUnit, pure; `tests/PktmonGUI.Tests/`)

- `HeadlessCliTests`:
  - actions implied or exclusive, unknown flag gives 2, `--filter "-t TCP"` is taken verbatim, `=` form, repeats accumulate, `--keep-filters` conflicts;
  - `Usage_text_mentions_every_public_flag`;
  - `Detacher.BuildChildArgs`.
- `DurationParserTests`: a theory over valid and invalid inputs.
- `FilterRuleParseTests`:
  - short and long aliases, the `pktmon filter add` prefix, a quoted name, second MAC/IP/port, TCP flags, rejection of unknown or duplicate options;
  - round-trip of every built-in preset through `ToArgs`+`QuoteArg`, then `Parse`;
  - every alias in the new fixture `Fixtures/raw/filter-add-help.txt` must be known.
- `ComponentSelectorTests`: built on the `raw/list.json` fixture; nics / id / MAC / exact / unique substring / ambiguous / wildcard / default.
- `HeadlessPathsTests` (zip name, host sanitization, collisions, rejection of UNC or Windows folders for `--out`) and `WorkingFolderTests` (SYSTEM's temp falls back to ProgramData).
- `ExitCodeTests`, `PresetLookupTests`, `RuleFileTests`, `EtlConverterTests` (`ParseSummary` on the `raw/etl2pcap.txt` fixture), `ConsoleOutputTests` (the `Decide` table), `CommandLogEventTests` (built inside `Task.Run`), `RunResultTests` (JSON round-trip, ASCII `--json`).
- `AttributionTests`: add `Evict_keepClosed_retains_old_closed_flows` and `Cap_eviction_is_counted`.
- `UiSmokeTests`: unchanged.

## Implementation order

1. Shared refactors and their tests, then `dotnet build src/PktmonGUI -c Release` and `dotnet test`.
2. `Program.cs`, the csproj changes, and removing the `App.xaml.cs` block. Check that the GUI, `UiSmokeTests` and `--dump-etw` still work.
3. The `Headless/` infrastructure and its tests.
4. `CaptureCommand` + `StopSignals`, then stop/status/cleanup/list-adapters, then `Detacher`.
5. `tools/Invoke-RemotePktmon.ps1`, then the README.

## Verification

- `dotnet test`: everything green, including the new suites.
- **Single-exe check:**
  - copy only `bin/Release/net472/PktmonGUI.exe` into an empty folder;
  - run `--version`, `--help` and `--status`;
  - confirm that `PresentationFramework.dll` is not in the headless process's modules (Process Explorer, or `Get-Process -Module`);
  - launch the GUI with no arguments.
- **Manual matrix** on an elevated host:
  1. `--capture --duration 1m --preset dns` from cmd with `start "" /wait`, from PowerShell with `Start-Process -Wait -PassThru`, and with `& exe | Out-Host`. Each should produce a zip containing `.etl`, `.pcapng` with process comments, counters, `run.log` and `result.json`, with exit 0.
  2. Start a capture with no duration, then `--stop` from a second prompt (exit 0). Also try Ctrl+C, and closing the console window (status Interrupted, filters restored).
  3. `Invoke-Command -ComputerName localhost { & C:\ProgramData\PktmonGUI\bin\PktmonGUI.exe --capture --detach --duration 5m | Out-String }`, then `Remove-PSSession` while it records. The capture should continue, and a later `--stop` over a new session should return its result.
  4. `psexec -s` with `--collect \\fs\share`: the zip lands on the share. From WinRM, the same collect should exit 5 with the double-hop hint.
  5. `Stop-Process -Force` in the middle of a capture: `--status` gives 7, `--cleanup` gives 0, and pktmon and the filters are back to their prior state.
  6. Add a named foreign filter set first (e.g. `pktmon filter add SenseNdrTest -p 9999`). It is snapshotted, cleared and restored exactly.
  7. A 10-minute or longer Record capture: process comments are still present on early flows (tests the eviction fix).
  8. A Wi-Fi adapter (warning), and `--comp` with a name, a MAC and `default`.
  9. `tools/Invoke-RemotePktmon.ps1 -Action Run` against two hosts.

## Risks

- **A hard kill leaves pktmon running and the filters replaced.** `--detach` has a 24h cap; recovery, `--status` and `--cleanup` detect and fix it.
- **Circular logging** keeps only the most recent window. The size math is documented; recommend filters or `--pkt-size`.
- **Disk space** is guarded at preflight and during the run.
- **The 64-session ETW limit:** pktmon start fails (exit 1); attribution falls back to table polling.
- **Defender for Endpoint (MDE)** can re-add its filters mid-capture (warned). `--force` must never be used fleet-wide.
- **The WMI launch in `--detach`** may be blocked by the ASR rule "Block process creations originating from PSExec and WMI commands". There is a fallback and a clear error.
- **EDR heuristics:** recommend signing the exe and allowlisting it.
- **The WinRM job's breakaway permission** and `Start-Process -Wait` waiting on descendant processes should be confirmed on Server 2022 and Windows 11 (matrix item 3).
