# Changelog

Versions follow [Semantic Versioning](https://semver.org/): MAJOR.MINOR.PATCH.

## 1.4.0

### Added
- **Export settings as a template.** Preflight's **Settings** row has **Export…**, which saves the settings in use as a `settings.json` to put beside the exe. It holds every preference a template can set, and none of the machine's state: no adapter MACs, applied filters or import history, and no working folder while it's the default. It's written from the same list of fields the import reads, so the two can't drift apart.
- **A guided tour.** It dims the window except for one control at a time, with a short card beside it: Preflight's checks, adapters and Continue, then the pages, Capture's mode, options, Start and packet grid, Counters, Filters, Files, the session card, and the title bar. Back, Next, Esc and the arrow keys move through it. The tour switches pages itself and goes back to the page you were on, and while it's open nothing under it can be clicked, so it never starts a capture or changes the machine. A control that isn't showing at that moment gets a centred card instead.
  - PktmonGUI offers the tour after Preflight's checks at each launch. *Don't offer this tour at startup*, on every card, turns that off. It's saved at once as `showTourAtStartup` in settings.json, and a settings.json template beside the exe can set it too.
  - The **?** button in the title bar, or F1, runs the tour any time.
- **A User Guide and an Admin Guide**, in `docs/`. The User Guide explains what pktmon is and what PktmonGUI adds, then goes through each screen step by step with annotated screenshots: Preflight, capturing, reading and filtering packets, filter rules (and other owners' filters), counters, converting files, and using the process comments in Wireshark, with common tasks, troubleshooting and a glossary. The Admin Guide covers deployment, settings.json templates and when they're trusted, every headless option, the zip and the exit codes, and capture over WinRM, Group Policy, Configuration Manager and PsExec. `tools/Build-Docs.ps1` builds both into one PDF for each release.
  - The screenshots are rendered from the real window by `tools/DocShots`, filled with a made-up machine (documentation addresses, `WS01`, `CORP\analyst`), so they can be taken again whenever the UI changes and name no real host, network or person. DocShots never runs pktmon, answering it from canned output instead, and refuses to run elevated. Before saving a picture it reads all the text in it, and refuses if any names the machine it runs on, its addresses, MACs, gateway or DNS servers, or the user.
  - Tests check that every picture the guides show exists and has alt text, that every link and anchor resolves as on GitHub, and that every headless option is documented.

### Changed
- The README is now an overview that links to the guides; the detail moved into them.

### Fixed
- Preflight's adapter rows ended in a stray " · " when the adapter had no warning to show.

## 1.3.0

### Added
- **A settings.json beside the exe is a template, for the GUI and for headless captures.** Copy the tool with its settings to a server and run it there. Headless captures take their defaults from it: output folder, file size and log mode, packet size, process attribution, and the Filters page's rules. Command-line flags always win, `--no-settings` ignores it, and `result.json`/`run.log` record which defaults it gave. A detached capture gets them as flags, because it may run from a copy of the exe with no settings.json beside it. The GUI imports the template's preferences each time it changes. `tools/Invoke-RemotePktmon.ps1` deploys it beside the exe (`-SettingsPath`), and removes a stale one.
  - **Trust:** the template is used only when nobody but an administrator could have written it. It must be in a local folder owned by Administrators that no other account can change, not on a share, and not a link, and no other account may be able to change the file. A template owned by an administrator's own account is handed to Administrators. It's checked and read through one handle, its values are checked as if typed in, and it never carries the machine's own state (which filters are PktmonGUI's, adapters, snapshots).
  - **When it isn't trusted:** the GUI's Preflight offers **Review…**, which lists every change before importing, or **Ignore**. A headless capture stops with exit code 2 and says why.
- **Join a multi-file capture into one pcapng.** With a part of a multi-file recording selected, Files ▸ Convert ▸ pcapng offers **Join all N parts into one file** (on by default). It converts every part with `etl2pcap`, joins them in capture order into `name.pcapng`, adds the process comments, and opens that in Wireshark. The joined file is a single pcapng section: each interface is listed once and every packet points at it, so readers that don't handle several sections open it too. The per-part pcapngs are temporary and deleted afterwards. In the list, the joined file shows as *joined parts* and each part as *joined*. The capture's metadata and process data stay until the last of its parts and the joined file is deleted. Checked on a real 4-part capture: 33,313 packets, the sum of the four parts converted on their own, read in full by Wireshark's `capinfos` and `tshark`. Marking rows still only affects Delete; Convert works on the selected row.
- **Light theme.** A sun/moon button in the title bar, beside Minimize, switches between the dark and light themes (also Ctrl+Shift+L). Right-click it for **Match Windows**, which follows Windows' "Choose your default app mode" and changes along with it. The choice is saved in `settings.json`; the default stays dark.
- **ETW provider events are shown.** Providers added in Capture ▸ Advanced ▸ Extra ETW providers (`pktmon --trace --provider`) are decoded by pktmon and printed in the same stream as the packets, on the same clock — the stack's own account of a drop or a reset, which the packet capture can't give on its own. PktmonGUI threw every one of them away: in one six-second capture with `Microsoft-Windows-TCPIP`, 3,013 of 3,038 lines were discarded as banner text (and each briefly replaced the status banner). They now appear in an "ETW provider events" panel beside the command log, with their time, pktmon's label for the source (`TCPIP`, `INETINSPECT`, `IP`, …) and the text, and the ones reporting a drop, block or failure are marked. The panel is there only when a provider actually produced something, and events recorded into an `.etl` show up the same way when that capture is opened.

### Changed
- **Settings live in one place:** `%LOCALAPPDATA%\PktmonGUI`. Portable mode is gone. It kept settings beside the exe when only administrators could change that folder, and otherwise silently ignored a settings.json there, which was confusing. Preflight has a **Settings** row with the file in use and where it was imported from, and hovering over the version in the title bar shows the same. The title bar no longer says "portable". A former portable copy's `presets.json` is copied in once. Its settings.json is imported as a template, without the machine state it held: Machine filters may ask once whether filters PktmonGUI left applied are its own.

### Fixed
- **Multi-file recordings were half-handled.** pktmon writes `name.etl` as `name1.etl`, `name2.etl`…, but PktmonGUI looked for `name.etl` and kept the capture's metadata and process data beside it, so:
  - After Stop the grid stayed empty, without a word. It now loads the newest parts, oldest first, up to 512 MB of them (the last part alone is often just the final second), and says how many of how many files it shows.
  - The Files page showed "unknown" for every part. Parts now use their capture's metadata (adapter, filters, snap length, log mode).
  - Process data was unreachable from a part, so *Add process comments* stayed disabled when converting one. Parts now share their capture's.
  - Every part would have shown the whole capture's length. Each now shows its own start and length, from when pktmon opened it to its last write; the packet count is left blank because it's only known for the whole capture.
  - Deleting one part would have taken the shared metadata and process data with it. They're now deleted only with the last remaining part, and every part of a running capture is protected from deletion, not just a file that doesn't exist.
  - Converting a part of a capture that was still running wasn't stopped, since the check looked for `name.etl`. It now says to stop the capture first, as it does for a single-file recording.
- While a Record capture ran, the empty grid still said "No packets yet. Pick an adapter, check the rules, and press Start." It now says the capture is recording, which file the packets are going to, and that they load after Stop. Counters-only mode points to the Counters page, and Live mode says nothing has matched the rules yet.
- A provider event arriving in the middle of a packet broke that packet. Any line the parser didn't recognise detached the packet that following indented lines belong to, so a verbose body wrapped onto a second line was lost; one arriving between a packet's metadata and its body was read as that body. Events are now recognised in their own right and leave the packet around them alone.
- Packets from a mobile broadband (WWAN) adapter were barely parsed. These adapters have no link-layer header, so pktmon reports `Type IP` and prints the packet behind a bare `ip: ` instead of a MAC pair and an ethertype. Every such packet fell through the Ethernet path: no addresses, no ports, no protocol, and the whole line left in INFO. They now parse like any other packet, with IPv4 or IPv6 taken from the address.
- Saving a Live capture as pcapng wrote an empty file on those adapters: packets that weren't Ethernet frames were counted as "skipped" because their link type wasn't known. Raw IP packets are now written to an interface with the raw-IP link type, so Wireshark opens them.
- A packet could end up in the pcapng referencing an interface the file never described, which makes the file unreadable. The interface was marked written before its block reached the disk, so anything that failed on the way (the adapter-name lookup, for one) left every later packet pointing at nothing — silently, since the tap swallows write errors.
- Ticking adapters in Preflight didn't move the Capture page's Adapter box: once it had a selection, it kept it, because the rebuilt list still held an option with the same label. The box now follows what Preflight has ticked (pktmon monitors several components in one session, so a multi-adapter tick stays a real target), while a choice made in the box itself survives a rebuild that changed no ticks. With nothing ticked it falls back to Ethernet.

### Changed
- **Explanations moved into tooltips.** Labels now say in plain words what a control does. pktmon flags such as `--pkt-size`, `-i`, `-z` or `--hex` are no longer printed beside them, and paragraphs of explanation no longer sit on the pages. Hover a control for the detail, with the pktmon flag behind it on its own line. Notes that belong to a heading rather than a control are behind an ⓘ icon beside it. Tooltips stay up for 30 seconds instead of 5. The command panels (*Apply will run*, *Convert will run*, *Commands behind this view*) still show every command in full. Warnings and errors stay on the page, shortened.
- **Multi-file sizes are labelled as requests.** pktmon logs through 16 MB ETW buffers and starts the next multi-file part only after the queued ones are written, so under load each part comes out at a few hundred MB whatever `--file-size` says: 64–144 MB parts with 10 MB and 144–176 MB with 64 MB measured with pktmon alone, 352 MB with 15 MB on a busier link. Circular mode does respect the cap. The Capture page now warns when Multi-file is chosen with a size under 200 MB, and the Record size defaults to 200 MB instead of 512 MB. The Files page shows "10 MB requested · this file 144 MB" instead of "10 MB cap", and the sidebar says "requested per file".
- The title bar shows only the version. The storage location is in the version's tooltip.
- The Capture page starts on **Packet type: Flow** instead of All. `--type all` logs a dropped packet twice — once as it flowed and again as a drop — which fills the grid with near-duplicate rows. Flow shows each packet once; switch to All or Drops to investigate drops (the Dropped counter only moves on those two). Headless `--type` still defaults to pktmon's own `all`.
- The packet grid shows the source and destination ports in columns of their own, instead of appending them to the address with a dot (`192.168.7.202.23744`). Both sort numerically and filter like numbers (`443`, `>1024`, `8000-8100`); packets with no port never match a port filter.
- **Filters: no duplicate rules.** A rule that matches the same packets as one already in the list isn't added again. Done on a new rule (or an unchanged Duplicate) drops it with a message naming the rule it repeats; a preset or imported file adds only the rules that are new and says how many it skipped. "The same packets" ignores the rule's name, letter case, MAC separators and the order of a pair (`-i A B` is `-i B A` to pktmon). A duplicate that gets in another way, such as by editing an existing rule, is marked on its card and keeps Apply disabled until it's changed.
- **The Filters page shows the machine, not just your list.** The list there is what the machine will hold after Apply to machine, and it used to be the only thing shown: after applying and then emptying it, nothing said the applied filters were still active, and clearing the machine's filters didn't say which ones went. Now every rule carries a badge: **On machine** (there exactly as shown), **Not applied** (Apply adds it) or **Changed** (edited since it was applied, with the version on the machine shown underneath). Filters on the machine that no rule accounts for are listed under the rules, struck through and marked **Will be removed**, with who set them and a **Keep** button that puts one back in the list. The Apply preview names each filter its `pktmon filter remove` takes away, and the status line says when the list is empty but the machine isn't. Filters PktmonGUI applied are compared with exactly what it sent; anyone else's with what `pktmon filter list` reports.
- **Apply to machine** is greyed out while the machine already holds exactly your list, and comes back as soon as a rule changes, or when the machine has filters your list doesn't (an empty list then clears them, with the usual snapshot offer for someone else's).
- **Remove all from machine…** (was *Clear machine filters…*) lists every filter it deletes, including PktmonGUI's own, and says your list stays as it is. **Clear list** (was *Remove all*) is red, with a trash icon, disabled when the list is empty, and its confirmation says the machine keeps its filters until you apply instead of "nothing on the machine changes until you apply", which read as if applied rules weren't applied yet. *Copy from machine* is now **Load from machine**.

## 1.2.0

### Security
- The GUI's captures went to `pktmon-work` at the root of the exe's drive, which every signed-in user can read and change. They now go to `%ProgramData%\PktmonGUI\work`, owned by Administrators and open to SYSTEM and Administrators only (you get read access, so Explorer opens it). A saved `pktmon-work` you didn't pick yourself moves to the new folder; existing captures stay where they are.
- `%ProgramData%\PktmonGUI`, and everything in it, must be owned by Administrators, SYSTEM or TrustedInstaller, writable by no one else, and contain no links. A folder that isn't is no longer repaired in place, which can't be made safe: its owner can change it back, and whatever was planted in it stays. It's renamed `PktmonGUI.untrusted-<date>` (kept for inspection) and made again in one step, with its owner and permissions already set. The reason is in `cli.log`, `result.json`'s warnings, `--status`, and in the GUI when you continue past Preflight.
- Every headless command makes `%ProgramData%\PktmonGUI` safe before writing anything there. `--list-adapters`, usage errors and other early failures used to create it with `%ProgramData%`'s default permissions, which let any user add files; `--status` ignored a failed check.
- Headless output is no longer exposed to, or redirected by, other accounts:
  - Run folders and zips (local `--collect` copies too) are created for SYSTEM and Administrators only, whatever `--out` lets others do.
  - A local `--out`, `--collect` or `--log` folder that accounts other than administrators can change, or that is a link, is refused (exit 2) unless `--force`. A missing one is created for administrators only. A new folder at a drive's root, such as `D:\captures`, lets every signed-in user change it by default.
  - The zip is built from the run folder's files, leaving out (and warning about) any link; `ZipFile.CreateFromDirectory` followed links.
  - Temporary `.partial` files get unpredictable names and must be new, and a finished zip or copy never replaces a file already there: the zip gets the next free `-2`, `-3` name instead.
- Any user could create headless mode's lock (`Global\PktmonGUI-Headless`) or stop signal (`Global\PktmonGUI-Headless-Stop`) first, then block every capture or stop a running one. PktmonGUI now makes Administrators the owner of the ones it creates, and uses an existing one only if SYSTEM or Administrators owns it; otherwise the command fails (exit 3) and says so.
- The elevated GUI no longer trusts its own folder unless only administrators can change it. `settings.json`, `presets.json` and `snapshots\` are kept beside the exe only then (e.g. `%ProgramFiles%\PktmonGUI`); otherwise they go to `%LOCALAPPDATA%\PktmonGUI`, so another account can't steer the GUI (the working folder it reads) or plant files it uses.
- At startup PktmonGUI loads DLLs only from System32 (`SetDefaultDllDirectories`), so a DLL planted beside the elevated exe can't be loaded in place of a real one.
- The GUI no longer looks for a portable Wireshark in a `Wireshark` folder beside the exe; it finds Wireshark through the registry and Program Files only. A folder beside the exe may be writable by others, and PktmonGUI launches Wireshark.
- The working folder can no longer be a UNC path: pktmon can't log to a share, and the elevated process would carry its credentials there.
- Deployment moves to `%ProgramFiles%\PktmonGUI`. The README's WinRM and GPO steps and `Invoke-RemotePktmon.ps1` used `%ProgramData%\PktmonGUI\bin`, where any user can create the folder first and then replace the exe that SYSTEM runs. The script now also refuses a `-RemoteFolder` that accounts other than administrators can change, and no longer creates anything in `%ProgramData%`.
- Preflight warns when a working folder you picked can be read or changed by other accounts.
- The GUI runs elevated, so Wireshark, editcap and a text viewer it opened inherited an administrator token; a parser bug in Wireshark would then run as administrator. Wireshark and the text viewer now open at Medium integrity, launched through the running Explorer, not as children of PktmonGUI. (The `etl2pcap`/`etl2txt`/`editcap` conversion steps still run elevated: they write into the administrators-only working folder.)

### Fixed
- The machine's pktmon filters could be put back wrong after a capture, in the GUI and headless mode:
  - The longest filter name, which pktmon prints one space from the next column, was read together with that column's value: `SenseNdrTest2 -t UDP -i 192.0.2.10` came back as a filter named `SenseNdrTest2 UDP` with no protocol.
  - TCP flags, which pktmon prints as `TCP (SYN)` or `TCP (FIN SYN ACK)`, weren't recognized, so those filters weren't put back (exit 8).
- A headless capture could die without a result if the host went to sleep when idle. A capture now keeps Windows awake until its zip is done.
- Every `--detach` capture warned "Another PktmonGUI is running" (the launcher waiting for it) and so left leftover ETW sessions running. Only the GUI and `--dump-etw` count now.
- The GUI's captures (Live and Record) could also end if the machine went to sleep when idle; they now keep Windows awake too.
- After `--collect` removed the local zip, the result's `zip` still named it; it now names the copy on the share.
- A usage error found after preflight (e.g. `--comp` matching no adapter) left a zip in `runs\`. Nothing is left now; the error is in `cli.log`.
- `tools/Invoke-RemotePktmon.ps1`:
  - A host whose WinRM session broke (asleep, rebooted, off the network) stopped the whole script with "No valid sessions". It now gets a row of its own, and `-Action Run` reopens the session and carries on.
  - One host failing to deploy stopped every host; it now fails alone.
  - Collecting a zip already removed with `-RemoveRemoteZip` reported "collect failed" (5); it's now 7.
  - The script exits 0 when every host succeeded, so `$LASTEXITCODE` is never left over from an earlier command.

## 1.1.0

### Added
- **Headless mode.** Any command-line argument runs PktmonGUI without a window, for use over GPO, SCCM, WinRM or PsExec:
  - Actions: `--capture` (implied by any capture option), `--stop`, `--status`, `--cleanup`, `--list-adapters`, `--help`, `--version`.
  - A capture records in Record mode with process attribution, converts to pcapng with process comments, and zips the results as `<HOST>-<yyyyMMdd-HHmmss>.zip`. `--collect` copies the zip to a share.
  - The machine's pktmon filters (Defender's included) are saved, replaced for the capture, and put back afterwards.
  - `--detach` keeps a capture running after a WinRM session closes or a GPO startup script times out.
  - `--cleanup` recovers after a capture was killed.
  - Documented exit codes 0–9, a run log, `result.json`, and `--json` output.
  - State lives in `%ProgramData%\PktmonGUI`, apart from the GUI's settings.
- `tools/Invoke-RemotePktmon.ps1`: starts, stops, checks and collects headless captures on many hosts over WinRM.
- **Process attribution:** each packet's owning process, from ETW and the connection tables, including which process DNS was sent for. Shown in the grid, and saved as `<name>.attribution.json` beside Record captures.
- **Process comments in pcapng:** conversion adds `Process:` and `Process path:` comments to every packet, for Wireshark.
- **Live captures as pcapng:** Live mode can also save real packet bytes to `live-<timestamp>.pcapng`.
- **Packet grid:** sort by any column, and filter per column (ranges, CIDR, `|` alternatives, `!` exclusions).
- **Files page:** mark several files with checkboxes and delete them together.

### Fixed
- Record mode forgot connections closed more than 5 minutes earlier, so long captures showed no process for early traffic.
- Choosing the working folder could crash when running as SYSTEM (its temp folder is inside `C:\Windows`) or from a network share.

### Changed
- `--dump-etw` (the fixture-recording mode) is now handled before WPF starts; its syntax is unchanged.

## 1.0.0

- First release: a portable WPF front end for pktmon, with Preflight, Capture (Live, Record, Counters only), Filters with snapshot and restore, Counters, and Files (etl2pcap, etl2txt, Wireshark).
