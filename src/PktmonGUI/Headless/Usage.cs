namespace PktmonGUI.Headless
{
    /// <summary>The --help text. Every public flag in <see cref="CliParser"/> must appear here (a test checks it).</summary>
    public static class Usage
    {
        public const string Text =
@"PktmonGUI headless mode: record a pktmon capture without the GUI.

Usage:
  PktmonGUI.exe [--capture] <capture options>   record a capture (implied by any capture option)
  PktmonGUI.exe --stop [--timeout <time>]       stop the headless capture and wait for its results
  PktmonGUI.exe --status                        show the running capture, the last result and leftovers
  PktmonGUI.exe --cleanup [--force] [--purge]   stop leftovers and put the machine's filters back
  PktmonGUI.exe --list-adapters                 list what --comp can select
  PktmonGUI.exe --help | --version
  PktmonGUI.exe                                 start the GUI (interactive sessions only)

What to capture:
  --duration <time>       stop after 90s, 10m, 2h, 1h30m or hh:mm:ss; 0 = no limit.
                          Default: until --stop or Ctrl+C (24h with --detach).
  --comp <list>           where to capture, comma-separated. Default: nics
                            nics      every network adapter
                            default   the adapter with the default gateway
                            <id>      a pktmon component ID (see --list-adapters)
                            <MAC>     every adapter with this MAC, e.g. 00-15-5D-01-02-03
                            <name>    connection name (""Ethernet 2""), adapter name or description;
                                      a unique part is enough; * and ? select several
  --filter ""<args>""       one pktmon filter, written as for 'pktmon filter add':
                            --filter ""-t TCP -p 443""    --filter ""DC -i 10.0.0.10 -t UDP -p 53""
                          Repeatable. Rules are ORed; at most 32 in total.
  --preset <name>         built-in rules: dns, rdp, smb, ldap-kerberos, tcp-syn, tcp-rst, icmp,
                          cdp-lldp, arp, dhcp, https. Repeatable, or comma-separated.
  --filters-file <file>   rules exported from the GUI's Filters page (JSON)
  --keep-filters          capture through the machine's current filters, unchanged. By default the
                          machine's filters are saved, replaced by yours (cleared if you gave none)
                          and put back when the capture ends.
  --pkt-size <bytes>      bytes logged per packet; 0 = whole packet. Default: 0
  --type all|flow|drop    Default: all
  --file-size <MB>        .etl size limit, e.g. 512 or 2GB. Default: 512
  --log-mode circular|multi-file
                          circular (default) keeps the newest packets once the file is full;
                          multi-file starts another file (the capture stops if disk runs low)
  --no-attribution        don't record which process owns each packet
  --no-pcap               keep the .etl only; skip the conversion to pcapng
  --no-settings           ignore the settings.json beside PktmonGUI.exe (see Settings below)

Where results go:
  --out <folder>          local folder for runs (not UNC). Default: %ProgramData%\PktmonGUI\runs
  --collect <folder>      copy the finished zip here, e.g. \\fs01\pktmon$
  --keep-local            keep the unzipped run folder, and the local zip after --collect
  --log <file>            also append the run log to this file
                          A local --out, --collect or --log folder must be one only administrators
                          can change (a missing one is created that way); runs and zips are made
                          for SYSTEM and Administrators only.

How it runs:
  --detach                record in a background process that outlives this one; returns once
                          the capture is running
  --force                 --capture: stop a pktmon session someone else left running, then capture;
                          also use an --out, --collect or --log folder other accounts can change.
                          --cleanup: also stop sessions and restore filters that aren't clearly ours.
  --purge                 --cleanup: also delete old runs and copies of the exe under %ProgramData%
  --timeout <time>        how long --stop / --detach wait. Default: 15m (--stop), 60s (--detach)
  --json                  print one JSON document on stdout instead of text
  --quiet                 print only warnings, errors and the final line

Settings: a settings.json beside PktmonGUI.exe (saved from the GUI) gives a capture its defaults:
  workingFolder (--out), recordFileSizeMb (--file-size), recordLogMode (--log-mode), fullPacket and
  snapLength (--pkt-size), attributeProcesses (--no-attribution) and draftRules (--filter, unless
  --filter, --preset, --filters-file or --keep-filters is given). Flags always win. It's used only
  from a local folder owned by Administrators that no other account can change, such as
  %ProgramFiles%\PktmonGUI; otherwise the capture stops and says why.

Results: <out>\<HOST>-<yyyyMMdd-HHmmss>.zip with the .etl, a .pcapng with a process comment on
every packet, counters, run.log and result.json.

Exit codes: 0 ok, 1 failed, 2 usage, 3 unsupported (not elevated, build < 19041, no pktmon, disk),
4 busy, 5 collect failed (zip kept), 6 done with warnings, 7 nothing to stop / leftovers,
8 machine not restored (run --cleanup), 9 timed out waiting.

PktmonGUI.exe is a GUI-subsystem program; to wait for it and read the exit code:
  PowerShell:  $p = Start-Process .\PktmonGUI.exe '--status' -Wait -PassThru -NoNewWindow; $p.ExitCode
               or: & .\PktmonGUI.exe --status | Out-Host; $LASTEXITCODE
  cmd:         start """" /wait PktmonGUI.exe --status      (then: echo %errorlevel%)
";
    }
}
