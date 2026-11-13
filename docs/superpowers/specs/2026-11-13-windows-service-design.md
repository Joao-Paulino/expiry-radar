# Run as a Windows service / systemd daemon

Date: 2026-11-13 · Status: approved in conversation ("já devíamos ter pensado nisso")

## Why
The collector and agent are plain console programs. On Windows, `sc create` fails (error 1053) because they do not answer the Service Control Manager, so the only way to keep them running is a scheduled task. Linux has no documented unit file.

## Goals
- Both binaries run as native Windows services: `install-service <config.json> [--account NAME]`, `uninstall-service`. Visible in `services.msc`, automatic start, restart on failure (1 min, three times, counter reset after a day), stop cleanly on Stop/Shutdown, log to the Windows Event Log.
- Default account `NT AUTHORITY\LocalService` (least privilege). `--account` accepts accounts without a password (`LocalSystem`, `NT AUTHORITY\NetworkService`, a gMSA `DOMAIN\name$`); password accounts are refused.
- Under the SCM the working directory is the config file's folder, so relative paths in the config keep working.
- README: Windows service and a hardened systemd unit.

## Non-goals / anti-goals
- No new module dependencies (`golang.org/x/sys/windows/svc` is already in the module graph).
- No change to behaviour when run from a console; Ctrl+C now stops the collector cleanly too.

## Approaches
- **Native SCM support (chosen):** `golang.org/x/sys/windows/svc` + `mgr` + `eventlog`.
- Wrapper (NSSM/WinSW): third-party binary to download and keep patched.
- Scheduled task: works today but no service controls, no Event Log, odd for operators.

## Decided
- Package `internal/service`: `Run(name string, fn func(ctx context.Context) error) error`, `Install(Spec) error`, `Uninstall(name string) error`; non-Windows `Install`/`Uninstall` return an "only on Windows" error.
- Names: `ExpiryRadarCollector` / `ExpiryRadarAgent`.
