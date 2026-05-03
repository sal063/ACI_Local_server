# Local Mock Server Walkthrough

This walkthrough is intentionally path-neutral so it can live in a public repo.
Replace `<repo>` with your checkout path and `<rpcs3-root>` with your RPCS3
folder.

## 1. Requirements

- Python 3.
- Administrator/root privileges when binding to ports `80` and `443`.
- A local RPCS3/game research setup.
- Locally obtained TSS files placed in `<repo>\listener\Myserver\tss`.

## 2. Verify The Server

```powershell
cd "<repo>\listener\Myserver"
python aci_listener.py --self-test --no-rpcs3-log-watch
```

Expected result:

- `save_response.status` is `200`
- `load_response.status` is `200`
- `tss_response` is `200` when a sample TSS file exists
- `tls_response` is `200`

## 3. Point Game Hosts At The Local Server

Add DNS overrides for the game backend and TSS host:

```text
127.0.0.1 dev-wind.siliconstudio.co.jp
127.0.0.1 a0.ww.np.dl.playstation.net
```

On Windows, edit this file as Administrator:

```text
C:\Windows\System32\drivers\etc\hosts
```

Then flush DNS:

```powershell
ipconfig /flushdns
```

## 4. Start The Server

```powershell
cd "<repo>\listener\Myserver"
python aci_listener.py
```

The server listens on:

- `http://0.0.0.0:80`
- `https://0.0.0.0:443`

Port `443` accepts TLS and plaintext HTTP. Some captured game traffic uses
`Host: dev-wind.siliconstudio.co.jp:443` while still speaking plaintext.

## 5. Smoke Test From Another Shell

```powershell
curl.exe http://127.0.0.1/Wind/test
curl.exe -k https://127.0.0.1/Wind/test
curl.exe http://127.0.0.1/tss/np/NPWR04428_00/NPWR04428_00-0.tss --output "$env:TEMP\NPWR04428_00-0.tss"
```

## 6. Launch RPCS3 And Play

Keep the server running while launching the game in RPCS3. The most useful live
files are:

- `listener\Myserver\requests.log`
- `listener\Myserver\telemetry\summary.json`
- `listener\Myserver\telemetry\http_events.jsonl`
- `listener\Myserver\telemetry\rpcs3_hle_events.jsonl`
- `<rpcs3-root>\log\RPCS3.log`

Raw request and response bodies are stored under:

```text
listener\Myserver\telemetry\raw
```

## 7. Recover Or Merge Captured Save State

If a test is interrupted or the newest `accum_data` payload is sparse, rebuild
the merged save replay from captured logs:

```powershell
python aci_listener.py --rebuild-save-from-logs
```

The merge keeps richer keyed progress entries such as missions and aircraft.

## 8. Create A Redacted Debug Report

```powershell
python aci_listener.py --debug-report
```

This writes:

```text
listener\Myserver\telemetry\debug_report_latest.json
listener\Myserver\telemetry\debug_report_latest.md
```

The report redacts private identifiers and summarizes HTTP events, save state,
and RPCS3 findings.

## 9. Inspect TSS, NP Storage, And Live State

Analyze all locally cached TSS files:

```powershell
python aci_listener.py --analyze-tss
```

This writes:

```text
listener\Myserver\telemetry\tss_inventory_latest.json
listener\Myserver\telemetry\tss_analysis
```

Analyze a scraped NP storage/TUS envelope sample with private fields redacted:

```powershell
python aci_listener.py --analyze-npstorage "<path-to-sample>"
```

Raw scraped samples may contain tickets, PSIDs, and account identifiers. Keep
them local and commit only the redacted analyzer/report code.

While the server is running, local debug endpoints are available:

```text
http://127.0.0.1/__debug/summary
http://127.0.0.1/__debug/tss
http://127.0.0.1/__debug/npstorage
http://127.0.0.1/__debug/rpcs3
http://127.0.0.1/__debug/save
```

## 10. GitHub Safety

The repo `.gitignore` excludes runtime logs, raw telemetry, generated certs,
save snapshots, TSS cache files, emulator HDD data, package files, and reverse
engineering databases. Review `git status --short` before publishing and do not commit
game content, user identifiers, credentials, generated certificates, or captured
telemetry.

## 11. Known Save/Load Shape

Observed sessions send detailed Wind telemetry to `/Wind/save/...`. Startup has
not been observed loading replay state through HTTP. RPCS3 logs indicate local
PS3 savedata and NP TUS paths:

```text
cellSaveDataAutoLoad2(dirName="BLUS30613-PLAYDATA")
sceNpTusSetDataAsync(slotId=3, totalSize=93672, sendSize=93672)
```

The mock can replay captured HTTP save data on known load-like routes, but TUS
payload injection requires a game/RPCS3-side patch because RPCS3 logs only the
slot, size, and pointer, not the payload bytes.
