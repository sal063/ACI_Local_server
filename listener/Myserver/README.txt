ACI mock listener
=================

Purpose
-------

Local mock server and telemetry harness for Ace Combat Infinity research. It
captures HTTP/HTTPS traffic from the game, serves locally cached TSS files, logs
raw request/response bytes, replays captured Wind save state on known load-like
routes, and parses RPCS3 HLE save/TSS calls from RPCS3.log.

Quick start
-----------

From this directory:

  python aci_listener.py --self-test --no-rpcs3-log-watch --rpcs3-bin "C:\path\to\rpcs3\bin"

For your current RPCS3 fork layout, this is the matching form:

  python aci_listener.py --self-test --no-rpcs3-log-watch --rpcs3-bin "C:\ext\OPus\New folder\Trae\ACI\rpcs3-source\build-msvc-aci-tss-vulkan\bin"

For a real game run, open an Administrator shell because ports 80 and 443 are
privileged on Windows:

  cd <repo>\listener\Myserver
  python aci_listener.py --rpcs3-bin "<rpcs3-bin>"

Host redirects
--------------

Add these entries to your hosts file or equivalent DNS override:

  127.0.0.1   dev-wind.siliconstudio.co.jp
  127.0.0.1   a0.ww.np.dl.playstation.net

On Windows the hosts file is:

  C:\Windows\System32\drivers\etc\hosts

TSS files
---------

Place your local TSS cache in:

  listener\Myserver\tss

Supported request paths include:

  /tss/np/NPWR04428_00/NPWR04428_00-0.tss
  /tss/np/NPWR04428_00/NPWR04428_00-1.tss
  /tss/np/NPWR04428_00/NPWR04428_00-2.tss
  /tss/np/NPWR04428_00/NPWR04428_00-3.tss
  /tss/np/NPWR04428_00/NPWR04428_00-4.tss
  /tss/np/NPWR04428_00/NPWR04428_00-5.tss

Runtime output
--------------

These files are intentionally ignored by git:

  requests.log
  telemetry\
  saves\
  save_state.json
  save_state_envelope.json
  cert.pem
  key.pem
  tss\*.tss

Telemetry includes structured HTTP JSONL, socket/TLS events, raw request and
response bodies, per-event Wind JSONL, startup inventory, self-test output, and
RPCS3 HLE save/TSS scans. TSS requests are also written to:

  telemetry\tss_events.jsonl
  telemetry\tss_inventory_latest.json
  telemetry\tss_analysis\

Save tools
----------

Rebuild a merged save replay from captured logs:

  python aci_listener.py --rebuild-save-from-logs

Write a redacted local debug report:

  python aci_listener.py --debug-report

Analyze the local TSS cache and write per-file probes:

  python aci_listener.py --analyze-tss

Analyze a scraped NP storage/TUS envelope sample with private fields redacted:

  python aci_listener.py --analyze-npstorage <path-to-sample>

The debug report redacts private identifiers and writes:

  telemetry\debug_report_latest.json
  telemetry\debug_report_latest.md

Local debug endpoints while the server is running:

  http://127.0.0.1/__debug/summary
  http://127.0.0.1/__debug/tss
  http://127.0.0.1/__debug/npstorage
  http://127.0.0.1/__debug/rpcs3
  http://127.0.0.1/__debug/save

Known save/load behavior
------------------------

Observed game sessions have sent rich Wind telemetry to /Wind/save/... but have
not been observed loading the replay state through HTTP at startup. RPCS3 logs
show startup using local PS3 savedata:

  cellSaveDataAutoLoad2(dirName="BLUS30613-PLAYDATA")

Mission/session saves are visible as NP TUS metadata:

  sceNpTusSetDataAsync(slotId=3, totalSize=93672, sendSize=93672)

RPCS3 logs the TUS slot and size, but not the payload bytes. This mock can log
that path from RPCS3.log and replay HTTP save shapes if the game asks, but it
cannot inject a TUS payload into the game without a game/RPCS3-side patch.
Scraped NP storage samples can be analyzed locally with --analyze-npstorage;
do not commit raw samples because they may contain tickets, PSIDs, and account
identifiers.

More setup detail is in MOCK_SERVER_WALKTHROUGH.md.
There is also a short friendlier handoff guide in SETUP.txt.
