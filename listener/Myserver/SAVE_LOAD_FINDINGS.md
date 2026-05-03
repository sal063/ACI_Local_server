# Save And Load Findings

This file is public-safe: local paths, private identifiers, and local reverse
engineering notes are intentionally omitted.

## Current Network Findings

The latest extended session reached request ID `20` and produced these observed
Wind events:

- `ev_pinger`: 2
- `ev_load_save_success`: 5
- `accum_data`: 5
- `ev_sortie`: 1
- `ev_objective_end`: 5
- `ev_mission_result`: 1
- `ev_title_return`: 1

All latest-session requests were `POST /Wind/save/...` and returned `200`.
There was still no observed startup HTTP call to `/Wind/load/test` or
`/Wind/load`.

## Current HTTP Save Replay

The merged replay save currently contains:

- credit gain: `80200`
- aircraft count: `1`
- mission IDs: `102`, `101`, `105`, `100`
- mileage: `30`

The listener merges keyed progress lists so interrupted or sparse `accum_data`
payloads do not erase richer captured mission/aircraft state.

## RPCS3 Save/Load Path

Startup has been observed through local PS3 savedata:

```text
cellSaveDataAutoLoad2(dirName="BLUS30613-PLAYDATA")
savedata_op(): funcStat returned result=-2
CELL_SAVEDATA_ERROR_CBRESULT
```

Mission/session saves are visible as NP TUS metadata:

```text
sceNpTusSetDataAsync(slotId=3, totalSize=93672, sendSize=93672)
```

RPCS3 logs the slot, size, and pointer, but not the payload bytes. The HTTP
mock can log this metadata from `RPCS3.log`; it cannot replay the TUS payload
unless the game or RPCS3 is patched to expose those bytes.

## Scraped NP Storage Sample Shape

A scraped write sample was inspected locally with private fields redacted. It is
an `npstorage` XML envelope for `NPWR04428_00` with a binary tail beginning with
`SAVE`. The envelope declares data slot `2` with size `1088`, while the captured
file is only `849` bytes total, so it is not the full 93672-byte slot `3` TUS
payload seen in RPCS3 logs. Treat raw NP storage samples as private and keep
them out of git.
