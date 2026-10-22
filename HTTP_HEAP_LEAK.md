# Pure-HTTP Heap Address Leak: Stale PS(id) + Set-Cookie Out-of-Bounds Read

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64, `172.16.0.103`)
Constraints: **Fully remote, HTTP only; no target-specific PHP files written to the target webroot.** The target page contains only `<?php echo "OK\n"; ?>` (no session calls; this leak does not depend on page contents).
Status: **Heap address leak (Zend MM 2 MB chunk base) is complete**; libphp/libc **code pointer** leak was incomplete at the time of this note. See section 7 for the next step.

---

## 1. Result

Two pure-HTTP requests use the response's `Set-Cookie` header to obtain a **4096-byte heap out-of-bounds read**:

- Request A first sends 1001 POST fields to trigger a `max_input_vars` warning (when `display_errors=On`, the warning is emitted and `SG(headers_sent)=1`). It then sends a `PHPSESSID` whose value is the single byte `\x00`, causing `php_session_initialize()` to generate a new id and set `send_cookie=1`. Then `php_session_reset_id()` fails to send the cookie because headers have already been sent, leaving `send_cookie` at 1. A ends with a 12 MB field that OOMs, leaving `PS(id)` dangling (the random id zend_string).
- Request B has no file field. Pre-RINIT upload-progress END cleanup calls `php_session_initialize()`; `php_session_reset_id()` sees `send_cookie=1` and that B has not sent headers yet, so it constructs `Set-Cookie: PHPSESSID=<url_encode(ZSTR_VAL(id), ZSTR_LEN(id))>` using stale `PS(id)`.
- B's multipart fields reclaim A's stale `PS(id)` block as a forged `zend_string` header: `len=0x1000`, with `data` pointing to block offset 0x18. `php_url_encode` reads that length past the end of the block into adjacent heap data and encodes it into `Set-Cookie`.

Measured in the no-ASLR calibration:

~~~text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F...%F5%FF%7F...
Cookie value: 11,548 URL-encoded characters; 4,096 decoded bytes
98 pointers beginning with 0x7f...; all satisfy & ~0x1fffff == 0x7ffff5e00000
~~~

Thus the **Zend MM chunk base can be recovered directly from an HTTP response header**, without `/proc/self/maps`, target-side PHP, or target application cooperation.

> This is orthogonal to the pure-HTTP RCE chain in `NOASLR_REPORT.md`: leak request A fails before `track_init` (because `reset_id` fails), so it does **not** leave a dangling `PS(http_session_vars)` reference. It leaves only stale `PS(id)` and `send_cookie=1`.

---

## 2. Mechanism and Source Path

### 2.1 Leave send_cookie at 1

In `ext/session/session.c`:

~~~c
static zend_result php_session_initialize(void)
{
    ...
    if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {      /* empty id -> create a new one */
        ...
        PS(id) = PS(mod)->s_create_sid(&PS(mod_data));
        ...
        if (PS(use_cookies)) {
            PS(send_cookie) = 1;
        }
    }
    ...
    if (php_session_reset_id() == FAILURE) {    /* fails here; track_init does not run */
        php_session_abort();
        return FAILURE;
    }
    php_session_track_init();
    ...
}
~~~

`php_session_send_cookie()`:

~~~c
if (SG(headers_sent)) {
    php_error_docref(NULL, E_WARNING,
        "Session cookie cannot be sent after headers have already been sent");
    return FAILURE;
}
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
~~~

Key points:

1. **`headers_sent` must be 1.** Trigger this with a `max_input_vars` warning: when the variable count exceeds 1000, `main/php_variables.c` calls `php_error_docref(NULL, E_WARNING, "Input variables exceeded ...")`. In the lab, `display_errors=On` emits the warning in the response and sets `SG(headers_sent)=1`.
2. **The id's first byte must be 0.** Set the multipart `PHPSESSID` value to one byte, `\x00`. The FORMDATA branch of `php_session_rfc1867_callback` requires `value_len != 0`, so `progress->sid` becomes a length-1 string containing `\0`. At FILE_START, `PS(id) = zend_string_init(progress->sid)`; then `!ZSTR_VAL(PS(id))[0]` is true and the “create new id” branch sets `send_cookie=1`.
3. `reset_id` fails because headers were sent, leaving `send_cookie` at 1; `php_session_track_init()` does not run, so no `$_SESSION` reference is created.
4. At the end of A, a 12 MB ordinary field triggers `memory_limit=8M` OOM. Bailout skips request shutdown and leaves `ps_globals.id` dangling (the random id is a 32-byte `zend_string`).

Measured after A in GDB with setarch -R:

~~~text
ps_globals.send_cookie = 1
ps_globals.id          = 0x7ffff5ea9000   (len=32, data0=0x35)
ps_globals.http_session_vars.type_info = 0 (UNDEF)
~~~

The response body also contains two useful warnings that remotely confirm the precondition:

~~~html
Warning: PHP Request Startup: Input variables exceeded 1000...
Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent
~~~

### 2.2 B Sends Set-Cookie Using Stale PS(id)

B has no file field, so it does not trigger `php_rinit_session(0)` at FILE_START (that would clear the PS globals). The multipart END event calls `php_session_rfc1867_cleanup()` → `php_session_initialize()` → `php_session_reset_id()`:

- `PS(use_cookies)=1` (default).
- `PS(send_cookie)=1` (left by A).
- B has not sent headers yet, so the cookie is sent.
- `php_url_encode` reads from `ZSTR_VAL(PS(id))` for `ZSTR_LEN(PS(id))` bytes. After B's fields reclaim the stale block, len/data are attacker-controlled.

### 2.3 Reclaim the Stale PS(id) Block

A's random id is 32 bytes; `zend_string_alloc(32)` = 24+32+1 = 57 → **64-byte bin**. With this lab request shape, the block is at `chunk + 0xa9000` (no-ASLR address: `0x7ffff5ea9000`).

During B request parsing, Zend MM pages the chunk again. Calibration found the stale address lies in an **80-byte bin page** in B's layout:

1. First send N fields with 48-byte values (`zend_string` = 24+48+1 = 73 → 80B bin). Each leaves a **live** 80B string, occupying slots in free-list order.
2. Unique 48-character values (`v%04d` + padding) identify which string lands at the stale address. In this lab, at `N=998` the cookie value begins with `v0892...`, so the 893rd field's string occupies that block.
3. Send **892** leading fields, then a forge field with a 79-byte value:
   - Raw buffer size: 79+1 = 80 → 80B bin.
   - Its value zend_string is 24+79+1 = 104 → 112B bin, so it does not take an 80B slot.
   - The raw buffer takes the “893rd 80B block,” which is the stale `PS(id)` block.
   - Raw buffer contents, with block start S and `PS(id)=S`:

     ~~~text
     S+0x00: gc (overwritten by free-list next on efree; irrelevant)
     S+0x08: h (arbitrary)
     S+0x10: len = 0x1000 (forged)
     S+0x18: data[0] = 'L', then padding
     ~~~

4. The raw buffer is `efree()`'d after field processing. Zend MM writes the free-list pointer only at block offset 0, leaving len at `+0x10` intact. B's END cleanup then reads `ZSTR_LEN(PS(id)) = 0x1000` and URL-encodes bytes starting from `S+0x18`.

After sending `Set-Cookie`, `php_session_valid_key()` in `ps_files_open()` rejects the id's illegal bytes and emits `Session ID is too long or contains illegal characters`. The warning comes after the leak has already been written to the response header and does not affect the result.

---

## 3. Reproduction

Environment (same as `NOASLR_REPORT.md`, with two additional requirements):

- `display_errors=On` (the warning must actually be emitted to set `headers_sent`).
- `session.use_cookies=1` (default; this lab previously had 0 and must be changed back).
- `memory_limit=8M`, `session.use_strict_mode=0`, `session.save_path=/tmp`, and `max_input_vars=1000` (default).

~~~bash
# Target host 172.16.0.103; ASLR may be on or off. These are the no-ASLR calibration commands.
cd ~/php2shell-work

# A: 1001 fields trigger max_input_vars warning; PHPSESSID is one-byte \x00;
#    file field triggers FILE_START; 12 MB field OOMs
python3 send_a_leak2.py 1001 12

# B: 892 fields with unique 48-character values consume 80B blocks; the final
#    79-byte forge value's raw buffer lands in stale PS(id) and forges len=0x1000
python3 b_numleak2.py 892 1 0x1000
~~~

Example B response header (truncated):

~~~text
Set-Cookie: PHPSESSID=LAAAA...%B2%D0%82f%60h%3F%C3%A0%90%EA%F5%FF%7F...
...
Warning: PHP Request Startup: Session ID is too long or contains illegal characters.
~~~

Decode and extract pointers:

~~~bash
python3 tools/decode_leak.py logs/http_heap_leak_20261021.resp
# decoded=4096, candidate_ptrs=98, chunk_bases=7ffff5e00000:98
~~~

Raw response archive: `logs/http_heap_leak_20261021.resp`. Analysis output: `logs/http_heap_leak_20261021.txt`.

---

## 4. Calibration Data (This Build and Request Shape)

| Item | Value |
|---|---|
| `PS(id)` after A (stale `zend_string`) | `0x7ffff5ea9000` = chunk + `0xa9000` |
| Id length / allocation size | 32 / 64B bin |
| Bin containing the reclaimed block in B | 80B |
| Number of leading 48-character fields for location | At `N=998`, value `v0892` lands in the block |
| Leading fields before forge | `K=892` |
| Forge-field value length | 79 (80B raw buffer) |
| Forged len | `0x1000` |
| B response `Set-Cookie` | 11,548 characters (4,096B decoded) |
| Leaked pointers | 98; all `0x7ffff5e…`; chunk base `0x7ffff5e00000` |

Additional evidence that the same stale address is being reclaimed:

- With `N=998` and unique 48-character values, the cookie value is `v0892...` (len=48), showing that a live 80B string reclaimed the block.
- With numeric keys and short values (`b_numleak.py`), the cookie is still a normal 32-character id, showing that the block was not reused. Only the 80B live-string/raw-buffer allocation sequence reaches it.

---

## 5. Relationship to the ASLR Chain

This leak provides the **Zend MM chunk base**. In the same experiment, external address checks confirmed:

- The calibrated pure-HTTP A/B RCE chain succeeds **3/3** with `personality=0` (ASLR enabled).
- It uses chunk-relative offsets only: `R0 = chunk + 0x24e0` and fake HT data at `chunk + 0x6e0d8` (see the request shapes below).
- When libc base was obtained externally from `/proc/<worker>/maps`, `system = libc + 0x4c490` and the chain executed `id>/tmp/p1` fully.

Therefore, **the A/B memory chain itself is independent of ASLR**; only the source of its addresses was missing. This Set-Cookie leak supplies the heap base. The remaining value at the time of this note was a **libphp code pointer** (for `zif_system` at libphp + `0x43a870`; libc is not needed) or a libc pointer.

### 5.1 no-ASLR Recalibration in This Run

On `172.16.0.103` (not the original report's 172.16.1.112), the original fixed parameters did not directly apply:

~~~text
A: send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
B: send_b_rce2.py 16 2 0x7ffff5e6e0d8 0x7ffff7d14490 "id>/tmp/p1"
~~~

- Six `7:7` pads move A's reference to `0x7ffff5e024e0`; `R0-0x10=0x7ffff5e024d0` is exactly the start of a 56B block.
- B needs `N1=16` (31-character priming fields) to place the 55B raw buffer at `R0-0x10`.
- Local libc `system = 0x7ffff7d14490` (offset `0x4c490`); fake HT data = `0x7ffff5e6e0d8`.
- Proof: `/tmp/p1` contains `uid=33(www-data) ...`.

---

## 6. Limits

1. **Requires `display_errors=On`.** The path needs warning output to set `headers_sent`; without it, the `send_cookie=1` residue does not occur (the current lab setting is On).
2. Requires more than 1000 POST variables (default `max_input_vars=1000`) to trigger the warning; request body is about 1 MB.
3. Requires `session.use_cookies=1` (default) and `session.use_strict_mode=0` (default 0).
4. Chunk offsets (`0xa9000`), `N=998`, and `K=892` depend on this build/request shape. Recalibrate after changing PHP, field lengths, or boundary length. These are **chunk-relative offsets** and independent of ASLR.
5. The leak reads toward higher addresses from `PS(id)+0x18`. The current 4 KB area is an 80B string page and contains only heap pointers. A 1 MB leak (which can be sent) also showed heap pointers only, with no libphp/libc code pointer.
6. If len reads an uncontrolled value (such as a HashTable `arData` pointer or 64-bit hash), `php_url_encode`'s `safe_emalloc` fatals with `Possible integer overflow in memory allocation (3 * N + 32)`. This signals an uncontrolled len but yields no data.
7. A does not leave a dangling `PS(http_session_vars)` reference (`reset_id` fails before `track_init`), so it cannot be combined with the RCE A into one request. These are independent primitives that can run sequentially on the same worker.

---

## 7. Next Step at the Time: Leak a libphp Code Pointer

> **Follow-up as of 2026-10-21 (completed):** This goal was achieved, and the full pure-HTTP ASLR-on RCE was later completed (two Set-Cookie leaks + `zif_system`), 5/5 in the lab. A uses 1001 fields with 39-byte values to place stale `PS(id)` at `chunk+0xb7400`. B uses 983 nested arrays to expand the HashTable for `$_POST['a0443']` to 16 elements. `PS(id)+0x10` reads `nTableSize=16`; the data area covers `nNextFreeElement` and `pDestructor` (`ZVAL_PTR_DTOR = libphp+0x613c50`). Full chain, payload, and driver are in [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md). The original analysis below is retained.

Goal: obtain a libphp code address (for example, HashTable `pDestructor = ZVAL_PTR_DTOR`) and combine it with the known chunk base and g18's Zend-only payload (`zif_system`, libphp + `0x43a870`) for **fully pure-HTTP ASLR-on RCE with no external addresses**.

Confirmed experimental facts:

- With 998 nested-array fields named `aNNNN[0]`, B creates many 56B HashTable pages in the chunk. A no-ASLR GDB scan found 73 libphp pointers per page at offsets including `0x2000, 0x76000, 0x7b000, …, 0xa9000, 0xad000, 0xb2000, …`.
- Current stale `PS(id)` is at `chunk+0xa9000`, which is a 56B HashTable page under nested-array B. The remaining problem is to make the qword at `PS(id)+0x10` a moderate len rather than an `arData`/hash pointer.
- Promising approaches, in priority order:
  1. Move `PS(id)` in A to `HT+0x18`. Then `len=nNextFreeElement` and data begins at `HT+0x30=pDestructor`. This needs `PS(id) ≡ page+0x18 (mod 56)`. Since `PS(id)=page+64m` (A uses the 64B bin), `m ≡ 3 (mod 7)`, such as `page+0xc0` or `page+0x280`. Scan A's field lengths, boundary lengths, and file-field shapes for a reachable offset.
  2. Or move `PS(id)+0x10` to `HT+0x20` (`len=nTableSize|nInternalPointer`). This needs `PS(id) ≡ page+0x10 (mod 56)`, or `m ≡ 2 (mod 7)` (such as `page+0x80`). Make the HashTable large enough, for example with 128 elements per array, to read through pDestructor.
  3. Move PS.id to a low offset in a libphp-pointer page (such as `0x2000`). This needs a smaller A pre-heap or a different warning trigger; with 1001 fields, the id currently lands no lower than about `0x61040`.
- Once the libphp base is known, RCE B can use `zif_system` plus the fake `zend_function`/`execute_data` layout from `tools/d_aslr.php`'s Zend-only payload. It needs the chunk base and libphp base, not libc.

---

## 8. Files

| File | Purpose |
|---|---|
| `tools/send_a_leak2.py` | Leak A: 1001 fields + `max_input_vars` warning + empty/NUL PHPSESSID + file + OOM |
| `tools/send_a_leak3.py` | Leak A variant with adjustable field-name/value lengths and boundary length (move `PS(id)`) |
| `tools/b_numleak.py` | B with numeric keys/short values (check whether stale block was overwritten) |
| `tools/b_numleak2.py` | **Final B:** consume 80B blocks with 48-character values + 79-byte forge field |
| `tools/b_consume.py` / `b_consume2.py` | 80B/64B block-consumption experiments |
| `tools/b_nested.py` | Nested-array B (place 56B HashTable pages throughout the chunk) |
| `tools/send_b_leak.py` | Early B (raw stale id / forged-header prototype) |
| `tools/decode_leak.py` | Decode `Set-Cookie` and extract pointers/chunk base |
| `tools/aslr_demo.sh` | ASLR-on check; reads maps externally and verifies relative A/B layout 3/3 |
| `logs/http_heap_leak_20261021.resp` | Raw leak response (4096B decoded / 11,548-character cookie) |
| `logs/http_heap_leak_20261021.txt` | Decoded pointer list and chunk-base statistics |

---

## 9. Disclaimer

For vulnerability research and reproduction in authorized environments only. Request shape, block offsets, and bin sequence depend on this lab's PHP 8.4.26 build and Apache/mod_php configuration; recalibrate after changing the build or configuration.
