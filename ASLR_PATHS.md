# ASLR Path Analysis: Pure Zend Bypass vs. Address Leak

Date: 2026-10-21
Prerequisite: Pure-HTTP RCE with ASLR disabled has been achieved (`NOASLR_REPORT.md`).
Constraints: **Fully remote, HTTP only, with no target-specific PHP constructed on the target.** The target page contains only an ordinary `echo` and does not call session APIs.

This document analyzes two paths with ASLR enabled. Earlier leaks/ROP results using custom PHP are not treated as valid deliverables.

---

## 0. Summary

| Path | Current assessment | Main blocker |
|---|---|---|
| Path 1: pure Zend bypass without a leak | No reliable primitive found | Every controlled write ends in NUL; a partial overwrite forces an ASLR-related byte to a fixed value; no known fixed function address |
| Path 2: pure-HTTP address leak | No usable entry point found under default settings | Default `session.serialize_handler=php` rejects session keys containing `\|`; earlier leak requires `php_serialize` plus userland `__serialize` reentry |

Under “default php.ini + vanilla session page” constraints, ASLR has not been bypassed by these paths. The experiments, source evidence, and next testable leads are below.

---

## 1. Existing Primitive

The key write primitive in the no-ASLR chain is:

1. Request A OOMs, leaving a dangling `PS(http_session_vars)` zend_reference (R0).
2. In request B, a 56B raw value buffer can overwrite R0 with:
   - `R0+0x00` gc: refcount=1, type=IS_REFERENCE
   - `R0+0x08` val.value: arbitrary 8-byte pointer
   - `R0+0x10` val.type: 0x307 (IS_ARRAY_EX)
   - `R0+0x18` sources: 0
3. Destructor path:
   `zend_delete_global_variable` → `zval_ptr_dtor` → `zend_reference_destroy` → `zend_array_destroy(val.value)` → `zend_hash_destroy` → `pDestructor(&bucket->val)`.
4. The best place for a fake HashTable is the data of a **live 192B zend_string** (L=167), because its gc is not overwritten by the free-list next pointer. Its contents are the field value and are controlled from data+0.

Therefore, under ASLR, the missing value is `val.value` (heap address) and/or `pDestructor` (libc/libphp code address).

---

## 2. Path 1: Pure Zend ASLR Bypass Without a Leak

Goal: construct an ASLR-insensitive pointer/function pointer without using any leak.

### 2.1 Option A: Reuse the Old Reference's `val.value = A0` (Real Session HashTable)

- In A, the old reference's `val.value` points to the real session HashTable A0. Under no-ASLR, measured A0 = `0x7ffff5e03268` (`R0+0xf48`).
- If B leaves R0's `val.value` intact and makes A0's memory attacker-controlled as a fake HashTable, the heap base is unnecessary.
- Feasibility checks:
  - A0 is a 56B HashTable structure (`sizeof(zend_array)=56`, bin 6).
  - A0's original `pDestructor` is `ZVAL_PTR_DTOR` (a libphp pointer).
  - A0 must be reclaimed by a **live**, content-controlled allocation while keeping `gc.type == IS_ARRAY`.
  - B has two types of content-controlled allocation:
    1. Raw value buffer from `multipart_buffer_read_body`. It is `efree()`'d after field processing; on free, the allocator writes `next_free_slot` at block offset 0, overwriting gc. Then `GC_DELREF` does not reach zero, so the array destructor is not entered.
    2. Live zend_string. Its gc type is IS_STRING (6), so `rc_dtor_func` calls `zend_string_destroy`, not `zend_array_destroy`.
  - A live real HashTable has the correct type=7, but `pDestructor` is the real `ZVAL_PTR_DTOR`; we cannot change it without changing gc.
- Conclusion: reusing A0 requires a “live, controlled, type=IS_ARRAY” allocation, which is not currently available.

### 2.2 Option B: Partial Pointer Overwrite (Preserve libphp High Bytes)

Idea: change A0's `pDestructor` from `ZVAL_PTR_DTOR` to another function/gadget inside libphp by overwriting only the low 2–3 bytes and preserving the high bytes of the libphp base. This would avoid a leak.

Two problems need to be solved:

1. **Can we write to A0+0x30 while changing only low bytes?**
   - Writes from a string/raw buffer always append a NUL:
     `zend_string_init` writes 0 at data[len]; `multipart_buffer_read_body` writes 0 at out[total].
   - If N bytes are written starting at `pDestructor`, byte N is always 0.
   - For example, a 2-byte overwrite controls `b0,b1` and sets `b2=0`; a 3-byte overwrite controls `b0..b2` and sets `b3=0`.
   - The high bytes of the target libphp address—`b3/b4/b5`—contain ASLR randomness. Forcing one to 0 works only if the corresponding absolute address byte is already 0, which depends on the base and is unreliable.
2. **Is there a useful target within a 2–3 byte range?**
   - Measured symbols in the current unstripped libphp build:
     ~~~text
     zif_system          0x43a870
     zend_call_function  0x566d20
     zend_hash_destroy   0x5cbb90
     zend_array_destroy  0x5cbdc0
     zval_ptr_dtor       0x613c50
     ~~~
   - `zval_ptr_dtor` is 0xacf30 away from `zend_call_function` (about 700 KB) and 0x1d93e0 from `zif_system` (about 1.9 MB).
   - A 2-byte partial overwrite can jump only within the same 64 KB. A 3-byte overwrite also forces b3=0 and therefore depends on the base byte. No useful gadget in the same 64 KB has been found.
   - libphp imports `popen` only (visible in `objdump -T`), not `system`. `popen@plt` also needs the libphp base, and the second argument in rsi is not controlled.
   - The earlier `zend_call_function → zif_system` intelligence requires a fake FCI and is another path that needs the libphp base.

Conclusion: partial overwrite is currently the closest “pure Zend” idea, but the NUL terminator is a hard blocker unless an **arbitrary-length prefix write without a terminator** can be found.

### 2.3 Option C: Allocator-Written Pointer (free-list next/shadow)

- A freed block has a plain `next_free_slot` heap pointer at offset 0 and an XOR-encoded shadow at offset size-8.
- If the fake reference's `val.value` is placed at a freed block's `next_free_slot`, the allocator writes a real heap pointer for us.
- However, that pointer targets the start of **another freed block**, whose offset 0 is also a next pointer, not a valid array gc. `GC_DELREF` will not reach zero.
- For alignment, `R0+8` must be the start of a bin slot. With `R0=0x...2320`, `R0+8=0x...2328` is divisible only by the 8B bin (page offset `0x328=808=8×101`); an 8B block has no controlled contents.
- Conclusion: this does not directly provide a heap pointer to a controlled fake HashTable.

### 2.4 Option D: Code at a Fixed Address

- The Apache main executable is PIE (`file /usr/sbin/apache2` reports a PIE executable); `libphp.so` and libc are ASLR-randomized.
- The only fixed executable page is vsyscall at `0xffffffffff600000`. It contains only gettimeofday/time/getcpu, not an arbitrary syscall or RCE.
- The main executable/modules have no usable fixed `system`/`popen`/`execve` PLT entry (imports checked; the PIE base is also randomized).
- Conclusion: no fixed code address is available.

### 2.5 Path 1 Summary

With the current primitive, a pure Zend bypass without a leak needs one of:

- A **partial write without NUL** that changes low bytes of A0's `pDestructor` while preserving high bytes.
- A **live, controlled, type=IS_ARRAY allocation** that can reclaim A0.
- A combination of an **allocator-written pointer and controlled contents**.
- A real libphp function pointer that permits the exploit within a single 64 KB range.

None is confirmed. The most useful next work is to measure functions/gadgets within 64 KB of libphp's `zval_ptr_dtor` and find a PHP allocation path that writes N bytes without a terminator.

---

## 3. Path 2: Pure-HTTP Address Leak

Goal: leak the heap chunk base, libphp base, or libc base into an HTTP response, then calculate addresses dynamically for the no-ASLR chain.

### 3.1 Default Session Serializer Restrictions (Tested)

Defaults:

~~~ini
session.serialize_handler = php
session.use_only_cookies = 1
~~~

Before writing each session key, the default `php` encoder does:

~~~c
smart_str_appendl(&buf, ZSTR_VAL(key), ZSTR_LEN(key));
if (memchr(ZSTR_VAL(key), PS_DELIMITER, ZSTR_LEN(key))) {
    /* key contains '|': abandon the whole encode and return NULL */
    fail = true;
    break;
}
smart_str_appendc(&buf, PS_DELIMITER);
php_var_serialize(&buf, struc, &var_hash);
~~~

GDB observation in `ps_files_write`:

~~~text
progress key = upload_progress_X|E:20:"AAAAAAAAAAAAAAAAAAAA";
FWRITE key=injtest0005 klen=11 vlen=0
php_session_decode len=0
~~~

That is, if a progress key contains `|`, the encoder returns NULL and writes an empty session. END cleanup reads session data of length 0. **Under the default configuration, an arbitrary serialized payload cannot be injected through a key.**

The default decoder also does not parse C strings:

~~~c
while (*q != PS_DELIMITER) {
    if (++q >= endptr) { retval = FAILURE; goto break_outer_loop; }
}
~~~

NUL cannot bypass the `|` delimiter.

### 3.2 Dependencies of the Earlier Leak Primitive (Do Not Meet Current Constraints)

Both leaks in section 10 of `NOTES.md` require:

1. `session.serialize_handler = php_serialize` (non-default; set through script `ini_set` or application configuration).
2. A userland class `C::__serialize()` that frees the `$_SESSION` array during encoding, then reclaims it with `zend_reference`/`stream_bucket_new` to create an encoder UAF.
3. The application to call `session_encode()` and output or store the result somewhere readable.

The current target page has only ordinary `echo`, no userland class, and no `session_encode()` output; the default handler is `php`. Therefore those leaks are unreachable under the current constraints.

### 3.3 Session Data Controllable over Pure HTTP

With defaults, the only data an attacker can influence that enters the session file is:

- The progress key (key name; cannot contain `|`).
- The fixed keys/values in the progress data array:
  `start_time`, `content_length`, `bytes_processed`, `done`, `files[0].field_name`, `files[0].name`, `files[0].tmp_name`, `files[0].error`, etc.
- `field_name`/`name` are attacker-controlled strings, but written as **serialized values** (`s:<len>:"...";`). They are binary-safe and cannot become a key or enum.

The PHP runtime generates the structure read by the session decoder. The attacker cannot supply `E:`/`O:`/`C:`/`R:` syntax or inject data across variables.

### 3.4 Candidate Leak Paths and Blockers

| Candidate | Result |
|---|---|
| Inject serialized `E:` through progress key → enum warning `%.*s` | Default `php` encoder rejects a key containing `\|`; writes 0 bytes |
| Out-of-bounds read from `E:` length | `maxlen < len` check; input buffer limits len |
| Session file as leak carrier | Requires an encoder OOB write first; default encoder has none |
| OOB read/warning in built-in `unserialize` class handler | Default settings cannot inject `O:`/`C:`; progress data contains only arrays/strings |
| `%p`/pointer formatting in errors | Session/unserialize paths have no `%p`; only enum's `%.*s` |
| `session_start` warning prints id/path (only a candidate if the app calls it) | No memory address; id characters are restricted |
| `/proc/self/maps` | Requires target-side PHP to read the file, violating the constraint |

### 3.5 If php.ini Changes Are Allowed (Not Application PHP)

If `session.serialize_handler` is changed to `php_serialize`:

- The encoder no longer rejects `|` in progress keys (`php_serialize` serializes the whole array with `php_var_serialize` and does not inspect `|` in keys).
- A key can inject extra session variables and trigger decode warnings/built-in class handlers.
- The earlier two leaks still require reentry that frees the session array during encoding, which the vanilla page does not provide.

So changing INI alone does not create a leak. A reentrancy gadget in built-in PHP functionality is also needed; none has been found.

---

## 4. Next Experiments for the Two Paths

### Path 1 (Pure Zend)

1. **Measure libphp layout:** use `nm -D`/`objdump` to get offsets for `zval_ptr_dtor`, `zend_call_function`, `zif_system`, and `system@plt`, then check for a usable partial-overwrite target within the same 64 KB/16 MB range.
2. **Find a write without a terminator:** inspect `erealloc` growth, stream bucket, `smart_str`, and similar paths for an allocation that copies only a prefix without writing NUL. If found, it may permit a true low-byte partial overwrite of A0->pDestructor.
3. **Reclaim A0 while live:** try to reclaim A0 (56B HashTable) in B with a live controlled allocation while preserving `gc.type=IS_ARRAY`. For example:
   - Use session decode to create a real small array at A0.
   - Then use a write that changes only low bytes of `pDestructor` without touching gc.
4. **Align an allocator pointer:** scan A parameters (progress-key length, SID length, file count/size) to move R0 so `R0+8` is a slot in a larger bin and the free-list next pointer can yield a heap pointer to a controlled location.

### Path 2 (Leak)

1. **Under defaults only,** enumerate paths that print attacker strings in warnings (such as `php_error` calls with `%s`/`%.*s`) and check for `%.*s` with an unchecked length.
2. **Fuzz built-in `Serializable` class handlers:** inspect C implementations of `unserialize()` for `ArrayObject`, `SplObjectStorage`, `DateTime`, `SimpleXMLElement`, `ZipArchive`, `Phar`, etc., looking for OOB reads or warnings that print input. The default configuration currently prevents injecting `C:`/`O:` into a session, so this matters only with `php_serialize` or application-controlled session data.
3. **Progress data values:** check whether `field_name`/`name`/`tmp_name` are printed with `%.*s` on any error path; none has been found in the current source.
4. **BG(unserialize) write primitive:** if the `serialize_lock` dependency can be bypassed over pure HTTP, `var_push`'s arbitrary write could forge a `zend_string.len` and trigger a `%.*s` warning leak. This path is paused because it needs application-level `__wakeup`/autoload.

---

## 5. Assessment Under the Constraints

- **Pure Zend without a leak:** theoretically clean, but constrained by the NUL terminator and lack of fixed code addresses; no reliable construction is known.
- **Address leak:** with the default `php` serializer, progress-key injection is rejected directly by the encoder's `memchr('|')` check. Earlier leaks need a non-default serializer plus userland reentry. No entry point has been found for pure HTTP without application code.
- If a **non-default php.ini** is allowed (`session.serialize_handler=php_serialize`), research can continue on key injection + built-in class handlers. This still avoids writing target-specific PHP, but diverges from defaults.
- If the target application has a session object/progress endpoint (an application gadget), the earlier `php_serialize` leak chain may be reusable. That depends on application code and does not meet the current vanilla-session-page constraint.

Under the strict constraints, the deliverable should be labeled **no-ASLR RCE**. Neither ASLR path is complete; one of the experiments above must break through.

---

## 6. Addendum: Measured Fixed Zend Offsets (2026-10-21)

After the user suggested that “some Zend addresses may be fixed,” we made these measurements.

### 6.1 Fixed Offsets

With ASLR enabled (`randomize_va_space=2`), trigger A/B and inspect in `php_session_track_init`:

- Old reference R0 = **chunk + 0x2320**, unchanged across three master restarts.
- Session HashTable A0 (`R0->val.value`):
  - With A's PHPSESSID length 8..32: A0 = **chunk + 0x3268**.
  - With A's PHPSESSID length 1..5: A0 = **chunk + 0x3230**.
- Zend main chunk base is aligned to 2 MB.
- Under one Apache master, killed workers with SIGKILL five times; each new worker had the same chunk base (example: `0x7fa32de00000`, B=7). That means:
  - **The chunk base stays fixed for one master lifetime.**
  - It is randomized again only after master restart; a worker crash does not let B retry at a new base.

### 6.2 Chunk Header Is Not a Code Trampoline

Dump of chunk+0x000..0x100:

- `heap`/`next`/`prev`/`free_slot[]` are all heap pointers.
- `size`/`peak`/`chunks_count`/`pid` are small integers.
- There is no libphp/libc code pointer.
- A 1-byte partial write can only point the old `val.value` to `chunk+0x00XX`, inside the header, which has no usable `pDestructor`. A 2-byte partial write zeroes b2 (the low 3 bits of the 2 MB index inside a 16 MB range); that slot was measured as the library's read-only `.eh_frame` data, not a controlled Zend chunk.

### 6.3 Old Contents of A0

Old HashTable at A0=chunk+0x3268:

~~~text
A0+0x00 gc        = 0xffffffff00000106   (refcount is not 1)
A0+0x10 arData    = chunk+0x33c0
A0+0x30 pDestructor = libphp zval_ptr_dtor (real code pointer)
~~~

Since the refcount is not 1, a destructor that leaves `val.value` intact only decrements the reference; it does not enter `zend_array_destroy`. This is why forging a reference was previously necessary.

### 6.4 New Primitive: Binary PHPSESSID Writes A0's gc

- `php_session_valid_key()` scans as a C string. A PHPSESSID value can be `validprefix\0<binary>`, and bytes after NUL still enter the `progress->sid` / `PS(id)` zend_string.
- `PS(id)` is made directly with `zend_string_init`. Its raw value buffer is freed first; later the 320B `PS(id)` reuses that slot.
- Measured: SID length 280, value `sidvalid\0...`, and a fake gc at SID offset 0x110. During B's track_init, **A0's first qword becomes `0x0000000700000001`** without needing to know the chunk base.
- The live 320B string is in page3 slot 0x3140 (data at 0x3158); A0=0x3268 is exactly data+0x110.
- This means **gc (refcount=1, type=IS_ARRAY) can be written relative to A0**.

### 6.5 Still Unsolved: pDestructor / arData

- For A0=0x3268, `pDestructor` at A0+0x30=0x3298 crosses into the **next 320B slot** (0x3280). Measurements show it is overwritten by B's 320B allocation with `0xffff...`, losing the original `zval_ptr_dtor`.
- If A's SID is changed to 1..5, A0=0x3230, and `pDestructor` is in the same 320B slot. However:
  - To cover/control gc/flags/arData, the 320B string must be at least 257 bytes, but `pDestructor` is at data offset 0x108=264, so the string copy **fully overwrites pDestructor**, losing its high bytes.
  - To preserve `pDestructor`, length must be ≤263; then `arData` (data offset 0xd8+0x10=232) has already been overwritten and must be set to an absolute pointer, but the base is unknown.
  - To change only gc/flags without touching `arData`, L must be <232, but the 320B bin requires L≥257. Bin size and copy length are coupled, so this cannot be done.
- The 8B header-key approach also failed: `R0+8=0x2328` is aligned only to an 8B slot within page2, while page2 is occupied by startup 56B allocations (`MAP2=bin6`), not bin0. Also, the 8B free-list shadow covers the entire qword, so old high bytes cannot be preserved.

### 6.6 Conclusion

Fixed Zend offsets are real and useful:

- R0, A0, and the fake HT have fixed offsets relative to the chunk.
- The chunk base stays fixed within one master lifetime.
- The old real `zval_ptr_dtor` pointer is at A0+0x30.

But these facts alone do not bypass ASLR because:

1. A **partial write without NUL that changes only a prefix** is needed to preserve high bytes of `pDestructor`.
2. Or `arData` must point to a fake bucket at an **attacker-controlled absolute address**.
3. Every currently available write copies the whole string and appends NUL, and bin geometry is fixed. Neither option has been achieved.

Most useful next steps:

- Use A parameters to move A0 so “string data ends at pDestructor+1” and bin/slot geometry both work (neither 0x3230 nor 0x3268 currently does).
- Find a Zend allocation/copy path that writes N bytes without a terminator.
- Or leak the chunk base first (fixed within one master, so one leak can be reused).

---

## 7. Addendum: A0 Shapes and Measured page3 Bin

### 7.1 A0 Has More Than Two Possible Values

Scanned A's PHPSESSID length more finely (no-ASLR, page3 fixed 320B bin):

| A SID length | A0 (chunk offset) | gc at A0+0 | A0+0x30 |
|---|---|---|---|
| 1–13 | `0x3230` | `0x80000000005978e8` (not an array HashTable) | `0x7ffff5e61208` |
| 14–21 | `0x3268` | `0xffffffff00000106` (huge refcount) | Real `zval_ptr_dtor` |
| 22–23, 32–40 | `0x3230` | Same as above | Not pDestructor |
| **24–30** | **`0x3310`** | **`0xc000040700000001`** (rc=1, type=IS_ARRAY) | **Real `zval_ptr_dtor`** |

`0x3310` is the first A0 that can already be used as a HashTable:

~~~text
A0=chunk+0x3310
A0+0x00 = 0xc000040700000001   gc: rc=1, type=IS_ARRAY
A0+0x10 = chunk+0x4900/0x4540  arData (real heap pointer)
A0+0x30 = libphp zval_ptr_dtor (real code pointer)
~~~

In other words, **there is no need to forge gc/flags**; the stale reference's `val.value=A0` and `zend_array_destroy(A0)` take the real array path.

### 7.2 page3 Bin Is Fixed

Under both ASLR and no-ASLR, B's chunk page map is always:

~~~text
page1 bin3 (32B)
page2 bin6 (56B)
page3-7 bin16 (320B)
page8-12 bin20 (640B)
~~~

Tested custom request header `X-Pad: A*N` with N=0/96/320/480/700/1000; page map did not change. GDB on the first 320B allocation in `zend_mm_alloc_small_slow`:

~~~text
zend_mm_alloc_small_slow(bin_num=16)
  zend_hash_real_init_mixed_ex
  zend_hash_real_init_mixed
  _zend_hash_add_or_update_i
  zend_hash_add
~~~

The first 640B allocation is `zend_hash_do_resize` for the same HashTable. Therefore page3's 320B bin is the startup allocation of HashTable arData; **request headers/fields cannot change it**.

### 7.3 320B Slot Geometry and A0=0x3310

A0=0x3310 is in page3's 320B slot 2 (block 0x3280, data 0x3298):

~~~text
A0 = 0x3310 = slot2 data + 0x78
arData       = A0+0x10 = slot2 data + 0x88
nNumUsed     = A0+0x18 = slot2 data + 0x90
pDestructor  = A0+0x30 = slot2 data + 0xa8
~~~

- A 320B zend_string in slot 2 has data starting at 0x3298; its length can only be 232..295.
- To overwrite/control `pDestructor` (data offset 0xa8=168), the copy must be at least 168 bytes. But the minimum string length for the 320B bin is 232, so the copy **necessarily overwrites arData** (offset 0x88=136) and the preceding gc/flags as well.
- To NUL only pDestructor byte 0 while preserving its high bytes requires L=168. That allocation is 193 bytes → **224B bin**, which cannot occupy slot 2 in the 320B bin.
- To preserve arData, L must be <136, which also cannot occupy the 320B slot.
- Although A0=0x3310 has valid gc, it is still blocked by “copy length vs. bin size”: pDestructor cannot be partially overwritten while preserving arData.

### 7.4 Current Assessment

- Fixed Zend offsets are confirmed, and A0=0x3310 provides a real controlled starting point with rc=1.
- However, page3's 320B bin is fixed, and the data-length window for its 320B slots (232..295) does not fit A0's internal fields (arData at offset 136, pDestructor at offset 168).
- A write primitive that copies a prefix without NUL, or a relative pointer that makes arData point to controlled data, is still missing.

This path is not complete. no-ASLR RCE remains the only verified code execution.
