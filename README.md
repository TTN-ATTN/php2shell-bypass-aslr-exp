# php2shell — PHP 8.4.26 Session Vulnerability Reproduction

Under the constraints of fully remote, HTTP-only exploitation, a target page without `session_start()`, and no PHP files written on the target, a single `exploit.py` achieves RCE on PHP 8.4.26 + Apache prefork + mod_php. The official `php:8.4.26-apache` image has been tested successfully in 3/3 one-shot runs (`PROOF: uid=33(www-data)...`). The current version requires `display_errors=1`; the pure-HTTP heap leak also works with `display_errors=0`, while complete RCE in that configuration is still under development.

## Run

Copy and run the complete command sequence below. This repository does not compile PHP or Apache and has no `docker build`; the environment uses the official `php:8.4.26-apache` image with configuration mounts from `docker/`.

~~~bash
# Requirements: Docker Engine/Desktop, Docker Compose v2, and Python 3.9+
git clone https://github.com/9bie/php2shell-bypass-aslr-exp.git
cd php2shell-bypass-aslr-exp

# 1) Pull the official image (PHP 8.4.26 / Debian 12 / Apache prefork)
docker compose -f docker/docker-compose.yml pull

# 2) Start the target: one worker, display_errors=On, memory_limit=8M
docker compose -f docker/docker-compose.yml up -d

# 3) Wait for Apache and confirm the ordinary page is available
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8088/index.php >/dev/null 2>&1 && break
  sleep 0.5
done
curl -s http://127.0.0.1:8088/index.php   # OK

# 4) Run the complete exploit with one command; the first run reads libphp offsets automatically
python3 exploit.py -u http://127.0.0.1:8088/index.php
# PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

If you are already in the repository directory, skip `git clone` and `cd`. You can also skip `pull`; `up -d` pulls the image automatically.

`exploit.py` handles worker rotation, both leak stages, `zif_system` execution, and proof retrieval. Each stage has built-in retries. The tested environment is:

| Component | Version | Source |
|---|---|---|
| PHP | 8.4.26 (NTS, mod_php) | `php:8.4.26-apache` |
| Base system | Debian 12 (bookworm) | Same image |
| Apache | 2.4.69 (Debian 12 package in the official image; tested) | Same image |
| MPM | prefork, one worker | [docker/apache.conf](docker/apache.conf) |
| Apache in lab reports | 2.4.68 (original lab build, `--profile lab`) | For an exact match, use the 2.4.68 tag from [apache/httpd](https://github.com/apache/httpd) |

Official image repository: [docker-library/php](https://github.com/docker-library/php) (Docker Hub: [`php:8.4.26-apache`](https://hub.docker.com/_/php)); PHP source: [php/php-src](https://github.com/php/php-src) (tag `php-8.4.26`).

On its first run, the exploit invokes [docker/offsets.py](docker/offsets.py) to read the actual `zif_system` and `zval_ptr_dtor` offsets from the container's `libphp.so`, then writes them to `out/offsets.env`. `exploit.py` loads that file automatically, so you do not need to edit offsets after changing or upgrading the official image. The default command is `id>/out/p1` (10 bytes). The container's `/out` is mounted to the repository's `./out`, so the proof is written on the host:

~~~text
[*] target http://127.0.0.1:8088/index.php (cmd='id>/out/p1')
[*] no offsets file; reading libphp symbols from container php2shell-target
zif_system     0x...
zval_ptr_dtor  0x...
[+] chunk base = 0x...
[+] libphp base = 0x...
[*] stage 3: HTDATA=0x... ZIF=0x...
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

Commands in the payload are limited to **14 bytes**. To run an arbitrary command, write a script in the mounted directory and execute it with `sh</out/c` (8 bytes):

~~~bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
~~~

Common options include `--profile`, `--cmd`, `--proof-file`, `--fetch`, `--zif-offset`, `--dtor-offset`, `--htdata-offset`, `--no-pre-rotate`, and `--retries`. The default profile is `bookworm` (official image); use `--profile lab` for the original lab build. Set `--offsets-file ''` to disable automatic offset lookup. If the container name is not `php2shell-target`, specify it with `--docker-container`.

The bookworm heap calibration is built in: stage 1 uses **841** fillers; stage 2 uses target array **406** with 16-byte element values; stage 3 uses `HTDATA=chunk+0x690d8`, A's padding is 6×(31,31), and A also includes a valid 32-character `Cookie: PHPSESSID` so B reuses the stale id (`send_cookie=0`) and avoids the session `Set-Cookie` header overwriting `val.type` at `R0+16). B uses a 15-byte carrier to overwrite the reference's `val.value`. The official image's libphp offsets are read automatically as `zif_system=0x465370` and `zval_ptr_dtor=0x65eb60`; the original lab uses `0x43a870` and `0x613c50`.

## Mechanism overview

The vulnerable path is session initialization triggered by `session.upload_progress` before RINIT, combined with dangling pointers left across requests after an OOM bailout. The example below uses the lab build; bookworm calibration values for the official image are listed above.

All attack traffic consists of ordinary multipart HTTP requests, and the target page contains only `<?php echo "OK\n"; ?>`:

0. **Worker rotation:** After `A_bigfields` (3 MB of live POST fields plus a 12 MB OOM), send a B request that initializes a session. The child exits with SIGABRT; prefork forks a new worker with the same libphp and chunk mappings.
1. **Heap leak:** A uses 1001 fields to trigger a `max_input_vars` warning (`display_errors=On` → `headers_sent=1`), and `PHPSESSID=\x00` creates a new id and sets `send_cookie=1`. The final 12 MB field causes OOM inside `php_session_initialize()`, leaving `PS(http_session_vars)` dangling. In B, a 56-byte multipart raw value buffer reclaims the old reference, while a live 192-byte zend_string carries a fake HashTable. An out-of-bounds read in `php_url_encode()` places Zend MM chunk pointers in `Set-Cookie` (4096 bytes, 98 pointers).
2. **libphp leak:** A places dangling `PS(id)` at `chunk+0xb7400`. B's 56-byte HashTable page makes `ZSTR_LEN(PS(id))` read `nTableSize=16`; its data area contains `nNextFreeElement|pDestructor`. Since `pDestructor = ZVAL_PTR_DTOR = libphp+0x613c50`, the libphp base can be recovered from `Set-Cookie`.
3. **Command execution:** A uses six pads to place the dangling reference at `R0=chunk+0x24e0`. B uses a 55-byte raw buffer to overwrite `R0-0x10`; the fake HashTable is stored in a live 167-byte string at `chunk+0x6e0d8`, with `pDestructor = zif_system = libphp+0x43a870`. The call chain is:

   ~~~text
   php_session_track_init()
     zval_ptr_dtor(PS(http_session_vars))
       zend_reference_destroy(R0)
         zval_ptr_dtor(&ref->val)          # IS_ARRAY_EX
           zend_array_destroy(fake HT)
             zend_hash_destroy(fake HT)
               pDestructor(&bucket->val)   # zif_system
   ~~~

   The final stage calls `zif_system` inside libphp and does not need libc.

## Mechanism details

- **Why the page does not need `session_start()`:** A and B initialize the session in multipart callbacks before RINIT (`FILE_START → php_session_rfc1867_update → php_session_initialize()`; `END → php_session_rfc1867_cleanup → php_session_initialize()`). This does not depend on the script contents.
- **Why the pointer becomes dangling:** A hits an OOM bailout inside `php_session_initialize()` without clearing `PS(http_session_vars)` or `PS(id)`. When the next request initializes a session, `php_session_track_init()` calls `zval_ptr_dtor` on the stale value.
- **Why the allocation can be reclaimed:** During request parsing, ordinary multipart field values are allocated as zend_strings. The 56-byte block, 55-byte reference, and 167-byte string have sizes that reclaim the old reference or carry the fake HashTable.
- **Why it works with ASLR:** Two `Set-Cookie` out-of-bounds reads reveal the chunk base and libphp base. Between stages, a pure-HTTP abort/fork rotates the worker while preserving the address space. The final stage does not depend on libc.
- **Earlier approach:** Defect D, using `session_unset()` and a userland `__destruct` to trigger an `arData` UAF, achieved RCE on a custom PHP page ([NOASLR_REPORT.md](NOASLR_REPORT.md)). It violates the no-target-specific-PHP constraint and is included only as mechanism background.

Addresses and offsets relative to the chunk or libphp base (independent of ASLR):

| Location | Meaning |
|---|---|
| `chunk+0xb7400` | Stage 2 dangling `PS(id)` |
| `chunk+0xb73f0` | Stage 2 target HashTable (`a0443`) |
| `chunk+0x6e0d8` | Stage 3 fake HashTable string data |
| `chunk+0x24e0` | Stage 3 dangling reference `R0` |
| `libphp+0x613c50` | `ZVAL_PTR_DTOR` |
| `libphp+0x43a870` | `zif_system` |

The table above describes the lab build (`--profile lab`). For the official image (default `--profile bookworm`), calibration is: 841 stage 1 fillers; stage 2 target array 406 with 16-byte element values; stage 3 `HTDATA=chunk+0x690d8`, A padding 6×(31,31) plus a valid 32-character `Cookie: PHPSESSID`, and a 15-byte carrier in B. The libphp offsets are read automatically by `docker/offsets.py` (`0x465370` / `0x65eb60`).

For the detailed mechanism, GDB evidence, and request calibration, see [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md) (heap leak), [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (libphp leak and full chain), [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md) (leak without `display_errors`), and [NOTES.md](NOTES.md) (root cause and source locations).

## Reproduction notes

- **One command runs the full exploit:** `python3 exploit.py -u ...` handles worker rotation, heap and libphp leaks, and `zif_system` execution. It needs no target-side files, no `session_start()`, and no local signals.
- **HTTP only:** Attack traffic is multipart POST, and the target webroot contains only `<?php echo "OK\n"; ?>`.
- **Environment:** The official `php:8.4.26-apache` image (PHP 8.4.26 / Debian 12 / Apache 2.4.69 prefork) with [docker/php.ini](docker/php.ini) and [docker/apache.conf](docker/apache.conf), using the default `--profile bookworm`, passed 3/3 tests. The original lab build (Apache 2.4.68, minimal PHP) uses `--profile lab`; chunk offsets and stage 3 trigger settings were calibrated separately for both profiles.
- **Requirements:** Current RCE requires `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, `session.use_cookies=1`, `session.use_strict_mode=0`, and a single-worker prefork setup. Full RCE with `display_errors=0` is still in progress.
- For vulnerability research and reproduction in authorized environments only.
