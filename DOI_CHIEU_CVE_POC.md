# Đối chiếu PHP2Shell và PoC trong repository

Ngày đối chiếu: 22/10/2026. Commit được đọc: `4221a0ff634870a4945664b3a0c932326f8d44e4`.

Phạm vi: đọc `exploit.py`, cấu hình Docker, các tài liệu nghiên cứu và artifact HTTP; đọc các phần liên quan trong `src/php-8.4.26.tar.gz`; đối chiếu advisory và mã nguồn upstream 8.4.27. Không chạy exploit, khởi động container hay gửi payload đến các IP xuất hiện trong ghi chép.

## 1. Kết luận

`exploit.py` triển khai chuỗi khai thác bộ nhớ PHP qua nhiều request: để lại session globals sau OOM, đọc bộ nhớ qua cookie, rồi lợi dụng destructor của cấu trúc giả. Cấu trúc mã phù hợp với cơ chế được công bố; artifact leak có nội dung kiểm tra lại được. Tuy nhiên, phiên rà soát này không xác nhận độc lập việc thực thi lệnh.

Nếu phân loại theo mô tả hiện hành của PHP, cơ chế cross-request trong PoC khớp nhất với **CVE-2026-109619 — stale global state**. OOM là tác nhân làm đứt vòng đời trạng thái; chỉ thấy OOM không đủ để kết luận PoC chứng minh riêng **CVE-2026-109618 — OOM corruption**. Hai lỗi và bản vá có liên quan. [Advisory 109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w), [advisory 109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

## 2. Đối chiếu nguồn công khai

| Nguồn | Nội dung cần phân biệt | Liên hệ với repository |
|---|---|---|
| PHP Security, advisory chính thức | 109618: bộ nhớ chưa khởi tạo hoàn chỉnh bị xử lý sau OOM; 109619: trạng thái request cũ bị dùng trong request sau | PoC hiện tại thể hiện rõ trường hợp thứ hai |
| Wiz, nhóm nghiên cứu công bố | Mô tả cả `BG(unserialize)` UAF và leak stale `PS(id)` ra cookie | Leak trong repo cùng họ; endpoint RCE của `exploit.py` dùng `PS(http_session_vars)` thay vì chuỗi `BG(unserialize)` |
| `syrex1013/php2shell`, PoC cộng đồng | Mô tả cached `zval*` trong upload progress và upload bị ngắt quãng | Không nên dùng mô tả này thay cho phân tích A/B cross-request trong repo hiện tại |

Có khác biệt thực sự trong cách gắn số CVE: bảng của Wiz xếp upload-progress unserializer và memory disclosure dưới 109618, trong khi advisory PHP mô tả session lifecycle cross-request trong 109619. Vì vậy, báo cáo nên luôn ghi cả cơ chế và nguồn phân loại, tránh chỉ gắn một số CVE rồi suy ra mọi biến thể có cùng điều kiện. [Wiz Research](https://www.wiz.io/blog/php2shell-php-rce).

Mô tả cộng đồng về stale progress pointer là một giả thuyết/chuỗi riêng; bản thân việc upload thành công hay `bytes_processed` thay đổi không chứng minh RCE của chuỗi này. [PoC cộng đồng và mô tả của tác giả](https://github.com/syrex1013/php2shell).

## 3. Chuỗi thực tế trong `exploit.py`

| Bước | Vị trí | Hành vi và ý nghĩa |
|---|---|---|
| Chuẩn bị worker | `rotate()`, dòng 281 | Gửi multipart gây OOM và request tiếp theo để kích hoạt abort. Chủ động làm chết child là một phần của thiết kế |
| Leak heap | `stage1()`, dòng 304 | A tạo điều kiện để sót `PS(id)`/`send_cookie`; B tái sử dụng bộ nhớ của ID và làm cookie chứa dữ liệu vượt phạm vi chuỗi ban đầu |
| Leak module | `stage2()`, dòng 333 | B tạo các array để vùng nhớ cũ được hiểu chồng lên HashTable; cookie tiết lộ con trỏ destructor dùng để suy ra libphp base |
| Thực thi | `_fake_payload()`/`stage3()`, dòng 359/404 | Dựng reference/HashTable/khung gọi PHP giả; đường hủy session dẫn tới `zif_system` |
| Kiểm chứng | `main()`, dòng 576 | Đọc file proof ở local hoặc GET đường dẫn được cung cấp |

Khác biệt chính với nghiên cứu `BG(unserialize)` trong `NOTES_BG.md`: entry point thực thi của driver hiện tại là hủy `PS(http_session_vars)`, không phải ghi qua `var_entries` rồi thay object handlers. Không được cộng bằng chứng của hai chuỗi thành một lần tái hiện end-to-end.

ASLR được xử lý bằng hai leak địa chỉ, sau đó dùng offset tương đối đã hiệu chuẩn. Việc child prefork kế tiếp giữ ánh xạ hữu ích là giả định của môi trường và có log hỗ trợ. Không có cơ sở coi giả định này đúng cho mọi SAPI, mọi allocator hoặc sau khi master restart.

Target được mount chỉ chứa `<?php echo "OK\n"; ?>` (`docker/www/index.php`). Cơ chế upload progress chạy trong startup có thể đến session trước RINIT; do đó việc trang không gọi `session_start()` phù hợp với cấu trúc mã này.

## 4. Đối chiếu mã nguồn và bản vá

Trong source archive 8.4.26:

- `main/main.c:1873`: `php_hash_environment()` đứng trước `zend_activate_modules()` ở dòng 1874.
- `main/main.c:1928`: gọi module RSHUTDOWN phụ thuộc `PG(modules_activated)`; giải phóng request heap vẫn có đường chạy ở dòng 1981. Vì vậy, “skip shutdown” trong một số ghi chú nên hiểu chính xác là bỏ lỡ cleanup/reset cần thiết của module, không phải không có request shutdown nào chạy.
- `ext/session/session.c:236`: `php_session_track_init()` hủy giá trị session hiện có trước khi tạo mới.
- Cùng file, dòng 475–481: lỗi reset ID trả về trước `track_init()`; điều này giải thích vì sao leak ID và stale session reference là hai trạng thái khác nhau.
- Cùng file, dòng 3209/3370: multipart END có thể gọi session cleanup; FILE_START mới có lời gọi reset session ở dòng 3308. B không có file part tránh đường reset đó.
- `ext/standard/basic_functions.c:386`: reset `BG(unserialize)` nằm ở RINIT; `var_unserializer.re:60` có thể lấy lại `BG(unserialize).data` khi nesting level còn khác 0. Đây là cơ sở của track nghiên cứu decoder riêng.

Đối chiếu với tag upstream 8.4.27 thấy các thay đổi trực tiếp liên quan:

1. Session callback reset globals ngay `MULTIPART_EVENT_START`, trước xử lý nội dung multipart.
2. Update/cleanup kiểm tra kết quả khởi tạo session, thay vì tiếp tục vô điều kiện.
3. Upload-progress serialization có chế độ incomplete classes để hạn chế thực thi user code trước RINIT.
4. `php_basic_early_rinit()` reset serialization globals sớm.

Các thay đổi này xác nhận hướng sửa vòng đời trạng thái. Đây là đối chiếu source, chưa phải kết quả chạy PoC trên phiên bản đã vá. [Session 8.4.27](https://github.com/php/php-src/blob/php-8.4.27/ext/session/session.c), [basic functions 8.4.27](https://github.com/php/php-src/blob/php-8.4.27/ext/standard/basic_functions.c).

Commit tổng hợp `506e87fa7dcdd306975e5b8f8265ee03527aacbf` ghi rõ sửa cả hai CVE, thay cơ chế bailout khi OOM và reset các globals có thể bị truy cập trong startup. [Commit bản vá](https://github.com/php/php-src/commit/506e87fa7dcdd306975e5b8f8265ee03527aacbf).

## 5. Bằng chứng nào đã kiểm tra lại được?

Tôi giải mã cookie trực tiếp từ file `.resp`, không chạy các chương trình tạo payload:

| Artifact | Kết quả giải mã trong phiên rà soát |
|---|---|
| `logs/http_heap_leak_20261021.resp` | 4.096 byte; 98 cửa sổ 8 byte có dạng con trỏ; cùng quy về chunk `0x7ffff5e00000` khi căn 2 MiB |
| `logs/libphp_leak_20261021.resp` | 16 byte; phần sau chứa `0x7f7287a13c50`; trừ offset lab `0x613c50` được `0x7f7287400000`, khớp maps được ghi trong log tổng hợp |
| `logs/oomcookie_de0_aslr_1.resp` | 4.000 byte; 47 ứng viên con trỏ, quy về `0x7f1416e00000` |
| `logs/oomcookie_de0_aslr_2.resp` | 4.000 byte; 47 ứng viên con trỏ, quy về `0x7f9acd000000` |

Đây là kiểm tra tính nhất quán của artifact có sẵn. Không chứng minh nguồn gốc artifact, trạng thái máy lúc thu thập hoặc RCE trong môi trường hiện tại.

`logs/pure_http_aslr_20261021.txt` ghi 5/5 khi không có rotation đầu và 9/10 khi có rotation đầu trên **lab build**. README ghi 3/3 trên **official image**. Hai tập có cấu hình/offset khác nhau; không nên gộp thành một tỷ lệ thành công. Các log `system()` ở `logs/evidence.md` lại thuộc chuỗi cũ qua `session_unset()`, không chứng minh trực tiếp driver HTTP hiện tại.

`exploit.py` cũng đã được parse AST thành công; không import hay thực thi module.

## 6. Các điểm tài liệu và driver cần đọc thận trọng

### README mô tả sai stage 1

`README.md:77` nói OOM trong `php_session_initialize()`, stale `PS(http_session_vars)`, raw buffer 56 byte và fake HashTable 192 byte. Nhưng `stage1()` hiện dùng carrier 79 byte để giả độ dài ID; không tạo các cấu trúc ấy. `HTTP_HEAP_LEAK.md:28` còn chỉ rõ leak A thất bại trước `track_init()`, chỉ để lại stale ID và `send_cookie=1`.

Tương tự, `README.md:96` gom mọi OOM vào `php_session_initialize()` là quá rộng. Ở leak mặc định, field lớn nằm sau file và gây OOM trong quá trình parse multipart; track `display_errors=0` mới chủ đích ép OOM bên trong gửi cookie.

### “Pure HTTP” cần giới hạn phạm vi

Lưu lượng khai thác của driver là HTTP. Tuy nhiên:

- `exploit.py:503` tự gọi helper Docker khi target là localhost và chưa có offsets.
- `docker/offsets.py` dùng `docker cp` để lấy `libphp.so`, rồi đọc ELF symbols.
- Proof mặc định được đọc từ `out/p1` local nhờ bind mount `/out`.

Do đó lệnh demo mặc định cần quyền và dữ liệu local để chuẩn bị/quan sát. Điều này không bác bỏ cơ chế remote HTTP, nhưng không chứng minh driver tự xử lý một remote build bất kỳ chỉ từ URL.

### Offset tự động không bao phủ heap layout

Helper chỉ suy ra hai symbol offsets, không hiệu chuẩn vị trí heap, số filler, array mục tiêu hoặc padding. Ngoài ra, profile mặc định là `bookworm`, nhưng khi không có offsets và target không phải localhost, fallback ở dòng 521–524 vẫn dùng hằng số **lab**. Đây là hạn chế tái hiện cụ thể khi dùng remote URL.

### “PROOF” là một chỉ dấu, chưa phải xác minh chặt

Driver chấp nhận nội dung file không rỗng hoặc body HTTP 200 không rỗng (`exploit.py:591`). Đường `--fetch` không xác thực marker gắn với lần chạy và có thể đọc nội dung có sẵn. Ngược lại, không thấy proof không đủ kết luận lệnh không chạy; code cũng đã ghi khả năng thực thi blind.

### Có nhiều lớp nghiên cứu lịch sử

- `NOASLR_REPORT.md`/`tools/d.php`: chuỗi có PHP gadget do lab cung cấp, khác điều kiện endpoint trung tính.
- `NOTES_BG.md`/`logs/g19_BG_unserialize_103.md`: nghiên cứu decoder globals; log g19 ghi rõ các blocker về dữ liệu session và `serialize_lock`.
- `logs/g20_php855_BG.md`: thử nghiệm PHP 8.5.4 có app mô phỏng lưu object vào session và ASLR tắt.
- `DISPLAY_ERRORS_OFF.md`: leak heap đã có artifact; chưa chứng minh driver RCE đầy đủ trong cấu hình này.

Các tài liệu trên có giá trị nghiên cứu, nhưng không mở rộng phạm vi được chứng minh của `exploit.py` hiện tại.

## 7. Điều kiện và mức độ khái quát

Môi trường được ship: Linux amd64, PHP 8.4.26 NTS/mod_php, prefork một worker, `memory_limit=8M`, `post_max_size=64M`, upload progress bật, cookie bật, strict mode tắt và display errors bật. Một worker giúp các cặp A/B đến đúng tiến trình; rotation giữa các bước đòi hỏi master và ánh xạ hữu ích còn phù hợp.

Đây là điều kiện của **PoC đã hiệu chuẩn**, không phải danh sách điều kiện bắt buộc cho mọi biến thể CVE. Không thể suy ra FPM, nhiều worker, memory limit khác hoặc tắt display errors là an toàn chỉ vì driver này thất bại. Advisory chính thức xác nhận sự khác biệt về vòng đời worker và điều kiện của đường FPM. [PHP advisory về stale state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

Bản phát hành sửa lỗi được PHP công bố ngày 21/10/2026 là 8.2.35, 8.3.36, 8.4.27 và 8.5.12. Tắt upload progress chỉ giảm đường session đã biết, không thay thế cập nhật đầy đủ. [Thông báo chính thức của PHP](https://www.php.net/archive/2026.php#2026-10-21-5).

Để đánh giá tác dụng bản vá bằng thực nghiệm còn thiếu một lần đối chứng trước/sau trên cùng cấu hình, ghi nhận build/image cụ thể và bằng chứng của từng stage. Báo cáo hiện tại không tuyên bố đã thực hiện bước đó.

## 8. Kết quả kiểm tra PoC trong Docker sau phiên rà soát

Phần 1–7 ghi lại phạm vi của lần rà soát tĩnh ban đầu. Sau đó đã dựng các image Apache/mod_php chính thức, chỉ bind vào localhost, lấy symbol offsets riêng từ từng `libphp.so`, rồi chạy `exploit.py` với profile `bookworm`, `memory_limit=8M`, upload progress bật, và lệnh kiểm chứng `id>/out/p1`.

| Image | Kết quả PoC | Bằng chứng quan sát được |
|---|---|---|
| PHP 8.4.24 | Thành công | Các stage 1–3 hoàn tất; proof `uid=33(www-data) gid=33(www-data) groups=33(www-data)`. |
| PHP 8.4.25 | Thành công | Các stage 1–3 hoàn tất; cùng proof chạy dưới `www-data`. |
| PHP 8.4.26 | Thành công | Bản lab gốc; reproduction trước đó ghi 3/3 lần thành công. |
| PHP 8.5.9 | Không có proof | Stage 1–2 leak thành công; hai lần chạy đầy đủ đều hết 5 lượt stage 3 mà không có `/out/p1`; log có `zend_mm_heap corrupted` và worker abort. |
| PHP 8.5.10 | Thành công | Các stage 1–3 hoàn tất; proof chạy dưới `www-data`. |
| PHP 8.5.11 | Thành công | Các stage 1–3 hoàn tất; proof chạy dưới `www-data`. |
| PHP 8.3.35 | Không có proof | Stage 1–2 leak thành công; stage 3 hết 5 lượt không có `/out/p1`; log có worker abort/segfault. |
| PHP 8.2.34 | Không có proof | Heap leak stage 1 trượt cả 3 lượt; log báo heap corruption. |

Các kết quả thành công xác nhận thực thi lệnh trong container ở user `www-data` trên những image đã liệt kê. Các trường hợp không có proof chỉ cho thấy cấu hình PoC hiện tại chưa chứng minh được RCE ở image đó; driver cũng cảnh báo lệnh có thể đã chạy blind. Không dùng các lần thử thất bại để kết luận phiên bản không bị ảnh hưởng. Các bản trên là image trước phiên bản vá được PHP công bố ngày 21/10/2026: 8.4.27, 8.5.12, 8.3.36 và 8.2.35.

Các container thử nghiệm vẫn được giữ chạy để kiểm tra tiếp; tất cả cổng mục tiêu bind vào `127.0.0.1`.
