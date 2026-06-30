# Android Bug Bounty Recon Workflow v2
### Bản hiệu chỉnh theo dữ liệu chương trình thực tế: MoveIt vs Grab

---

## 0. Phản biện flow gốc (v1)

Mô hình ban đầu — "Static Analysis = phiên bản Recon của Android, vì attack surface đã nằm sẵn trong APK" — về cơ bản đúng, nhưng có 4 lỗ hổng mà dữ liệu MoveIt và Grab phơi bày rất rõ.

**APK chỉ giới hạn ở app, không giới hạn ở backend.** Static analysis cho bạn biết app *gọi* endpoint nào, nhưng không cho bạn biết hệ sinh thái backend đứng sau nó lớn đến đâu. Grab không phải một app — nó là một super-app với hàng chục service đứng sau: passenger, driver, merchant, GrabPay, GrabFood, GrabExpress... APK của `com.grabtaxi.passenger` chỉ là một cửa sổ nhìn vào một phần rất nhỏ của hạ tầng đó. Phần backend còn lại vẫn là "unknown unknown" y hệt một target web thuần — recon kiểu web (subdomain enum, OSINT hạ tầng) vẫn cần thiết, chỉ là nó nằm ở một layer khác so với pure-web pentest.

**Tỷ lệ effort không phải hằng số — nó là hàm số của out-of-scope policy.** Sơ đồ v1 gán "~50% effort cho Static Analysis" như một con số cố định. Nhưng nhìn vào danh sách out-of-scope của Grab, phần lớn các mục rơi đúng vào nhóm "local-device hardening, storage confidentiality, resilience" — chính là nhóm mà một checklist MASVS giáo khoa sẽ dành nhiều effort nhất để kiểm tra. Một workflow "phức tạp" chạy đầy đủ MASTG mà không đọc policy trước sẽ đốt rất nhiều thời gian vào những mục trả $0 cho riêng chương trình này.

**v1 nói đúng tinh thần bug bounty nhưng chưa biến nó thành một bước cụ thể.** Cái thiếu không phải khái niệm (đã nói tới cạnh tranh, edge-case asset), mà là cơ chế: chưa có phase nào bắt buộc đọc out-of-scope policy *trước khi* chạy checklist kỹ thuật, để biết trước cái gì sẽ không được trả tiền. Dữ liệu Grab chứng minh điều này cụ thể — chạy máy móc workflow v1 sẽ lãng phí một phần lớn khối "Static Analysis" cho riêng target này.

**Thiếu bước đánh giá độ trưởng thành của target.** MoveIt — `1 (0%)` — gần như một target trinh nguyên, ít người động vào, nhiều khả năng bug giáo khoa vẫn còn nguyên. Grab — payout tới $15,000 cho Critical, out-of-scope list dài và chi tiết — là chương trình đã bị hàng nghìn hunter cày qua nhiều năm, low-hanging fruit gần như không còn. Hai target này đòi hỏi hai chiến lược khác hẳn nhau, nhưng v1 chỉ đưa ra một workflow áp dụng chung cho cả hai.

Workflow v2 dưới đây thêm hẳn một **Phase 0** để giải quyết lỗi #3 và #4, mở rộng phần recon hạ tầng để giải quyết lỗi #1, và bỏ tỷ lệ effort cố định để giải quyết lỗi #2 — đồng thời **không đánh đổi các vector tấn công thuần Android**: exported component dẫn tới leakage, deep link hijacking, WebView JS bridge, Content Provider injection gần như không bị động đến trong out-of-scope list của Grab.

---

## 1. Phân loại target: Tier A vs Tier B

| | MoveIt (`com.moveit.app.customer`) | Grab (`com.grabtaxi.passenger`) |
|---|---|---|
| Tín hiệu trưởng thành | 1 submission, 0% | Bounty Critical tới $15,000 |
| Mức độ cạnh tranh | Gần như chưa bị khai thác | Đã bị hàng nghìn hunter cày nhiều năm |
| Out-of-scope policy | Chưa rõ — cần đọc full policy riêng | Dài, chi tiết, loại phần lớn local-device findings |
| Hạ tầng | Khả năng cao đơn giản hơn, ít service | Super-app, nhiều service, nhiều app vệ tinh |
| Chiến lược tối ưu | Breadth — chạy checklist giáo khoa đầy đủ kể cả MASVS cơ bản, khả năng cao chưa ai report | Depth + chuỗi liên kết — chỉ logic bug có impact thật, ưu tiên backend và app vệ tinh ít người để ý |

Gọi đây là **Tier A** (mature, đỏ máu) và **Tier B** (đất mới). Việc đầu tiên không phải kỹ thuật — mà là xếp loại target để biết nên đổ effort vào đâu, trước khi mở `jadx`.

---

## 2. Grab out-of-scope → effort redirect map

| Out-of-scope (Grab) | Vì sao bị loại | Redirect effort vào đâu |
|---|---|---|
| URI bị app khác đọc được (do cơ chế permission của Android) | Đặc tính nền tảng Android, ngoài tầm kiểm soát riêng của app | Bỏ qua — không phải hướng test cho chương trình này |
| Absence of certificate pinning | Thiếu pinning là thiếu defense-in-depth, không phải lỗ hổng tự thân | Bypass pinning để làm công cụ quan sát traffic ở Phase 3–4, không report việc bypass |
| Sensitive data in URL/body khi đã có TLS | Kênh truyền đã được bảo vệ, nội dung request không tự thân là bug | Soi authorization logic trong nội dung đó (IDOR/BOLA) thay vì soi "có data nhạy cảm hay không" |
| User data trên external storage không mã hóa | Out-of-scope tường minh | Bỏ hẳn external storage khỏi checklist cho Grab |
| Lack of obfuscation | Thiếu hardening, không phải bug | Tận dụng: code dễ đọc hơn nghĩa là bạn nhanh hơn ở Phase 2 |
| Crash do malformed Intent tới exported component | Crash thuần không tính, phải có leakage thật | Đẩy tiếp tới chứng minh đọc được data user khác hoặc bypass auth — không dừng ở crash |
| Sensitive data trong private directory | Sandbox riêng, không tự leak ra ngoài nếu không root | Bỏ qua local DB/SharedPreferences trong private dir, trừ khi dùng để pivot sang backend |
| Lack of binary protection control | Thiếu anti-tamper/anti-debug không phải bug | Không report; vẫn dùng Frida nội bộ để nghiên cứu |
| Frida/Appmon exploit chỉ chạy trên rooted device | Yêu cầu root không khớp threat model thực tế của Grab | PoC cuối cùng phải tái hiện được trên thiết bị không root |

**Điểm mấu chốt cần nhớ:** danh sách trên loại bỏ gần như toàn bộ nhóm "device-local hardening & storage confidentiality" — nhưng không hề đụng tới nhóm "Android attack-surface". Exported component dẫn tới data leakage vẫn in-scope tường minh, và không có dòng nào loại trừ deep link hijacking, WebView JS bridge, Content Provider injection, hay Intent redirection. Đừng nhầm "bị loại scope" với "bỏ luôn Android" — phần lớn vector Android-native quan trọng nhất vẫn sống khỏe.

---

## 3. Workflow v2 — đầy đủ các phase

Chú thích mức tự động hóa cuối mỗi dòng: **(tự động)** · **(bán tự động — cần script + review)** · **(thủ công — đòi hỏi judgment)**

### Phase 0 — Program & Scope Intelligence
*Phase v1 hoàn toàn thiếu.*

- Đọc toàn bộ policy: reward table, in-scope assets, out-of-scope list, disclosure rule, SLA phản hồi *(bán tự động — scrape trang policy được, diễn giải thì thủ công)*
- Đánh giá tín hiệu trưởng thành: số submission, % resolved, payout tier, ngày cập nhật policy gần nhất, kích thước Hall of Fame nếu công khai *(bán tự động)*
- Xây "scope matrix" — gạch chéo từng category bị out-of-scope, đánh dấu nơi cần redirect effort *(thủ công)*
- Liệt kê toàn bộ family asset trong scope, không chỉ một APK — Grab thường có app driver, merchant, GrabPay, GrabFood, GrabExpress, web booking, partner portal. Service backend yếu thường được chia sẻ giữa nhiều app; app ít người để ý nhất hay là nơi bug sống lâu nhất *(bán tự động)*
- Phân loại Tier A/B theo mục 1 để quyết định tỷ lệ breadth/depth cho các phase sau *(thủ công)*

### Phase 1 — Multi-asset & Infrastructure Recon
*Phần mở rộng quan trọng nhất so với v1 — đây là nơi "tinh thần web recon" áp dụng vào Android.*

- Pull APK của tất cả app trong family (không chỉ app passenger) qua APKPure/APKMirror hoặc tải trực tiếp từ Play Store bằng tài khoản test *(tự động)*
- Pull nhiều version lịch sử của cùng một APK để diff — phát hiện endpoint mới thêm, security check bị gỡ giữa các bản; script diff output `jadx` giữa hai version là việc lặp lại hoàn toàn tự động hóa được *(tự động)*
- OSINT hạ tầng công ty: subdomain enum trên domain chính (`subfinder`, `amass`, `crt.sh`), Shodan/Censys cho ASN, GitHub/GitLab dorking tìm key bị leak (`trufflehog`, `gitleaks` trên repo/gist public liên quan), Google dork tìm staging/Swagger/GraphQL playground bị public nhầm *(tự động)*
- Đọc tech blog, job posting kỹ thuật của công ty để suy ra tên internal service, tech stack — giúp đoán naming convention cho subdomain bruteforce *(thủ công)*

### Phase 2 — APK Teardown / Static Analysis
*Đây chính là "Recon-equivalent" của v1 — vẫn đúng, chỉ cần lọc qua scope matrix trước khi viết finding.*

- Decompile hàng loạt bằng `jadx`/`apktool`, đưa vào pipeline batch chạy tự động cho mọi APK pull được ở Phase 1 *(tự động)*
- Parse `AndroidManifest.xml`: liệt kê toàn bộ exported Activity/Service/Receiver/Provider, custom permission, deep link/intent-filter; script dùng `androguard` để tự động gắn cờ `exported=true` *(tự động)*
- Grep secrets & endpoint: API key, JWT secret, Firebase config, GraphQL endpoint string, AWS key — chạy `MobSF` hoặc regex pattern tùy chỉnh làm pass đầu tiên *(bán tự động — review kết quả vẫn cần người)*
- Kiểm kê third-party SDK và version để đối chiếu CVE đã biết *(bán tự động)*
- Audit WebView: tìm `addJavascriptInterface`, `loadUrl` với input không sanitize — vẫn in-scope với Grab vì có thể dẫn tới leakage/RCE thật *(thủ công)*
- Audit Content Provider: path traversal, SQL injection trên provider exported — fuzz cơ bản tự động hóa được, phân tích kết quả thì thủ công *(bán tự động)*

Lưu ý Grab-specific: không viết finding kiểu "app không obfuscate" hay "thiếu cert pinning" — out-of-scope tường minh. Dùng các fact này như lợi thế thao tác, không phải finding.

### Phase 3 — Dynamic Instrumentation
*Android-native, dùng làm công cụ chứ không phải đích đến cuối.*

- Setup Frida + Objection để hook runtime — mục đích là quan sát, không phải tự thân exploit, vì Grab loại trừ rõ "exploit chỉ chạy được trên rooted device"; PoC cuối cùng phải tái hiện được trên thiết bị không root *(thủ công)*
- Bypass pinning bằng Frida/mitmproxy chỉ để quan sát traffic phục vụ Phase 4, không report việc bypass đó là finding *(bán tự động)*
- Test exported component bằng `adb am start`/Drozer — không dừng ở "gây crash", đẩy tiếp tới chứng minh đọc được data của user khác hoặc bypass auth *(thủ công)*
- Fuzz deep link/App Link: enum toàn bộ custom scheme, kiểm tra có leak token (vd: link reset password bị app khác đọc được), có bypass được màn hình auth không — một trong những class bug giá trị cao nhất còn sống trên Grab vì hoàn toàn không bị loại scope *(thủ công)*

### Phase 4 — Backend API & Authorization Testing
*Nơi "DNA web pentest" phát huy tối đa trên target trưởng thành như Grab.*

- Build full Postman/Burp collection từ toàn bộ endpoint thu được ở Phase 2–3 *(bán tự động)*
- Authorization matrix (BOLA/IDOR): tạo hai tài khoản test, hoán đổi token/ID có hệ thống trên mọi endpoint chứa ID (ride ID, driver ID, wallet ID, support ticket ID...); bán-tự-động hóa bằng Burp Autorize/Turbo Intruder sau khi đã map endpoint *(bán tự động)*
- GraphQL-specific nếu có: kiểm tra introspection có bật không, batch query abuse, field-level authorization; scan đầu bằng `graphql-cop` *(bán tự động)*
- Rate-limit và OTP: account enumeration, OTP bruteforce, password reset flow *(bán tự động)*
- ID predictability: kiểm tra ride/user/driver ID có sequential hay đoán được không *(bán tự động)*

### Phase 5 — Business logic đặc thù ride-hailing
*Domain-specific, áp dụng cho cả hai target vì cùng ngành two-wheeler taxi. Phần này gần như hoàn toàn thủ công — đòi hỏi domain knowledge và sự sáng tạo, không phải scripting.*

- Fare manipulation: client có đang được tin tưởng để gửi giá cuốc, khoảng cách, hay tọa độ không
- Promo/voucher logic: stack được nhiều mã không, replay được không, áp dụng cho cuốc đã hoàn thành không
- Race condition: nạp ví, hủy cuốc, áp mã cùng lúc nhiều request — pattern kiểu double-spend
- GPS spoofing impact: tác động tới surge pricing, vùng phục vụ (geofencing), điều phối tài xế
- IDOR trên dữ liệu cuốc xe: xem được lịch sử hoặc vị trí GPS thời gian thực của user khác không — class bug kinh điển, impact privacy rất lớn trong ngành ride-hailing
- Referral/loyalty fraud: vòng lặp tự giới thiệu, claim thưởng nhiều lần
- Driver verification bypass: upload giấy tờ giả, bypass xác minh danh tính

### Phase 6 — Chain, Impact Validation & Reporting

Vì phần lớn local-device finding bị loại scope trên Grab, "thắng" ở đây nghĩa là chuỗi được một technical primitive (vd: IDOR + ID đoán được + thiếu rate limit) thành một câu chuyện impact cụ thể: account takeover, leak dữ liệu hàng loạt user, gian lận ví/fare ở quy mô lớn *(thủ công)*. Đối chiếu với Hall of Fame hoặc báo cáo công khai đã có nếu tìm được, để tránh trùng và học pattern chương trình hay thưởng *(bán tự động)*. Report cuối cùng giữ chuẩn thông thường — PoC rõ ràng, impact định lượng được, business context đầy đủ.

---

## 4. Quy tắc phân bổ thời gian nhanh

| | Tier B (MoveIt-like) | Tier A (Grab-like) |
|---|---|---|
| Phase 0 — Scope intel | Vẫn làm, nhưng nhanh — ít rule loại trừ hơn | Bắt buộc làm kỹ — đọc kỹ từng dòng out-of-scope |
| Phase 1–2 — Static + infra | Đầu tư mạnh, khả năng cao chưa ai khai thác | Làm nhanh, chủ yếu để lấy endpoint, không kỳ vọng tìm config/secret issue |
| Phase 3 — Dynamic | Đầy đủ checklist MASTG vẫn có giá trị | Chỉ dùng để hỗ trợ Phase 4, không tự thân là đích |
| Phase 4–5 — API + business logic | Vẫn quan trọng nhưng ít cấp bách hơn vì breadth đã ra bug | Trọng tâm chính — gần như nơi duy nhất còn "đất sống" |

---

*Lưu ý: bảng mục 2 dựng riêng theo policy của Grab. MoveIt là chương trình khác, hiện chưa rõ out-of-scope list đầy đủ — luôn đọc full policy riêng trước khi áp bất kỳ scope-mapping nào ở trên, vì rule có thể khác nhau hoàn toàn giữa hai chương trình.*
