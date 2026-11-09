# Tổng hợp hồ sơ Markdown AgroFlow

Tài liệu tập hợp các hồ sơ Markdown hiện có trong thư mục đồ án. Các hồ sơ theo ngày phản ánh trạng thái tại thời điểm ghi nhận. Khi một nội dung thay đổi qua các lần triển khai, đối chiếu ngày của hồ sơ và bằng chứng nghiệm thu tương ứng.

## Mục lục

- [1. BAN_GIAO_RULE_NGUOI_1.md](#ho-so-1)
- [2. BO_RULE_WAZUH.md](#ho-so-2)
- [3. BOI_CANH_DO_AN_CHO_CHATGPT.md](#ho-so-3)
- [4. CAI_DAT_AGENT_AUDITD_2026-11-05.md](#ho-so-4)
- [5. CAI_DAT_WAF_2026-11-05.md](#ho-so-5)
- [6. DANH_MUC_TEP_GIAM_SAT.md](#ho-so-6)
- [7. DASHBOARD_WAZUH_2026-11-06.md](#ho-so-7)
- [8. HO_SO_HIEN_TRANG_2026-11-05.md](#ho-so-8)
- [9. KIEM_THU_NGHIEP_VU_WAF_2026-11-05.md](#ho-so-9)
- [10. KIEM_THU_SURICATA_2026-11-05.md](#ho-so-10)
- [11. KIEM_TRA_SURICATA_PFSENSE_2026-11-05.md](#ho-so-11)
- [12. MA_TRAN_KIEM_SOAT_GIAM_SAT.md](#ho-so-12)
- [13. NGHIEM_THU_BUOC_2_2026-11-07.md](#ho-so-13)
- [14. NGHIEM_THU_SURICATA_PHAN_DOAN_2026-11-06.md](#ho-so-14)
- [15. NGHIEM_THU_WAF_2026-11-06.md](#ho-so-15)
- [16. PLAYBOOK_ALERTS_AGROFLOW.md](#ho-so-16)
- [17. SSH_PFSENSE_2026-11-05.md](#ho-so-17)
- [18. suricata-evidence/SALES-IPS-2026-11-06.md](#ho-so-18)
- [19. TICH_HOP_SURICATA_WAZUH_2026-11-05.md](#ho-so-19)
- [20. VIEC_CAN_LAM_TIEP.md](#ho-so-20)
- [21. WAF_BAN_GIAO_2026-11-05/CAI_DAT_WAF_2026-11-05.md](#ho-so-21)

---

<a id="ho-so-1"></a>
## 1. BAN_GIAO_RULE_NGUOI_1.md

# Bàn giao tích hợp log AgroFlow và FIM cho Người 1

Ngày 05/11/2026. WEB01: 10.20.50.10, agent ID 007, Wazuh 4.14.8. Manager: 10.20.60.10. Người dùng yêu cầu chỉ chuẩn bị rule để Người 1 áp dụng. Chưa cài rule riêng vào thư mục cấu hình đang chạy của Manager và chưa restart Manager trong lần tích hợp này.

## Những gì đã thực hiện trên WEB

- Thêm /var/log/agroflow/agroflow-*.jsonl và /var/log/agroflow-backup/backup-*.jsonl với log_format json; không viết lại log nguồn.
- Thêm /var/log/mysql/error.log với log_format mysql_log. Đây chỉ là error log, không phải audit SQL hoặc bằng chứng mọi thay đổi database.
- Giữ nguồn Nginx access/error, Auditd và journald có sẵn, không thêm trùng.
- Bật FIM who-data cho server/shared/scripts, các cấu hình ứng dụng, Nginx/TLS, MySQL, systemd, backup, agent, audit, SSH và quyền tài khoản. package.json/package-lock.json và wrapper backup có bộ lọc riêng. dist theo lịch quét 12 giờ mặc định, không giám sát toàn node_modules.
- Đã xác minh trực tiếp 34/34 tệp ưu tiên có baseline; xem monitoring-evidence/endpoint-verification.json để biết tên từng tệp và phạm vi thực tế.
- report_changes=no trên mọi vùng bổ sung; nodiff thêm cho env, shadow/gshadow, TLS key, client.keys, authd.pass và thông tin xác thực backup. Không gửi nội dung diff của bí mật.
- Agent tự cấu hình audit plugin af_wazuh và rule wazuh_fim phục vụ who-data. Không thêm audit rule thu toàn bộ execve. Auditd vẫn active.

Nguồn log JSON dùng trường application và event_code. Tài khoản là actor_id/role, thời gian timestamp, IP source_ip, kết quả result, lý do reason. Không mặc định dùng event_type/actor_role trong rule vì không khớp log thật.

## Bằng chứng đã có

- 754 dòng website và 18 dòng backup ban đầu đều parse được thành JSON object, không có dòng sai định dạng.
- Request thử không dùng tài khoản nghiệp vụ: một lần đăng nhập bằng username không tồn tại; trả HTTP 401. request_id c836debf-0d23-44cc-8a4d-0510f62938a0; event_id b19018c5-2b61-469b-9360-d4e485bff1ba; source_ip 10.20.50.254.
- Logcollector sau cấu hình đã đếm 2 sự kiện từ JSONL website, target agent, drops=0. Số đếm có thể tăng theo hoạt động thực tế; xem logcollector-counters.json.
- Mẫu JSON thật chạy wazuh-logtest trên Manager tách đúng application, event_code, request_id và source_ip. Đây là kiểm thử decoder, không phải bằng chứng cảnh báo nghiệp vụ đã chạy.
- FIM trên thư mục thử riêng tạo cảnh báo Manager 550 (sửa), 554 (thêm), 553 (xóa), có mode whodata, người đăng nhập agroflow, effective user root và tiến trình. Xem agroflow-review/fim-manager-evidence.json.
- Bộ rule dự thảo được thêm vào bản config kiểm thử riêng và kiểm tra bằng wazuh-analysisd -t, exit 0, không có cảnh báo không đọc được rule sau khi điều chỉnh đường dẫn/quyền. Config đang chạy của Manager có hash không đổi. Đây là kiểm tra tải/cú pháp, chưa phải kiểm thử matching của bộ rule trong dịch vụ thật.
- AgroFlow, Nginx, MySQL, Auditd và Agent vẫn active; health database connected. Manager/Indexer/Dashboard/Filebeat active.

## Bộ rule đề xuất

Tệp agroflow-web-rules.xml. Dải 111000–111049 đề xuất cho Người 2; tại thời điểm rà soát không trùng các custom XML đang cài trên Manager. Người 1 phải kiểm tra lại trước triển khai để tránh thay đổi từ thành viên khác. Không cần decoder riêng vì dùng JSON decoder tích hợp.

| ID | Ý nghĩa |
|---|---|
| 111000–111002 | Phân loại log AgroFlow; HTTP request thông thường level 0, audit nghiệp vụ level 3 |
| 111003 | Một lần đăng nhập thất bại, level 5; chưa kết luận brute force |
| 111004 | Backend từ chối quyền, level 5 |
| 111005 | Backend từ chối CSRF/origin, level 5 |
| 111006 | Sự kiện lỗi toàn vẹn/mất tài liệu, level 8 |
| 111020–111022 | Backup: phân loại, tiến trình thành công và thất bại |
| 111040 | Tăng ưu tiên thay đổi tệp quan trọng; cần đối chiếu bảo trì/phê duyệt |

Không có rule ngưỡng 5 lần/300 giây hoặc 3 lần/60 giây trong gói ban đầu này. Không có rule kết luận SQLi/XSS hoặc cảnh báo backup quá hạn. Không suy diễn một lần từ chối/đổi tệp thành sự cố đã xác nhận. Chưa có WAF.

## Người 1 triển khai trên Manager

1. Đọc XML và thống nhất dải ID. Bản dự thảo có sẵn tại /home/wazuh/agroflow-review/agroflow-web-rules.xml hoặc lấy từ gói bàn giao. Không chép nguyên cấu hình WEB vào Manager.
2. Sao lưu /var/ossec/etc/rules và config Manager vào vùng chỉ root đọc. Không đưa khóa hoặc cấu hình chứa mật khẩu vào gói chia sẻ.
3. Chỉ tạo tệp riêng /var/ossec/etc/rules/agroflow_web_rules.xml sau khi chắc chắn tệp đích chưa tồn tại. Chủ root:wazuh, mode 640; giữ nguyên local_rules.xml của Người 1.
4. Chạy sudo /var/ossec/bin/wazuh-analysisd -t. Nếu lỗi, gỡ riêng tệp mới về vùng lưu trữ và kiểm tra lại; không restart khi cấu hình lỗi.
5. Chạy từng dòng real-log-samples.jsonl qua sudo /var/ossec/bin/wazuh-logtest. Mẫu login_failed mong đợi 111003; HTTP thông thường không sinh cảnh báo; backup.completed 111021; backup.failed 111022. Các mẫu backup là sự kiện lịch sử, không tự chèn lại vào log sản xuất.
6. Khi kiểm thử đạt, Người 1 restart wazuh-manager, kiểm tra active và agent 007 Active.
7. Tạo sự kiện mới bằng thao tác thật, kiểm tra alerts.json rồi tra Dashboard. Logtest đúng chưa đủ kết luận toàn luồng đúng.

Không tự bật logall_json hoặc lập chỉ mục archives chỉ để mọi HTTP request xuất hiện trên Dashboard. Hiện Manager logall/logall_json=no và log_alert_level=3. Vì thế, đọc/gửi JSON thành công chưa đồng nghĩa từng JSON được lưu thành cảnh báo. Nếu cần lưu/truy vấn mọi request, hai người thống nhất riêng chính sách archives, dung lượng và retention. HTTP level 0 vẫn giữ tại nguồn, nhưng không được bảo đảm lưu trên Manager với cấu hình hiện hành.

## Sao lưu và hoàn tác WEB

Config trước đổi: /var/lib/agroflow-monitoring/production-20261105T102448Z/ossec.conf.before. Có bản tiếp theo trước chỉnh bộ lọc: /var/lib/agroflow-monitoring/ossec.before-restrict-fix-20261105T102906.

Muốn hoàn tác tích hợp lần này, dùng bản trước đổi đầu tiên, kiểm tra cấu hình rồi restart wazuh-agent; giữ nguyên Auditd/Agent đã cài. Không xóa toàn bộ audit rules bằng auditctl -D. Không thay schema/dữ liệu ứng dụng hoặc nội dung mã nguồn trong lần cấu hình này.

Chưa có backup mới phát sinh sau khi mở nguồn JSONL backup trong phiên này, nên chỉ xác nhận đã mở nguồn; chưa xác minh một lần backup mới được chuyển đầu cuối. Không tạo lỗi backup hoặc sửa tài liệu sản xuất để demo.

## Tệp bàn giao

- agroflow-web-rules.xml: rule dự thảo.
- monitoring-evidence/web-ossec.conf.review.xml: cấu hình WEB tham khảo, không dùng thay config Manager.
- monitoring-evidence/endpoint-verification.json: danh mục baseline/phạm vi.
- monitoring-evidence/logcollector-counters.json: bằng chứng nguồn đã đọc và bộ đếm.
- monitoring-evidence/real-log-samples.jsonl: mẫu đã chọn trường, không phải toàn bộ lịch sử.
- agroflow-review/fim-manager-evidence.json: cảnh báo FIM thật, chỉ chứa metadata.
- agroflow-review/json-decoder-logtest.txt: kết quả giải mã JSON bằng ruleset đang chạy.
- agroflow-review/manager-config-unchanged.json: hash config và trạng thái chưa áp dụng rule.

Tham chiếu: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html và https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html.

---

<a id="ho-so-2"></a>
## 2. BO_RULE_WAZUH.md

# Bộ rule Wazuh AgroFlow

Tiêu đề dùng dạng `Nguồn | Sự kiện`. Dashboard lọc theo `rule.groups` và `rule.id`. IP, tài khoản, tài nguyên và mã giao dịch tra trong trường dữ liệu của sự kiện.

| Nguồn | ID | Nhóm lọc chính | Trạng thái |
| --- | --- | --- | --- |
| AgroFlow | 111000–111009 | `agroflow_authentication`, `agroflow_authorization`, `agroflow_request_security`, `agroflow_document_integrity`, `agroflow_upload` | Đã nạp tên và nhóm cập nhật. |
| AgroFlow | 111010–111016 | `agroflow_authentication`, `agroflow_account_management`, `agroflow_document_access`, `agroflow_bulk_download` | Đã nạp và xác minh bằng log thật. |
| AgroFlow | 111017 | `agroflow_session_rejected` | Đã nạp. Log thật xác minh phiên hết hạn và token không còn bản ghi. |
| Backup | 111020–111024 | `agroflow_backup`, `agroflow_backup_overdue` | Đã nạp. Xác minh 111021–111023 qua ca bắt đầu, lỗi chuẩn bị và quá hạn. |
| FIM/Auditd | 550, 553, 554, 80781, 80790, 80791 | `syscheck`, `audit` | Rule mặc định đã khớp log thật. Rule tùy chỉnh 111040 còn là bản nháp. |
| Auditd | 111025 | `agroflow_web_process` | Đã nạp. Ca thực thi Dash dưới UID dịch vụ khớp rule. |
| MySQL | 50106, 111026 | `mysql_log`, `agroflow_mysql_authorization` | Đã xác minh lỗi xác thực và lỗi quyền 1142 sau khi kết nối. |
| WAF | 111050–111055, 111060–111061 | `agroflow_waf_detection`, `agroflow_waf_blocked`, `agroflow_waf_audit` | Đã nạp tên và nhóm cập nhật. |
| WAF | 111056–111059, 111062–111066 | `agroflow_waf_classified` | Nhận diện loại phát hiện cho giao dịch bị chặn. Cùng `transaction_id` với 111054. |
| Suricata | 111100–111106, 111109 | `suricata_detected`, `suricata_blocked` | ID đã triển khai trước đây. Tên và nhóm bổ sung đang chờ nạp. |
| Windows | 111200–111205 | `agroflow_windows_authentication`, `agroflow_windows_account_management`, `agroflow_windows_persistence` | Đã nạp. Cả năm máy đã xác minh đủ sáu rule bằng log thật. Bằng chứng ITADMIN tại `waf-acceptance-evidence/itadmin-AFProbec1eeccbc-index.json`. |
| Defender | 111210–111214 | `agroflow_defender` | Rule đã nạp. Thu kênh Operational qua cấu hình chung cho năm máy Windows. FINANCE xác minh 111210. WAREHOUSE, ITADMIN, DIRECTOR và SALES xác minh 111210 và 111211. SALES khớp các Record ID 557–558 và 565–566 sau lượt khởi động lại agent để bật debug. |
| Sức khỏe agent | 111220–111221 | `agroflow_agent_disconnected`, `agroflow_agent_started` | Đã nạp. 111221 có log thật từ FINANCE và SALES. Tạm gác nghiệm thu 111220 theo quyết định người dùng. Ca suspend FINANCE 17 phút 19 giây không thấy 111220 hoặc 504 trong cửa sổ thử. Khi tiếp tục, đối chiếu ngưỡng runtime của Manager. Bằng chứng tại `waf-acceptance-evidence/finance-agent-disconnect-live.json`. |

`WAF | Inbound Anomaly Threshold Exceeded` ghi ngưỡng bị vượt. `WAF | Request Blocked by Inbound Anomaly Score` ghi giao dịch được phân loại chặn. `Suricata | Inline Traffic Drop` dành cho syslog có dấu hiệu `[Drop]`.

WAF ghi sự kiện phân loại trước bản ghi chặn trong cùng lần xử lý audit. Thời điểm HTTP lấy từ `data.source_timestamp`; thời điểm lập cảnh báo lấy từ `timestamp`. `data.source_ip` là IP client trong audit WAF. `data.source_host` là tên suy ra từ bảng IP lab. `data.detection_types` liệt kê các nhóm khớp, còn `data.detection_type` là nhãn chính dùng chọn level. Hai alert có ID sự kiện riêng, dùng chung mã giao dịch.

Rule 111016 áp dụng cho mọi bộ phận. AgroFlow sinh sự kiện tương quan khi một tài khoản tải thành công hồ sơ thứ năm khác nhau trong cửa sổ 120 giây. Tải lại hoặc tải phiên bản khác của cùng hồ sơ giữ nguyên một ID hồ sơ. Khi demo, dùng tài khoản Kho hoặc Kinh doanh có quyền tải năm hồ sơ thử. Điều kiện 20 lượt trong 60 giây thuộc đợt nghiệm thu trước.

Đợt duyệt và khóa tài khoản đạt 139/139 request. Wazuh nhận 111012 khi quản trị viên duyệt tài khoản, 111011 ở lần nhập sai thứ năm và 111013 khi quản trị viên đặt lại khóa. Rule 111007 tương quan theo IP nên đã tính cả lần đăng nhập khi tài khoản còn chờ duyệt. Bằng chứng tại `waf-acceptance-evidence/account-approval-lock/`.

Bộ ca thay đổi quyền và tải liên tiếp đạt 148/148 HTTP. Trong index, lần đổi quyền khớp 111013, lần đổi trái quyền khớp 111004, lần đăng nhập sau đổi quyền khớp 111010. Hai lượt tải đối chứng và 17 lượt đầu của chuỗi khớp 111015, lượt thứ 18 của chuỗi khớp 111016 tại tổng 20 lượt thành công cùng tài khoản. Chuỗi dùng nhiều request tải lại cùng tệp thử, nên xác minh tần suất request. Hồ sơ ở `waf-acceptance-evidence/access-and-download/`.

## Phần còn thiếu dữ liệu hoặc cần xác nhận

- Phiên hết hạn và cookie đã đăng xuất đều trả HTTP 401 và khớp 111017. Log phân biệt `expired` và `invalid_or_revoked`. Bản ghi phiên bị xóa không đủ dữ liệu để phân biệt thu hồi với token ngẫu nhiên. Bằng chứng tại `waf-acceptance-evidence/web-session/` và `waf-acceptance-evidence/web-step2/wazuh-index.json`.
- Đăng nhập sai theo tài khoản và đăng nhập thành công sau chuỗi sai cần khóa tương quan được xuất nhất quán và ca kiểm thử dương, âm.
- Windows, Defender và mất agent thuộc lượt riêng.
- Phân đoạn và nghiệm thu Suricata thường trực tạm gác theo phạm vi hiện tại.

---

<a id="ho-so-3"></a>
## 3. BOI_CANH_DO_AN_CHO_CHATGPT.md

# Bối cảnh đồ án tốt nghiệp để tiếp tục làm việc trong ChatGPT

## Cập nhật thực tế mới nhất — 05/11/2026 23:48 +07

Người dùng hiện đảm nhiệm cả hai phần công việc. SSH pfSense 10.20.40.1:22 đã dùng được với admin; rule IT cho host 10.20.40.254, nhưng anti-lockout có sẵn trên SALES vẫn cho SSH. Không chứa mật khẩu trong tài liệu.

Suricata 7.0.8 chạy IT/em4 và SERVER/em5 ở IDS, chưa chặn. Đã bật JA3 riêng IT, xác minh 23.696 rule nạp/0 thất bại; SERVER trước đó 28.902/0. Đã áp dụng hai file riêng decoder/rule Suricata RFC5424 lên Wazuh Manager (agroflow_pfsense_suricata.xml trong decoders và rules), ID111100–111103,111109. Hai alert ET SID2062547 từ mẫu DNS .invalid đã đối chiếu chính xác tới alerts.json của Manager, rule111101 level12; chưa xác minh index/Dashboard. Đây là dữ liệu test, không phải nhiễm malware. WEB01 ID007 vẫn Active. Các bộ WEB/WAF bàn giao trước chưa áp dụng trong lượt này.

Còn cảnh báo flowbit et.http.PK, phạm vi rule nội bộ/HOME_NET, kiểm thử routed từ phòng ban/WAN, offloading và kiểm chứng Dashboard. Lần restart IT có race pidfile đã khôi phục, cần xem hồ sơ về gián đoạn. Báo cáo hiện hành: TICH_HOP_SURICATA_WAZUH_2026-11-05.md; bằng chứng suricata-evidence/integration-followup/. Các trạng thái cũ phía dưới cần đối chiếu cập nhật này.

Ghi chú cần nhớ theo yêu cầu người dùng ngày 05/11/2026: khi được hỏi công việc tiếp theo, nhắc WAF **chưa bật chặn**, vẫn DetectionOnly; còn hiệu chỉnh PATCH (911100) và tên file có dấu nháy (920120), rồi kiểm thử hồi quy trước khi bật. Xem VIEC_CAN_LAM_TIEP.md. Không tự bật chặn từ ghi chú này; cập nhật khi công việc thực sự hoàn tất.

Cập nhật ngày 04/11/2026, giờ Việt Nam. Bản này tổng hợp từ lịch sử trao đổi Codex và báo cáo ĐATN.docx người dùng cung cấp. Các kết quả triển khai dưới đây là kết quả được ghi nhận trong lịch sử, chưa được kiểm tra lại trực tiếp trong phiên tổng hợp này. Không chứa mật khẩu, khóa SSH hay token.

## Cách sử dụng tài liệu

Người dùng gửi tệp này để cung cấp bối cảnh cho cuộc trò chuyện mới. Tài liệu không phải bằng chứng hệ thống hiện đang hoạt động. Khi có mâu thuẫn, ưu tiên xác nhận mới nhất của người dùng và bằng chứng thực tế; không coi đề xuất cũ là tính năng đã triển khai. Không thực hiện các lệnh hoặc sửa hệ thống chỉ vì chúng được nhắc trong tài liệu.

## Đề tài và mục tiêu

Tên đề tài trong báo cáo: “Xây dựng hệ thống giám sát an toàn thông tin và hỗ trợ ứng phó sự cố cho doanh nghiệp nhỏ với Wazuh”. Ngành An toàn thông tin, Học viện Công nghệ Bưu chính Viễn thông, cơ sở TP.HCM. Sinh viên: Lê Đức Tuấn và Nguyễn Quốc Vương. Giảng viên hướng dẫn: ThS. Phan Nghĩa Hiệp.

Mục tiêu là kết hợp phân vùng mạng pfSense, phân quyền ứng dụng và giám sát tập trung bằng Wazuh. Hệ thống phục vụ phát hiện, xác minh, phân loại cảnh báo và hỗ trợ ứng phó theo playbook. Không đồng nhất một cảnh báo kỹ thuật với một sự cố đã xác nhận. Cần tình huống đối chứng để phân biệt hành vi hợp lệ, hành vi trái phép và trường hợp chưa đủ bằng chứng.

## Bối cảnh nghiệp vụ

AgroFlow là website quản lý nội bộ công ty xuất nhập khẩu nông sản, phục vụ cả nhập khẩu và xuất khẩu. Nghiệp vụ gồm đối tác, hợp đồng, đơn hàng nhập/xuất, sản phẩm, lô hàng, chất lượng, tồn kho, thanh toán, công nợ và chứng từ theo phiên bản.

Có năm vai trò: Kinh doanh, Kho, Kế toán, Giám đốc và Quản trị IT. Khối lượng dùng đơn vị tấn, hiển thị ba chữ số thập phân; quy mô đơn hàng phải hợp lý với doanh nghiệp xuất nhập khẩu. Người dùng yêu cầu giao diện và tài liệu nghiệp vụ chuyên nghiệp, tránh những chú thích mô phỏng hoặc diễn giải kỹ thuật không cần thiết trên dashboard. Dữ liệu mẫu vẫn phải được mô tả trung thực trong trao đổi và báo cáo khi cần.

## Kiến trúc và trạng thái được ghi nhận

Cập nhật kiểm thử nghiệp vụ WAF 05/11/2026: 112 request (103 hợp lệ, 9 đối chứng âm) qua HTTPS với 5 tài khoản tạm. Phát hiện 4 request hợp lệ vượt anomaly: PATCH partners/products do 911100, và upload tên có dấu nháy O'Brien do 920120 ở FILES:file. Bốn phép thử chẩn đoán xác nhận tiếng Việt không phải nguyên nhân; dấu nháy đơn gây match. Chưa hiệu chỉnh hoặc bật chặn. Đã dọn 5 account và toàn bộ fixture; hash/count 17 bảng nghiệp vụ không đổi, audit giữ lại. Hồ sơ mật khẩu cũ không còn đăng nhập được (1 lần thử, không lặp), nên nghiệm thu tài khoản hiện có cần xác nhận mật khẩu mới. Xem KIEM_THU_NGHIEP_VU_WAF_2026-11-05.md.

Đã đọc chính sách chứng từ hiện hành: sales chỉ contract/annex; warehouse packing_list/bill_of_lading/certificate/quality; accounting invoice/payment/bank_receipt; director đọc mọi loại nhưng không upload; admin đọc/ghi mọi loại được hỗ trợ. Kế toán bị 403 khi xem contract là đúng chính sách mới, thay cho ma trận cũ trước lần sửa quyền. Đây là quyền ứng dụng, không phải WAF.

Cập nhật WAF 05/11/2026: đã cài ModSecurity 3.0.12, connector Nginx 1.0.3 và CRS 3.3.5 từ Ubuntu, chạy DetectionOnly PL1 trên HTTPS WEB. 7 phép thử cuối đạt, gồm request hợp lệ, SQLi/XSS/traversal, JSON body và ngoại lệ Host IP hẹp; chưa bật chặn hoặc thử toàn bộ nghiệp vụ có tài khoản. Log thô giữ trên WEB; Agent chỉ thu JSON metadata đã loại body/header/query qua dịch vụ agroflow-waf-log, kèm correlation request. Đã thêm cấu hình/code WAF vào backup và backup sau cài thành công. Không thao tác cấu hình Manager; rule WAF dự thảo agroflow-waf-rules.xml dành Người 1. Xem CAI_DAT_WAF_2026-11-05.md và waf-evidence/waf-verification.json. Các mô tả “chưa cài WAF” trong tài liệu/lịch sử trước đó đã được thay thế bởi trạng thái này.

Cập nhật tích hợp cuối 05/11/2026: agent WEB đã cấu hình thu JSONL website/backup, MySQL error log, giữ Nginx/Auditd/journald; who-data cho các vùng tệp quan trọng, 34/34 tệp ưu tiên có baseline, không nội dung diff. FIM thêm/sửa/xóa đã có alert thật 554/550/553 trên Manager. JSONL đã có bộ đếm agent và decoder logtest; chưa xác nhận alert nghiệp vụ do người dùng chọn chỉ chuẩn bị rule để Người 1 áp dụng. Rule dự thảo 111000–111049 không nạp vào Manager; config Manager giữ nguyên. Xem BAN_GIAO_RULE_NGUOI_1.md để phân biệt đã cấu hình, đã kiểm thử và phần còn chờ Người 1. Chưa triển khai thu mọi execve, audit SQL, WAF, cảnh báo backup quá hạn hoặc GS01/GS03 đủ ngưỡng.

Cập nhật sau cài ngày 05/11/2026: Auditd 1:3.1.2-2.1ubuntu0.1 và Wazuh Agent 4.14.8-1 đã hoạt động trên WEB. Agent WEB01 ID 007 kết nối Manager ubuntuserver 10.20.60.10, tài khoản SSH wazuh. Manager 4.14.8-1 ban đầu failed ở API khi boot, đã start lại thành công, chưa xác định nguyên nhân gốc. Probe Auditd tạo tệp đã tạo alert 80790 trên Manager lúc 16:59:26 Việt Nam. Xem CAI_DAT_AGENT_AUDITD_2026-11-05.md cho bằng chứng và phạm vi; chưa triển khai rule audit toàn bộ ứng dụng, chưa xem Dashboard/Indexer và chưa tích hợp JSONL website/backup riêng.

Kiểm tra trực tiếp ngày 05/11/2026 đã được lưu trong HO_SO_HIEN_TRANG_2026-11-05.md cùng thư mục. Ưu tiên hồ sơ này cho hiện trạng: Nginx HTTPS → backend loopback:3000 → MySQL loopback:3306; gateway 10.20.50.1; Windows VMnet5 10.20.50.254. Wazuh Agent và Auditd chưa cài; chưa thấy WAF hoạt động. Backup hôm nay thành công lúc 16:31 Việt Nam, sau lỗi drive_upload hôm trước. Máy Windows chưa tin cậy CA HTTPS. Mã nguồn/log ứng dụng đang được bảo vệ, sudo yêu cầu mật khẩu; chưa xác minh nghiệp vụ có đăng nhập và rule thực tế. Hồ sơ ghi rõ đường dẫn và cách kiểm tra nhanh cho lần sau.

- Website hiện hành là React/Vite, backend Node.js/Express, MySQL. Không nhầm với bản MVP rất sớm dùng Fastify/TypeScript và in-memory.
- Website, MySQL và HTTPS đã được triển khai trên Ubuntu webserver. Địa chỉ truy cập được ghi nhận: https://10.20.50.10.
- Mã nguồn Ubuntu: /opt/agroflow. Dịch vụ systemd: agroflow. Tài khoản SSH được ghi nhận: agroflow.
- Bản mã nguồn trên Windows: D:\Website_tot_nghiep.
- Thư mục làm việc của chat hiện tại: C:\Users\ACER\Documents\ChatGPT\đồ án tốt nghiệp 2. Khi kiểm tra đầu phiên, thư mục này trống; điều đó không có nghĩa đồ án chưa có mã nguồn ở nơi khác.
- Báo cáo người dùng cung cấp: C:\Users\ACER\Downloads\ĐATN.docx.
- pfSense kiểm soát kết nối giữa các vùng mạng. Các máy phòng ban Windows, Ubuntu webserver, Wazuh và Kali phục vụ mô hình lab. Không tự suy đoán IP các máy còn lại khi chưa đọc sơ đồ hoặc cấu hình thực tế.
- Quyền website được quyết định bởi tài khoản và chính sách backend. IP phục vụ kiểm soát mạng, ghi log và truy vết; không suy ra quyền website từ IP hay tên máy.

## Thay đổi quan trọng về lưu chứng từ

Phương án cũ lưu hợp đồng/chứng từ trong D:\Hợp đồng đã được người dùng yêu cầu bỏ khỏi kiến trúc hiện hành trên Ubuntu. Nội dung tài liệu được lưu trong MySQL BLOB, bảng document_contents.

Không tiếp tục mô tả D:\Hợp đồng là nguồn chứng từ/FIM/backup hiện hành của Ubuntu. Việc theo dõi tệp mã nguồn và cấu hình bằng FIM khác với theo dõi nội dung BLOB trong database. Cơ chế lưu tài liệu của bản Windows có thể khác; lần đồng bộ quyền gần nhất ghi rõ giữ nguyên cơ chế lưu tài liệu Windows, nên không khẳng định hai môi trường giống hoàn toàn.

## Phân quyền ứng dụng

Backend kiểm tra quyền chức năng, phạm vi hợp đồng/bản ghi, loại chứng từ và trạng thái nghiệp vụ trước khi trả dữ liệu hoặc thực hiện thao tác.

- Kinh doanh: quản lý đối tác, tạo hợp đồng và đơn, sửa hồ sơ ở bước được phép, chuyển Kế toán, trình Giám đốc, theo dõi tiến độ. Không xác nhận nhập/xuất kho, ghi nhận thanh toán hoặc quản lý tài khoản.
- Kho: quản lý sản phẩm/lô/chất lượng, xác nhận nhập/xuất và xem thông tin giao nhận cần thiết. Không ghi nhận thu/chi hoặc cấp quyền.
- Kế toán: kiểm tra hồ sơ, xác nhận bước Kế toán, ghi nhận thu/chi và quản lý chứng từ tài chính. Không xác nhận kho hoặc cấp quyền.
- Giám đốc: xem tổng quan, phê duyệt, yêu cầu chỉnh sửa, quyết định đề nghị hủy và gửi chỉ đạo. Không mặc nhiên có chức năng quản trị IT. Lịch sử trước lần sửa quyền chứng từ ghi nhận Giám đốc không có API upload.
- Quản trị: duyệt/khóa tài khoản, đổi vai trò, giao hợp đồng, xem audit và kiểm tra toàn vẹn tài liệu. Bản lab có nhiều quyền nghiệp vụ, nhưng API quyết định phê duyệt của Giám đốc được ghi nhận chỉ dành cho director. Admin website không đồng nghĩa admin Ubuntu/MySQL/pfSense/Wazuh.

Trong bản được rà soát trước lần sửa chứng từ, Kinh doanh chỉ truy cập hợp đồng được giao; nhân viên cùng phòng không mặc định xem mọi hồ sơ của nhau. Cần đối chiếu mã mới để xác nhận phạm vi chính xác hiện tại.

Trạng thái nghiệp vụ cũng giới hạn thao tác: đơn bị giữ không được xử lý tiếp tùy tiện; phê duyệt Giám đốc không bỏ qua điều kiện Kế toán và tồn kho; các phòng ban đề nghị hủy, Giám đốc quyết định; luồng dừng/hủy bị giới hạn sau khi Kho xác nhận giao nhận.

## Lần sửa quyền chứng từ gần nhất

Người dùng phát hiện mọi bộ phận đều tải được chứng từ và yêu cầu sửa logic, cập nhật Ubuntu đồng thời đồng bộ Windows.

Lịch sử ghi nhận:

1. Đã lấy và đối chiếu mã đang chạy trên Ubuntu trước khi sửa, vì server/index.js khác bản cục bộ.
2. Gói sửa có shared/document-policy.js và cập nhật API danh sách/xem/tải cùng giao diện.
3. Ubuntu đã backup, build và khởi động dịch vụ thành công, kết quả UPDATE_INSTALLED_HEALTH_OK.
4. Windows ban đầu chưa đồng bộ vì backup lỗi khóa restic. Sau đó người dùng cho phép bỏ backup riêng lần đồng bộ này.
5. Kết quả cuối ghi nhận đã cập nhật trực tiếp D:\Website_tot_nghiep, build thành công và 906 kiểm tra giả lập đạt.
6. Chưa có xác nhận cuối cùng về đăng nhập, danh sách, xem và tải bằng tài khoản từng bộ phận trên website thực tế.

Không lấy ma trận chứng từ trong chat “Tổng hợp thông tin đồ án” làm chính sách cuối cùng mà không đọc mã mới: ma trận đó có trước lần sửa này, từng ghi nhận Kho chưa bị chặn invoice. Bản bối cảnh này chưa trích xuất đầy đủ chính sách mới, nên không tự khẳng định quyền hiện tại theo từng loại tài liệu.

## Nhật ký và giám sát

Website ghi log hoạt động/bảo mật và HTTP dạng JSONL; audit nghiệp vụ còn có trong MySQL audit_events. Lịch sử từng xác nhận log có actor_id, vai trò, IP nguồn, thời gian, mã yêu cầu, đối tượng, hành động và kết quả. Cần đọc log thật để chốt schema và đường dẫn hiện hành trên Ubuntu.

Không sử dụng đường dẫn log cũ trong D:\Hợp đồng làm đường dẫn hiện hành. Nguồn log ứng dụng nằm trên máy chạy backend; máy phòng ban chỉ mở trình duyệt không tự có log backend. Cần kiểm tra trusted proxy/NAT khi xác minh IP người dùng.

Phải phân biệt cấu hình mẫu, logtest đạt và luồng thực tế agent → manager → dashboard đã kiểm chứng. Không khẳng định Wazuh đã tích hợp hoàn tất chỉ vì có sẵn XML.

## Backup

- Trước đây có hệ thống backup Windows dùng restic/rclone lên Google Drive, với lịch log 2 giờ, dữ liệu 6 giờ, mã nguồn Chủ nhật 03:00 và trước cập nhật. Đây là lịch của hệ thống Windows trước đó, không dùng thay lịch Ubuntu.
- Thông tin mới hơn trong chat sửa quyền: backup Ubuntu đã cài xong, lần đầu thành công và timer bật lúc 23:00 mỗi ngày, Asia/Ho_Chi_Minh.
- Kết quả triển khai bản sửa quyền cũng ghi nhận backup Drive thành công trước cập nhật và trước build.
- Khi cài backup Ubuntu, đầu ra ghi Wazuh Agent chưa được cài, snippet thu log được lưu để cấu hình sau. Chưa có bằng chứng mới trong bản tổng hợp này xác nhận agent đã cài và thu log.
- Chưa xác nhận lại lần backup định kỳ gần nhất hoặc kiểm thử phục hồi Ubuntu.
- Không ghi mật khẩu, khóa mã hóa, token OAuth hoặc nội dung khóa SSH vào báo cáo/chat.

## Phạm vi báo cáo và rule

Báo cáo có thiết kế cảnh báo CB01–CB06, kịch bản KB00–KB07 và playbook PB01–PB05. Chương 3 hiện có bảng 6 chính sách bảo vệ BV01–BV06 và 10 nhóm giám sát GS01–GS10. Những nhóm này không đồng nghĩa đã triển khai toàn bộ và cũng không nhất thiết mỗi nhóm chỉ dùng một rule XML.

BV01 kiểm soát Internet; BV02 phân đoạn mạng; BV03 bảo vệ quyền website; BV04 đầu vào và phiên; BV05 upload/download; BV06 MySQL và tài khoản quản trị.

GS01 đăng nhập; GS02 tài khoản/đặc quyền; GS03 vi phạm quyền nghiệp vụ; GS04 upload vi phạm; GS05 tải tài liệu hàng loạt; GS06 toàn vẹn tài liệu; GS07 mã nguồn/cấu hình; GS08 tiến trình/lệnh; GS09 tự khởi động; GS10 chống mã độc.

Hướng ưu tiên mới nhất trong chat rà soát rule: triển khai GS01–GS03, thứ tự GS02 → GS03 → GS01 vì dùng chung luồng log JSON.

- GS02: bắt đầu từ sự kiện tạo tài khoản hoặc đổi vai trò thành công, có người thao tác, đối tượng và giá trị trước/sau khi phù hợp.
- GS03: ngưỡng thiết kế 3 lần bị từ chối trong 60 giây theo cùng actor_id.
- GS01: bắt đầu với 5 lần đăng nhập thất bại trong 300 giây theo tài khoản được thử. Thiết kế CB01 còn đề cập nhóm độc lập theo tài khoản hoặc IP; phần mở rộng tương quan thành công sau thất bại cần được xác định riêng.

Một lần đăng nhập sai không chứng minh brute force; đổi vai trò hợp lệ vẫn có thể tạo cảnh báo rà soát; log access denied không phát hiện được mọi trường hợp backend cho truy cập sai quyền thành công. Rule 100101–100103 từng được đề xuất làm mẫu, chưa coi là ID đang chạy thực tế.

KB07 kiểm tra các cặp tình huống tương tự về kỹ thuật nhưng khác bối cảnh. Phân loại thành: hành vi trái phép/sự cố đã xác nhận; hoạt động hợp lệ đã xác nhận; chưa đủ bằng chứng. Cần phân biệt nhận diện sự kiện đúng với kết luận sự cố đúng.

## Việc nên tiếp tục

### Phân công mới nhất do người dùng xác nhận ngày 04/11/2026

Người dùng đảm nhiệm NGƯỜI 2 — WAF, website và dữ liệu. Phân công này mở rộng hướng ưu tiên GS01–GS03 trước đó; không tự đồng nhất mã TC/PH/NV/TV/VH với mã GS/CB. Cần đọc danh mục rule đầy đủ trước khi diễn giải chi tiết từng mã chưa có định nghĩa trong tài liệu.

Người 1 phụ trách pfSense, Suricata, 5 máy Windows và phối hợp giám sát Ubuntu WAZUH. Người 2 phụ trách WAF trên web server/reverse proxy và Ubuntu WEB chứa website cùng MySQL. Hai bên gửi log về Wazuh chung.

Phạm vi Người 2:

- Cài WAF và bộ rule phù hợp như OWASP CRS; bảo đảm request đi qua WAF. Đây là công việc được phân công, chưa phải xác nhận đã cài.
- Thu thập log WAF, website, Auditd, MySQL khả dụng và backup về Wazuh.
- TC07–TC11: SQLi, XSS, CSRF, upload/download, đường dẫn và phiên. Phối hợp TC05 về HTTP/tài nguyên web, TC06 về brute force website và SSH Ubuntu WEB.
- PH01–PH02, PH05–PH10, PH12–PH16 trên Ubuntu WEB tùy khả năng nguồn dữ liệu. Hỗ trợ đối chiếu với server Wazuh khi kiểm thử.
- NV01–NV05: quyền, quy trình, thay đổi quyền, tải hàng loạt và log nghiệp vụ.
- TV01–TV03 trên Ubuntu WEB; TV05 dependency/bản phát hành; xử lý phát hiện TV04 liên quan webserver.
- VH02 phía website/MySQL; VH03 dữ liệu website và Google Drive. VH04–VH05 phối hợp hai người.
- Ứng phó: thu hồi phiên, xử lý file upload, phục hồi website/database.
- Hiệu chỉnh cảnh báo giả của WAF/ứng dụng dựa trên nghiệp vụ, upload hợp lệ và lịch triển khai.
- Bàn giao cấu hình WAF/backend/Auditd, rule/decoder Wazuh, log mẫu và kết quả thử.

Nghiệm thu Người 2 chủ trì: (1) SQLi/XSS/path traversal/upload vi phạm; (2) CSRF, phiên hết hiệu lực, truy cập tài liệu ngoài quyền; (3) tiến trình bất thường từ backend, sửa mã nguồn hoặc tài liệu; (4) backup lỗi, không chạy và phục hồi. Cần chứng minh cả kiểm soát xử lý đúng lẫn bằng chứng được Wazuh tiếp nhận. Nội dung tài liệu lưu BLOB phải được kiểm chứng bằng cơ chế phù hợp, không mặc định FIM theo dõi được từng nội dung trong database.

Nghiệm thu chung: chuỗi request đáng ngờ → thực thi server → kết nối ra ngoài; và mất nguồn log/Wazuh ngừng hoạt động với kiểm tra độc lập.

Quy tắc phối hợp: Người 1 quản lý áp dụng thay đổi lên Wazuh Manager. Người 2 chuẩn bị rule, decoder và log mẫu để cùng kiểm tra trước khi áp dụng. Mỗi người có file riêng và thống nhất ID tránh trùng. Triển khai phát hiện trước, hiệu chỉnh rồi mới bật chặn phù hợp. CSRF, phân quyền, truy vấn SQL và phiên là trách nhiệm backend; WAF chỉ hỗ trợ. Thứ tự chung: thống nhất log/mã rule → Suricata/WAF → thử từng phần → thử chuỗi → hoàn thiện bằng chứng/cảnh báo giả.

### Các việc đang chờ từ lịch sử

1. Xác minh quyền chứng từ trên Ubuntu bằng tài khoản từng bộ phận, cả API trực tiếp và giao diện; đối chiếu shared/document-policy.js hiện hành.
2. Chốt vị trí/schema log thật trên Ubuntu, kiểm tra trạng thái Wazuh Agent và khả năng tiếp nhận tại manager.
3. Tích hợp từng phần GS02, GS03, GS01; mỗi phần có thao tác thử, log nguồn và cảnh báo dashboard liên kết được bằng mã sự kiện/thời gian.
4. Chạy tình huống hợp lệ đối chứng và ghi nhận căn cứ phân loại; không chỉ chụp cảnh báo.
5. Cập nhật chương 3 theo bằng chứng thực tế; tách đã thiết kế, đã cấu hình, đã kiểm thử và còn thiếu.

## Các chat nguồn đã truy cập

- Tổng hợp thông tin đồ án.
- Kiểm tra quyền tải kho chứng từ — nguồn mới hơn về sửa quyền và backup Ubuntu.
- Rà soát rule giám sát chương 3.
- Cấu hình IP khi triển khai website.
- Đề xuất chức năng phòng giám đốc.
- Xây dựng website quản lý nội bộ.
- Các chat chạy đồ án, ngôn ngữ backend và mạng máy ảo liên quan.

Đây là bản chuyển giao bối cảnh, không phải toàn văn lịch sử hoặc bản sao mã nguồn. ChatGPT mới không tự có quyền đọc các đường dẫn trên máy người dùng; muốn kiểm tra nội dung mới cần người dùng cung cấp tệp hoặc dùng công cụ kết nối được hỗ trợ.

---

<a id="ho-so-4"></a>
## 4. CAI_DAT_AGENT_AUDITD_2026-11-05.md

# Kết quả cài Wazuh Agent và Auditd trên WEB

Hoàn thành ngày 05/11/2026 khoảng 17:01 giờ Việt Nam. Không lưu mật khẩu hoặc khóa đăng ký agent trong hồ sơ.

## Thông tin kết nối đã xác minh

| Thành phần | Giá trị |
|---|---|
| WEB | webserver, 10.20.50.10, tài khoản SSH agroflow |
| Wazuh | ubuntuserver, 10.20.60.10, tài khoản SSH wazuh |
| Wazuh Manager | 4.14.8-1 |
| Wazuh Agent trên WEB | 4.14.8-1, tên WEB01, ID 007 |
| Auditd | 1:3.1.2-2.1ubuntu0.1 |
| Kênh agent | TCP 1514; đăng ký TCP 1515 |
| Trạng thái cuối | WEB agent connected; Manager agent_control báo Active |

Wazuh Agent được cài cùng phiên bản Manager từ APT chính thức có kiểm tra chữ ký. Đã đặt hold để tránh nâng agent ngoài ý muốn trước Manager. Không sửa rule, decoder hoặc cấu hình của Manager.

## Sự cố phát hiện và xử lý

Ban đầu WEB kết nối đến Manager TCP 1514/1515 bị Connection refused. SSH Manager hoạt động nhưng wazuh-manager.service failed từ lúc boot; journal ghi wazuh-apid did not start correctly và tiến trình bị Killed. Chưa có bằng chứng xác định nguyên nhân gốc. Tại lúc kiểm tra, RAM available khoảng 3.6Gi và swap chưa dùng; truy vấn kernel không trả dòng OOM được yêu cầu.

Đã thực hiện systemctl start wazuh-manager, dịch vụ chuyển active và mở TCP 1514/1515/55000. Kiểm tra sau đó cho thấy wazuh-manager, wazuh-indexer, wazuh-dashboard và filebeat đều active. Không sửa cấu hình hay rule Manager. Cần theo dõi lại lần boot tiếp theo, không coi khởi động lại thành công là đã khắc phục nguyên nhân gốc.

## Cấu hình trên WEB

- Dịch vụ auditd và wazuh-agent được enable và đang active.
- Cấu hình agent: /var/ossec/etc/ossec.conf.
- Nguồn audit: /var/log/audit/audit.log, log_format audit; kiểm tra không thêm trùng nguồn. Cài Auditd trước Agent giúp cấu hình mặc định nhận nguồn này.
- Agent logcollector xác nhận đang đọc /var/log/nginx/access.log, /var/log/nginx/error.log, /var/log/audit/audit.log và các nguồn mặc định; có thu journald.
- Rule thử Auditd: /etc/audit/rules.d/70-agroflow-probe.rules.
- Nội dung hiện hành: -w /var/lib/agroflow-monitoring/audit-probe -p wa -k audit-wazuh-w.
- Thư mục thử: /var/lib/agroflow-monitoring/audit-probe.
- Rule probe ban đầu dùng key agroflow_probe; đã đổi sang audit-wazuh-w vì Manager có sẵn mapping audit-wazuh-w:write. Bản trước đổi lưu tại /var/lib/agroflow-monitoring/probe-rule.before-wazuh-key.
- Không thêm audit rule cho toàn bộ execve, database hoặc nội dung BLOB. Chưa triển khai bộ giám sát sản xuất theo TC/PH/NV/TV/VH.
- Repository: /etc/apt/sources.list.d/agroflow-wazuh.list; keyring /usr/share/keyrings/agroflow-wazuh.gpg.
- Script cài trên WEB: /home/agroflow/install-web-monitoring.sh; bản lưu trong workspace cùng tên. Script dùng tham số audit hoặc agent 4.14.8 10.20.60.10; không chạy lại chế độ agent khi đã có agent.

Hồ sơ cài được bảo vệ trên WEB trong /var/lib/agroflow-monitoring/setup-20261105T095207Z và các setup tiếp theo, gồm install.log. Bản sao cấu hình agent trước kiểm tra bổ sung nguồn audit nằm trong setup của lần cài agent hoàn tất khoảng 09:56:48 UTC. Không sao chép client.keys vào hồ sơ dùng chung.

## Bằng chứng kiểm thử đầu cuối

1. Tạo /var/lib/agroflow-monitoring/audit-probe/e2e-20261105.txt bằng thao tác vô hại trên WEB.
2. Auditd ghi SYSCALL openat success=yes, nametype CREATE; audit event 1793872765.384:1128; auid=1000 (agroflow), uid=0 (root qua sudo), exe=/usr/bin/bash; key=audit-wazuh-w.
3. Wazuh agent state: status='connected'; last_keepalive và last_ack có giá trị mới.
4. Manager agent_control -i 007: WEB01 Active, Client version Wazuh v4.14.8.
5. /var/ossec/logs/alerts/alerts.json trên Manager có cảnh báo:

```json
{
  "timestamp": "2026-11-05T09:59:26.557+0000",
  "rule": {
    "id": "80790",
    "level": 3,
    "description": "Audit: Created: /var/lib/agroflow-monitoring/audit-probe/e2e-20261105.txt."
  },
  "agent": {"id": "007", "name": "WEB01", "ip": "10.20.50.10"},
  "manager": {"name": "ubuntuserver"},
  "id": "1793872766.1181691",
  "decoder": {"name": "auditd"},
  "location": "/var/log/audit/audit.log"
}
```

Đây là trích lọc các trường từ sự kiện thực tế, không phải toàn văn alert. Audit tại nguồn lúc 16:59:25 Việt Nam; cảnh báo Manager lúc 16:59:26. Chứng minh đã chạy luồng Auditd → Agent → Manager → alerts.json. Chưa tra cứu sự kiện trong Indexer hoặc quan sát giao diện Dashboard. Có thể tìm sau bằng agent.id:007 AND rule.id:80790 trong khoảng thời gian phù hợp.

## Ảnh hưởng và giới hạn

Health AgroFlow sau cài trả status ok, database connected. Không sửa mã nguồn, schema hay dữ liệu nghiệp vụ. APT cài auditd, libauparse0t64, wazuh-agent và nâng libaudit-common/libaudit1 theo phụ thuộc; needrestart đã khởi động lại một số dịch vụ hệ điều hành. Không khởi động lại máy.

Website JSONL, log backup/MySQL và các rule nghiệp vụ chưa được tích hợp riêng trong bước này. Rule 80790 xác nhận tạo tệp; không kết luận đó là hành vi tấn công. Chưa cài WAF.

## Kiểm tra nhanh lần sau

WEB, với sudo khi cần:

```bash
systemctl is-active auditd wazuh-agent agroflow nginx mysql
sudo grep -E '^(status|last_keepalive|last_ack)' /var/ossec/var/run/wazuh-agentd.state
sudo auditctl -s
sudo auditctl -l
curl -sS http://127.0.0.1:3000/api/health
```

Manager, chỉ đọc:

```bash
sudo /var/ossec/bin/agent_control -i 007
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

## Tài liệu tham chiếu

- https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html
- https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html

## Gỡ bỏ hoặc hoàn tác

Không tự động gỡ trong phiên này. Khi cần, dừng/disable wazuh-agent và gỡ gói theo quy trình; phối hợp Người 1 xóa enrollment 007 nếu bỏ WEB01. Audit rule riêng có thể được lưu trữ rồi loại bỏ và nạp lại bằng augenrules, giữ nguyên các rule khác. Kiểm tra apt-mark hold trước thao tác cập nhật/gỡ. Không dùng auditctl -D riêng lẻ để xóa toàn bộ rule của hệ thống.

---

<a id="ho-so-5"></a>
## 5. CAI_DAT_WAF_2026-11-05.md

# Kết quả cài WAF trên Ubuntu WEB

Ngày 05/11/2026. WAF đã được cài và hoạt động trên Ubuntu WEB 10.20.50.10. Chế độ **DetectionOnly**, paranoia level 1. Chưa bật chặn; chưa thay đổi cấu hình/rule trên Wazuh Manager trong phiên này.

## Kiến trúc và phiên bản

Máy phòng ban → Nginx HTTPS 443 + ModSecurity → AgroFlow 127.0.0.1:3000 → MySQL localhost.

Gói từ APT Ubuntu, không biên dịch hoặc tải script cài bên ngoài:

- Nginx 1.24.0-2ubuntu7.19.
- Connector libnginx-mod-http-modsecurity 1.0.3-1build3.
- libmodsecurity3t64 3.0.12-1.1build2.
- OWASP CRS modsecurity-crs 3.3.5-2.

Đây là phiên bản ghi nhận tại lúc cài, không phải tuyên bố đã đánh giá toàn bộ CVE hoặc đạt chứng nhận bảo mật. Khi nâng cấp Nginx/module/CRS phải kiểm tra lại tương thích và các ngoại lệ.

Nginx đã nạp module và báo 923 local rules sau khi thêm chính sách Host. WAF bật tại server HTTPS AgroFlow nên áp dụng cho các location kế thừa của website. Cổng 80 vẫn redirect HTTPS; backend vẫn chỉ nghe loopback. Request từ tiến trình cục bộ gọi trực tiếp 127.0.0.1:3000 không đi qua WAF.

## Cấu hình chính

| Thành phần | Đường dẫn |
|---|---|
| Nginx site | /etc/nginx/sites-available/agroflow |
| Module | /usr/lib/nginx/modules/ngx_http_modsecurity_module.so |
| WAF entry point | /etc/agroflow-waf/main.conf |
| ModSecurity settings | /etc/agroflow-waf/modsecurity.conf |
| Chính sách cục bộ | /etc/agroflow-waf/policy.conf |
| CRS setup | /etc/modsecurity/crs/crs-setup.conf |
| CRS rules | /usr/share/modsecurity-crs/rules/ |
| Log thô WAF, chỉ đọc cục bộ | /var/log/agroflow-waf/audit.jsonl |
| Nginx error chi tiết cho HTTPS site | /var/log/agroflow-waf/nginx-error.log |
| Log WAF đã chọn trường gửi Agent | /var/log/agroflow-waf/events.jsonl |
| Log tương quan request | /var/log/nginx/agroflow-waf-access.jsonl |
| Bộ chuẩn hóa | /usr/local/lib/agroflow-waf/normalizer.py |
| Dịch vụ chuẩn hóa | agroflow-waf-log.service |
| Trạng thái đọc log | /var/lib/agroflow-waf/offset.json |
| Logrotate | /etc/logrotate.d/agroflow-waf |

SecRuleEngine DetectionOnly; request body inspection On, JSON body parser theo config khuyến nghị của gói; giới hạn tổng body 11 MiB và body không tính file 1 MiB. Nginx vẫn có giới hạn 11m trước đó. Response body inspection Off, không tuyên bố giám sát/chặn nội dung phản hồi hoặc rò rỉ dữ liệu qua response.

Ngoại lệ hẹp: bỏ rule 920350 chỉ khi Host là chính xác 10.20.50.10 hoặc 10.20.50.10:443, vì địa chỉ IP là cách truy cập hợp lệ của lab. Không bỏ rule trên toàn hệ thống, không bỏ rule SQLi/XSS/traversal. Tên miền agroflow.internal không cần ngoại lệ numeric Host. Mã chính sách ModSecurity cục bộ: 100010 và 100011; không nhầm với ID rule Wazuh.

## Bảo vệ dữ liệu trong log

- Audit dùng JSON, các phần AHZ; không chủ động ghi request body, request/response header hoặc response body trong audit. Tuy vậy message của rule có thể chứa dữ liệu khớp, nên log thô vẫn được coi là nhạy cảm.
- Module Ubuntu không hỗ trợ modsecurity_use_error_log. Vì vậy error log của riêng HTTPS site chuyển sang tệp được bảo vệ /var/log/agroflow-waf/nginx-error.log; không thu tệp này vào Agent. Nginx error.log cũ vẫn tồn tại cho các context khác. Đây là thay đổi nguồn log cần lưu ý khi điều tra lỗi HTTPS/upstream.
- Agent chỉ thu events.jsonl đã allowlist và correlation JSONL. Không thu audit.jsonl hoặc nginx-error.log thô.
- events.jsonl không có cookie, Authorization, body, matched-data hoặc query string. Có transaction_id, event_id, IP, method, path, status, rule_ids, severity và engine_mode.
- Correlation log không có query/header/body; transaction_id nối với WAF, backend_request_id nối với request_id của AgroFlow. Hai log access (combined và correlation) có mục đích riêng, không được cộng thành hai lần tấn công.
- Bộ chuẩn hóa chạy bằng tài khoản hệ thống riêng agroflow-waf-log, có giới hạn systemd, không chạy root. Offset được lưu qua restart; raw log có quyền đọc hạn chế.
- Đã thử marker mật khẩu/cookie/Authorization giả; chúng không xuất hiện trong hai log chuyển tiếp. Không dùng mật khẩu thật để tạo phép thử này.

Logrotate quay vòng theo ngày, giữ 7 thế hệ và kiểm tra maxsize 20M khi logrotate chạy. Dùng copytruncate để giữ descriptor của ModSecurity; phương pháp này có cửa sổ mất dữ liệu khi copy/truncate dưới tải, nên không coi đây là hệ thống lưu log không mất mát. Đã kiểm tra dry-run; chưa kiểm thử quay vòng dưới tải lớn.

## Kết quả kiểm thử

Thử từ Windows thật 10.20.50.254; các tham số tấn công GET được gửi vào /api/health chỉ đọc, không nhằm đọc tệp thật hoặc thay đổi database.

| Phép thử cuối | Kết quả |
|---|---|
| Health hợp lệ qua IP đã duyệt | 200, không có rule WAF khớp |
| Health hợp lệ qua Host agroflow.internal | 200, không có rule WAF khớp |
| SQLi trong query | 200; CRS 942100 và 949110 |
| XSS trong query | 200; CRS 941100/941110/941160 và 949110 |
| Traversal trong query | 200; CRS 930100/930110/930120, 932160 và 949110 |
| Host numeric khác 192.0.2.44 | 200; vẫn có 920350, chứng minh ngoại lệ không mở rộng |
| XSS trong JSON body đăng nhập với thông tin giả | Backend trả 401; WAF phát hiện 941100/941110/941160 và 949110 |

7/7 phép thử phân biệt kết quả mong đợi đạt. 949110 cho biết vượt ngưỡng anomaly của CRS; với DetectionOnly, điều này không chứng minh request đã bị WAF chặn. HTTP 200 ở API health cũng không chứng minh SQLi/XSS đã khai thác thành công.

Trang chủ HTTPS trả 200, HTTP chuyển 301 sang HTTPS, backend health status ok và database connected. Agent đã thu log WAF và correlation với drops=0 trong bộ đếm được chụp. Tệp cấu hình WAF, CRS, normalizer, service và module đều có baseline FIM.

Chưa kiểm thử đăng nhập thành công, upload/download và toàn bộ quy trình bằng tài khoản nghiệp vụ trong phiên cài WAF. Chưa bật chặn, chưa đánh giá tải lớn và chưa kiểm thử phục hồi WAF từ backup. Duy trì DetectionOnly cho đến khi kiểm thử các luồng hợp lệ và hiệu chỉnh hoàn tất.

## Backup và hoàn tác

- Backup đầy đủ trước cài đã thành công lên Drive, exit 0. Cấu hình Nginx và Agent trước đổi còn tại /var/lib/agroflow-monitoring/waf-setup-20261105/nginx.before và ossec.conf.before.
- Đã cập nhật danh sách backup trong /usr/local/lib/agroflow-backup/backup.py để có /etc/agroflow-waf, /etc/modsecurity, normalizer, service, logrotate và log WAF đã chọn trường. Bản code backup trước sửa lưu trong thư mục hồ sơ cài được bảo vệ.
- Backup đầy đủ sau cài cũng đã thành công, exit 0. Dữ liệu trạng thái/snapshot gần nhất xem /var/lib/agroflow-backup/last-success.json.
- Khôi phục trên máy mới cần cài các gói đúng phiên bản/tương thích và tạo tài khoản dịch vụ; restore config đơn thuần không thay thế cài dependency. Chưa thực hiện restore trong phiên này.
- Nếu cần tắt WAF tạm thời có phê duyệt, đổi modsecurity on thành off trong đúng site, nginx -t rồi reload. Không tắt backend validation hoặc đổi quyền người dùng để bỏ qua lỗi WAF.
- Nếu hoàn tác toàn bộ phiên cài, dùng config Nginx/Agent trước đổi, kiểm tra trước reload/restart; dừng/disable normalizer sau khi bỏ nguồn log tương ứng. Gỡ gói chỉ sau khi bỏ tham chiếu module và kiểm tra dependency. Giữ hồ sơ/bằng chứng.

## Bàn giao Người 1

agroflow-waf-rules.xml đề xuất dải 111050–111069, chưa áp dụng và chưa kiểm thử matching trong dịch vụ Manager. XML đã kiểm tra cấu trúc tại workspace. Người 1 kiểm tra trùng ID, sao lưu và chạy analysisd -t/logtest trước khi nạp.

- 111050: phân loại JSON metadata WAF.
- 111051: rule WAF khớp, level 5.
- 111052: ngưỡng anomaly 949110 xuất hiện, level 7; không kết luận bị chặn/xâm nhập.
- 111053: chỉ numeric Host 920350, level 3.
- 111060: correlation access metadata, level 0; không tạo alert mỗi request.

Không cần decoder riêng vì log đã được chuẩn hóa thành JSON phẳng. Manager hiện không lưu toàn bộ archives; log level 0 không tự xuất hiện thành cảnh báo Dashboard. Không khẳng định WAF đã có alert riêng trên Dashboard trước khi Người 1 triển khai và kiểm tra.

## Tài liệu đối chiếu

- https://github.com/owasp-modsecurity/ModSecurity-nginx
- https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29
- https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
- https://packages.ubuntu.com/noble/modsecurity-crs

---

<a id="ho-so-6"></a>
## 6. DANH_MUC_TEP_GIAM_SAT.md

# Danh mục đề xuất giám sát tệp Ubuntu WEB

Bổ sung sau cài WAF: who-data đã thêm /etc/agroflow-waf, /etc/modsecurity, /usr/share/modsecurity-crs, /usr/local/lib/agroflow-waf và /usr/lib/nginx/modules; service được bao phủ bởi /etc/systemd/system. Không nội dung diff. Đã xác minh baseline cho main/modsecurity/policy.conf, crs-setup.conf, normalizer.py, unit và module .so. Logrotate và logformat mới cũng là cấu hình cần bảo vệ; logformat nằm trong /etc/nginx đã theo dõi.

Cập nhật cuối phiên 05/11/2026: đã áp dụng FIM who-data và kiểm chứng 34/34 tệp ưu tiên trong baseline; dist theo lịch. Đã thử thêm/sửa/xóa trong thư mục riêng và thấy cảnh báo Manager 554/550/553 có thông tin người/tiến trình. Xem BAN_GIAO_RULE_NGUOI_1.md và monitoring-evidence/endpoint-verification.json; các đoạn “chưa áp dụng” bên dưới ghi nhận trạng thái lúc lập danh mục, không phải trạng thái mới nhất.

Đối chiếu trực tiếp trên 10.20.50.10 ngày 05/11/2026. Đây là danh sách đề xuất, chưa áp dụng cấu hình FIM/Auditd sản xuất. Chính sách: không được thay đổi ngoài bảo trì/triển khai có phê duyệt. FIM phát hiện thay đổi; quyền hệ điều hành mới giới hạn việc sửa. Không mặc định chặn, phục hồi tự động hoặc gán mọi thay đổi thành tấn công.

## Mã nguồn cần bảo vệ nghiêm ngặt

- /opt/agroflow/server/index.js — API, xác thực, phiên, CSRF, quyền và nghiệp vụ.
- /opt/agroflow/shared/document-policy.js — quyền xem/tải chứng từ.
- /opt/agroflow/server/contract-workflow.js — quy trình hợp đồng/đơn.
- /opt/agroflow/server/director.js — phê duyệt và quyền Giám đốc.
- /opt/agroflow/server/file-validation.js — kiểm tra upload.
- /opt/agroflow/server/document-storage.js — đọc/ghi document_contents trong MySQL.
- /opt/agroflow/server/runtime-config.js — kiểm tra runtime, proxy và IP.
- /opt/agroflow/server/log-writer.js — xuất nhật ký.
- /opt/agroflow/server/db.js — lớp kết nối/truy vấn database.
- /opt/agroflow/package.json và /opt/agroflow/package-lock.json — lệnh chạy, hook và phụ thuộc.

Theo dõi cả thư mục server/shared để phát hiện thêm file lạ, đổi tên hoặc thay thế file, không chỉ các tên đã biết. Schema SQL/migration được theo dõi theo đợt triển khai, không mặc định là schema hiện hành của database. dist cần baseline theo release; node_modules không theo dõi toàn bộ thời gian thực ở bước đầu.

## Cấu hình và bí mật cần bảo vệ nghiêm ngặt

- /etc/agroflow/agroflow.env.
- /etc/nginx/nginx.conf và /etc/nginx/sites-available/agroflow; theo dõi thay đổi site/symlink và file bổ sung trong cấu hình Nginx.
- /etc/systemd/system/agroflow.service; bao gồm unit override nếu được tạo.
- /etc/mysql/mysql.conf.d/mysqld.cnf; mở rộng file include khi xác minh cấu hình đầy đủ.
- /etc/nginx/tls/agroflow/server.key và server.crt.
- /var/ossec/etc/ossec.conf và client.keys.
- /etc/audit/auditd.conf và /etc/audit/rules.d/70-agroflow-probe.rules; giám sát toàn bộ rules.d khi thêm rule.
- /usr/local/sbin/agroflow-backup.
- /opt/agroflow/scripts/backup-before-update.mjs.
- /etc/systemd/system/agroflow-backup.service và agroflow-backup.timer.
- /etc/agroflow-backup/rclone.conf và restic-password.txt.
- /etc/ssh/sshd_config; theo dõi sshd_config.d nếu có thay đổi.
- /etc/sudoers, /etc/passwd, /etc/shadow, /etc/group; theo dõi sudoers.d và SSH authorized_keys theo tài khoản khi triển khai.

Bí mật: không bật report_changes hoặc gửi nội dung diff cho env, shadow, client.keys, TLS key, rclone.conf, restic-password.txt và các tệp chứa token/mật khẩu. Chỉ thu hash, metadata, loại thay đổi, người/tiến trình khi được hỗ trợ. Không cần đọc tệp bí mật để trình bày danh mục.

## Cách giám sát

FIM: hash, kích thước, owner/group, mode, thêm/xóa/sửa. Who-data dựa Auditd nếu cấu hình và kiểm thử thành công; ghi người dùng gốc, effective user, tiến trình và thời gian. Không thu nội dung diff hàng loạt. Chính sách quyền ghi phải kiểm tra cả thư mục cha, quyền tạo/thay thế file và systemd override; không chỉ chmod từng file.

Các file cấu hình OS có thay đổi hợp lệ khi đổi mật khẩu, thêm người dùng, cài gói, gia hạn TLS hoặc bảo trì. Đối chiếu lịch và phê duyệt; ưu tiên xác minh cao cho thay đổi ngoài lịch hoặc do tài khoản ứng dụng.

Log ứng dụng/Nginx/audit/backup thay đổi liên tục: thu log và theo dõi dấu hiệu xóa/truncate/đổi quyền/mất nguồn, không phát cảnh báo nghiêm trọng cho mọi append hoặc logrotate.

MySQL BLOB: giám sát nội dung tài liệu qua kiểm tra hash/version, audit nghiệp vụ và cơ chế database phù hợp; không FIM toàn /var/lib/mysql để kết luận tài liệu bị sửa. Cần thêm bằng chứng để quy kết ai thay đổi dữ liệu trực tiếp.

## Tình trạng

Chỉ rule Auditd thử tại /var/lib/agroflow-monitoring/audit-probe và nguồn mặc định của agent đã được kiểm chứng. Chưa cấu hình giám sát nghiêm ngặt toàn bộ danh mục này. Không sửa tệp sản xuất để demo; thử trước bằng tệp riêng hoặc thay đổi có phê duyệt, backup và phương án hoàn tác.

---

<a id="ho-so-7"></a>
## 7. DASHBOARD_WAZUH_2026-11-06.md

# Bộ 5 dashboard AgroFlow trên Wazuh — 06/11/2026

## Đã triển khai

Tạo trực tiếp trong Wazuh Dashboard 4.14.8 (OpenSearch Dashboards 2.19.6), dùng Saved Objects API và index pattern hiện có wazuh-alerts-*. Không tạo giao diện ngoài, không nhân bản log, không sửa quyền người dùng hay tắt xác minh TLS. API chạy trên loopback đúng SAN 127.0.0.1 của chứng chỉ; credential admin từ gói cài chỉ đọc trong bộ nhớ trên server, không ghi vào script, output hoặc backup.

| Trang | Địa chỉ |
|---|---|
| 01 · SOC tổng quan | https://10.20.60.10/app/dashboards#/view/agroflow-soc |
| 02 · Suricata & mạng | https://10.20.60.10/app/dashboards#/view/agroflow-suricata |
| 03 · WAF & website | https://10.20.60.10/app/dashboards#/view/agroflow-web |
| 04 · Endpoint & tệp quan trọng | https://10.20.60.10/app/dashboards#/view/agroflow-endpoint |
| 05 · Vận hành & backup | https://10.20.60.10/app/dashboards#/view/agroflow-operations |

Tổng 60 Saved Objects: 5 dashboard, 50 visualization, 5 saved search. Mỗi trang 11 panel: giới thiệu và điều hướng, 4 KPI, biểu đồ thời gian, donut phân bố, 2 bảng xếp hạng, bảng sự kiện và hướng dẫn phạm vi dữ liệu. Thanh chuyển nhanh 01–05 có trên tất cả trang. Mặc định 24 giờ, tự làm mới 60 giây. Chưa đổi trang chủ chung của Wazuh.

Lượt nhập đầu với header securitytenant:global bị từ chối quyền ghi và không tạo đối tượng. Nhập lại vào tenant mặc định của admin thành công; trình duyệt đang đăng nhập admin nhìn thấy đủ năm trang. Không mở rộng quyền hoặc sửa multitenancy để vượt lỗi. Các cập nhật về sau chỉ ghi đè ID agroflow-* do chính tác vụ này tạo, không sửa Saved Objects khác.

## Nội dung và phạm vi số liệu

- **SOC:** tổng alert, level từ 10 trở lên, số agent có alert, alert Suricata; diễn biến, phân bố level, decoder và tài sản nổi bật.
- **Suricata:** tổng alert, priority 1, IP nguồn khác nhau, số SID khác nhau; diễn biến, phân bố priority, signature và IP nguồn; bảng có SID, IP/cổng, level.
- **WAF/web:** nhóm cảnh báo web/Nginx, nguồn WAF riêng, đăng nhập thất bại, IP nguồn; nhóm alert, nguồn log và chi tiết sự kiện.
- **Endpoint:** Windows/Auditd/FIM/xác thực; số FIM và Auditd, đường dẫn tệp, agent và sự kiện mới.
- **Vận hành:** cảnh báo Wazuh và nguồn backup khi được tích hợp; backup failed/completed, mức ưu tiên, nguồn và sự kiện.

Số liệu phản ánh alert đã index trong khoảng thời gian được chọn, không phải toàn bộ request hoặc số máy đang online. Cardinality agent chỉ đếm agent có alert. Log syslog mạng đi trực tiếp qua Manager mang agent.id=000; không suy đó là cài agent lên pfSense.

Các bộ rule WEB/WAF/backup riêng trước đây vẫn chưa được áp dụng trong tác vụ dựng dashboard. Vì vậy số WAF riêng và backup hiện bằng 0 không chứng minh nguồn không có sự kiện, không chứng minh backup thành công và không chứng minh WAF chặn được request. Những giới hạn này được ghi tại panel hướng dẫn mỗi trang. WAF vẫn DetectionOnly. Trang Vận hành không thay heartbeat Agents, kiểm tra lịch backup độc lập hay phép thử khôi phục dữ liệu.

## Kiểm chứng API và dữ liệu

- Nhập Saved Objects thành công: successCount=60, không lỗi ở bản cuối.
- Đọc lại cả 5 dashboard: mỗi trang có 11 panel và 11 reference.
- Chạy 40 truy vấn tổng hợp theo đúng field và bộ lọc của các panel KPI/biểu đồ/bảng: tất cả thành công, không failed shard.
- Bản chụp API cuối: SOC khoảng 1.090 alert/24h, 6 alert level >=10, 3 agent có alert; Suricata 4; web 21; endpoint 171 (FIM41, Auditd71); vận hành58. Tổng SOC có thể tăng trong lúc kiểm tra vì log tiếp tục được gửi.
- Đã mở dashboard trong Edge bằng skill computer-use để kiểm tra hiển thị thật. Có giai đoạn trình duyệt báo lỗi truy vấn tạm thời/ERR_NETWORK_CHANGED; sau tải lại và ổn định, các panel biểu đồ/bảng hiển thị. Không coi lỗi tạm thời lúc đang tải là kết quả xác minh cuối. Chi tiết kiểm tra giao diện cuối nằm trong dashboard-evidence/ui-verification.json.
- Có sửa schema bảng terms sang bucket, bổ sung nhãn bucket và tăng chiều cao panel, rút gọn điều hướng để tránh cắt chữ ở cửa sổ nhỏ. Không dùng dữ liệu mẫu để làm đầy giao diện.

## Xác minh Suricata từ gói thử tới dashboard

Đợt thử mới 00:05:11–00:05:26 ngày 06/11 +07. Hai DNS query dương mô phỏng chữ ký SID2062547 và hai query âm; tên dương thuộc .invalid, không liên lạc C2 thật, recursion-desired tắt. Suricata không đổi rule/chế độ trong lượt này.

| Ca dương | Luồng UDP | Thời điểm alert index UTC | Thời gian hiển thị giao diện +07 |
|---|---|---|---|
| IT/em4 | 10.20.40.254:52008 → 10.20.40.1:53 | 2026-11-05 17:05:19.163 +0000 | Nov 6, 2026 @ 00:05:19.163 |
| SERVER/em5 | 10.20.50.1:35872 → 10.20.50.10:53 | 2026-11-05 17:05:20.975 +0000 | Nov 6, 2026 @ 00:05:20.975 |

Cả hai khớp đúng SID2062547 và rule Wazuh111101/level12. Đã đối chiếu IP/cổng/SID giữa EVE mới và document index, mỗi ca đúng một document. Index của hai sự kiện mang ngày UTC **2026.11.05**, dù giao diện hiển thị ngày Việt Nam 06/11; không phải thất lạc log sang index khác.

Dashboard Suricata hiển thị tổng **4 alert**, gồm 2 bản từ đợt trước 23:48 và 2 bản mới 00:05; priority1=4, IP nguồn=2, SID khác nhau=1. Bảng sự kiện đã hiển thị đúng hai dòng mới với port52008/35872 và hai dòng cũ. Mẫu DNS âm được ghi DNS event tại nguồn nhưng không sinh alert Suricata trong cửa sổ thu; chúng không xuất hiện trên dashboard alert là đúng thiết kế.

Các alert mang tên ET MALWARE chỉ là mẫu nghiệm thu có chủ đích, không kết luận hệ thống nhiễm malware. Phép thử này xác minh đường Suricata → syslog → Wazuh Manager → indexer → dashboard, chưa thay kiểm thử tấn công routed/WAN/phòng ban hoặc kiểm chứng chặn IPS.

## Sử dụng

1. Vào Dashboards, mở một trang 01–05 hoặc dùng liên kết ở bảng trên.
2. Chọn khoảng thời gian ở đầu trang; mặc định Last 24 hours. Sự kiện cũ hơn cần mở rộng thời gian.
3. Ô tìm kiếm dùng Lucene, ví dụ `data.id:2062547`, `data.srcip:10.20.40.254`, `rule.level:[10 TO 15]`. Giữ/ghép bộ lọc phạm vi của trang khi sửa query.
4. Có thể bấm giá trị trong biểu đồ/bảng để lọc, mở dòng sự kiện để đọc chi tiết. Không suy số blocked request từ số alert.
5. Nếu đang điều tra sự kiện cũ và không thấy, kiểm tra thời gian, bộ lọc, trạng thái Refresh và nguồn dữ liệu trước khi kết luận mất log.

## Backup và bằng chứng

Thư mục dashboard-evidence/:

- agroflow-dashboards-native-export.ndjson: bản export native cuối gồm đủ dependency/index pattern; dùng Import trong Saved Objects để phục hồi sang Wazuh tương thích. Thao tác import có thể báo xung đột nếu object cùng ID đã có; chỉ chọn overwrite cho bộ AgroFlow sau khi sao lưu.
- agroflow-five-dashboards.ndjson: định nghĩa sinh từ mã nguồn; native export là bản ưu tiên để khôi phục.
- dashboard-catalog.json: ID, URL, query phạm vi từng trang.
- import-result.json: lần nhập cuối thành công.
- api-verification.json: query các trang, 40 tổng hợp và 4 Suricata documents.
- suricata-index-correlation.json: kết quả đối chiếu hai gói mới với index.
- suricata-live-20261106/: EVE mới, tham số gói, timestamp, SHA256 và kết quả thử.
- ui-verification.json: kiểm tra giao diện thực tế.

Mã xây dựng: build-wazuh-dashboards.py. Mã import/verify qua SSH và API là công cụ tái lập, không chứa mật khẩu. Chưa áp dụng rule WEB/WAF/backup mới hoặc thay đổi cấu hình Suricata trong tác vụ này.

## Phần cần làm tiếp

Hoàn thiện nguồn/rule WEB-WAF-backup để lấp đúng các KPI còn thiếu; bổ sung giám sát mất lịch backup độc lập, kiểm thử restore và agent heartbeat nếu cần dashboard vận hành đầy đủ. Vẫn còn flowbit Suricata, ma trận nội bộ/WAN và hiệu chỉnh WAF trước chặn, theo VIEC_CAN_LAM_TIEP.md.

---

<a id="ho-so-8"></a>
## 8. HO_SO_HIEN_TRANG_2026-11-05.md

# Hồ sơ hiện trạng Ubuntu WEB AgroFlow

Cập nhật sau phiên kiểm kê: đã cài Auditd và Agent; xem CAI_DAT_AGENT_AUDITD_2026-11-05.md. Các mục “chưa cài” dưới đây là trạng thái trước cài, giữ lại làm bằng chứng ban đầu.

Kiểm tra ngày 05/11/2026 khoảng 16:40–16:44 giờ Việt Nam bằng SSH và HTTP từ Windows thật. Chỉ kiểm tra đọc và gửi request GET/HEAD; không thay đổi cấu hình, không chạy backup thủ công, không sửa database, không khai thác lỗ hổng. Request kiểm tra có thể tạo log truy cập thông thường.

## Địa chỉ và đường dẫn đã xác minh

| Thành phần | Giá trị | Bằng chứng |
|---|---|---|
| Ubuntu WEB | 10.20.50.10/24, hostname webserver | SSH hostname, ip -br address |
| Interface Ubuntu | ens33 | ip -br address |
| Gateway Ubuntu | 10.20.50.1 | ip route; chưa đăng nhập kiểm tra pfSense |
| Windows thật VMnet5 | 10.20.50.254/24 | Get-NetIPAddress và access.log Nginx |
| Windows thật VMnet4 | 10.20.40.254/24 | Get-NetIPAddress |
| Website | https://10.20.50.10 | HTTP 200 và health database connected |
| Tên cấu hình Nginx | agroflow.internal | server_name; chưa kiểm tra phân giải DNS |
| SSH | agroflow@10.20.50.10:22 | đăng nhập thành công bằng khóa hiện có |
| Mã nguồn server | /opt/agroflow | systemctl show agroflow |
| Backend | 127.0.0.1:3000 | ss -lnt và proxy_pass |
| MySQL | 127.0.0.1:3306; X protocol 127.0.0.1:33060 | ss -lnt |
| Dịch vụ ứng dụng | agroflow; User/Group agroflow-app | systemctl show |
| Node runtime | /opt/agroflow-runtime/node-v24.21.0-linux-x64/bin/node | ExecStart |
| Nginx site | /etc/nginx/sites-available/agroflow | đọc trực tiếp |
| Nginx log | /var/log/nginx/access.log và error.log | đọc danh sách; access.log đọc được |
| Log ứng dụng | /var/log/agroflow | thư mục tồn tại; tài khoản SSH không đọc được nội dung |
| TLS certificate | /etc/nginx/tls/agroflow/server.crt | cấu hình Nginx; chưa đọc được chứng chỉ do quyền |
| TLS private key | /etc/nginx/tls/agroflow/server.key | chỉ ghi nhận đường dẫn từ cấu hình; không đọc nội dung |
| Backup state | /var/lib/agroflow-backup/last-success.json | đường dẫn dự kiến từ lịch sử; lần này chưa đọc được do quyền |
| Backup logs | /var/log/agroflow-backup/ | journal chỉ dẫn; chưa đọc được chi tiết |

Đường dẫn khóa SSH trên máy thật: C:\Users\ACER\Documents\ChatGPT\đồ án tốt nghiệp\private-migration\ubuntu-deploy-key. Chỉ tham chiếu vị trí; không sao chép nội dung khóa vào hồ sơ.

## Luồng truy cập đã xác nhận

Windows thật 10.20.50.254 → Ubuntu WEB 10.20.50.10:443 Nginx TLS → HTTP 127.0.0.1:3000 AgroFlow → MySQL localhost.

Từ Windows thật, HTTP cổng 80 trả 301 đến https://10.20.50.10/. HTTPS /api/health trả 200 với {"status":"ok","database":"connected","application":"AgroFlow"}. Trên Ubuntu, gọi trực tiếp backend /api/health cũng trả cùng trạng thái. Đây là bằng chứng health của ứng dụng, chưa phải kiểm tra nội dung và tính toàn vẹn toàn database.

Nginx proxy_pass http://127.0.0.1:3000; đặt Host từ $host, X-Real-IP và X-Forwarded-For từ $remote_addr, X-Forwarded-Proto từ $scheme. Access log ghi 10.20.50.254 cho request từ Windows. Chưa xác minh source_ip trong JSONL của ứng dụng hoặc cấu hình trust proxy backend vì mã và log bị giới hạn quyền.

Chú ý: gọi http://127.0.0.1 trên Ubuntu trả trang mặc định Nginx 200 do default site vẫn được bật. Request đến đúng IP 10.20.50.10 từ Windows trả redirect 301. Không nhầm kết quả localhost với virtual host AgroFlow.

## Kết quả kiểm tra

| Kiểm tra | Kết quả |
|---|---|
| SSH bằng khóa và xác minh host key hiện có | Thành công, dùng StrictHostKeyChecking=yes |
| agroflow, nginx, mysql | active |
| HTTPS từ Windows với bỏ qua kiểm tra CA | 200; health database connected |
| HTTPS từ Windows với xác minh chứng chỉ bình thường | Lỗi curl 60, SEC_E_UNTRUSTED_ROOT; máy này chưa tin cậy chuỗi CA |
| API /api/admin/users chưa đăng nhập qua HTTPS localhost | HTTP 401 |
| Kết nối Windows → cổng 3000 | Không kết nối được; backend chỉ bind loopback |
| Kết nối Windows → cổng 3306 | Không kết nối được; MySQL chỉ bind loopback |
| TLS cấu hình | TLSv1.2 và TLSv1.3; chưa thử handshake từng phiên bản |
| Nginx request body limit | client_max_body_size 11m |
| WAF | Không thấy gói libnginx-mod-http-modsecurity/libmodsecurity3/modsecurity-crs; modules-enabled trống; site không có directive WAF. Chưa có bằng chứng WAF đang hoạt động |
| Wazuh Agent | Unit wazuh-agent.service không tồn tại; dpkg-query không liệt kê gói |
| Auditd | Unit auditd.service không tồn tại; dpkg-query không liệt kê gói |
| sudo không tương tác | Không khả dụng: sudo yêu cầu mật khẩu |
| Mã nguồn, policy và JSONL thật | Được bảo vệ; chưa đọc được trong phiên SSH hiện tại |

Nginx 1.24.0-2ubuntu7.19; MySQL server 8.0.46-0ubuntu0.24.04.4 theo dpkg-query. Không đánh giá tình trạng cập nhật/lỗ hổng chỉ dựa vào các phiên bản này.

Response HTTPS có CSP, HSTS, nosniff và các header bảo vệ khác. /api/health có Cache-Control: no-store. Việc có header không chứng minh ứng dụng đạt toàn bộ yêu cầu bảo mật.

## Backup và tài nguyên

systemctl show agroflow-backup.service: Result=success, ExecMainStatus=0.

Journal ghi:

- 04/11/2026 13:28:49 UTC (20:28:49 Việt Nam): Backup failed at drive_upload; service exit 1.
- 05/11/2026 09:31:07 UTC (16:31:07 Việt Nam): Backup completed; Drive snapshot e5e163f80c2bc21d6469fef64f6fcf126f2373178d0ed40229ea3d5bfd028029; service hoàn tất thành công.

agroflow-backup.timer có Persistent=yes; lần kích hoạt gần nhất 05/11 09:29:42 UTC; lần kế tiếp 05/11 16:00 UTC tức 23:00 Việt Nam. agroflow-backup-check.timer có lịch tiếp theo; service check có Result=success, ExecMainStatus=0. Chưa đọc được script để kết luận check phát hiện đầy đủ những lỗi nào.

Chưa kiểm tra kho Drive trực tiếp hoặc restore từ snapshot trong phiên này. Không gọi backup đang thành công là bằng chứng đã phục hồi thành công.

Ổ đĩa root 57G, dùng 7.5G, còn khoảng 47G (14%). RAM tổng 2.9Gi, available khoảng 2.1Gi; swap chưa dùng tại thời điểm kiểm tra.

## Chưa kiểm chứng và bước tiếp theo

1. Đọc có quyền các tệp mã nguồn, shared/document-policy.js và log JSONL; xác nhận quyền chứng từ từng vai trò và IP nguồn thật ở lớp ứng dụng. Không đọc hoặc in .env/secrets.
2. Đọc cấu hình/nhật ký backup được bảo vệ và xác minh restore trong vùng biệt lập.
3. Xác minh chứng chỉ đang phục vụ, SAN, thời hạn và CA; quyết định cách phân phối CA tin cậy cho máy phòng ban.
4. Xác định địa chỉ Wazuh Manager và dải rule ID với Người 1; chưa có địa chỉ Manager được kiểm tra trong phiên này.
5. Chuẩn bị Wazuh Agent, Auditd và WAF dựa trên Nginx hiện có; backup thành công trước khi thay đổi runtime theo quy định dự án. Người 1 áp dụng thay đổi Manager.
6. Sau tích hợp mới thử SQLi/XSS/CSRF/upload/download, phiên, cảnh báo và đối chứng. Lần này chưa kiểm thử đăng nhập/nghiệp vụ có tài khoản và chưa thực hiện tấn công.

## Cách dùng hồ sơ lần sau

Dùng lại địa chỉ, account và đường dẫn ở trên làm điểm xuất phát. Chỉ kiểm tra nhanh SSH, health, trạng thái dịch vụ và backup mới nhất mỗi phiên; không cần dò lại toàn bộ mạng. Kiểm kê lại đầy đủ khi thay đổi topology, IP, reverse proxy, tài khoản dịch vụ hoặc lưu trữ. Hồ sơ là ảnh chụp trạng thái theo thời điểm, không bảo đảm trạng thái tương lai.

Lệnh SSH chuẩn từ PowerShell:

```powershell
ssh -i 'C:\Users\ACER\Documents\ChatGPT\đồ án tốt nghiệp\private-migration\ubuntu-deploy-key' -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes agroflow@10.20.50.10
```

Kiểm tra nhanh trong Ubuntu:

```bash
hostname
systemctl is-active agroflow nginx mysql
curl -sS http://127.0.0.1:3000/api/health
systemctl show agroflow-backup.service -p Result -p ExecMainStatus
systemctl list-timers agroflow-backup.timer agroflow-backup-check.timer --no-pager
journalctl -u agroflow-backup.service -n 12 --no-pager
```

---

<a id="ho-so-9"></a>
## 9. KIEM_THU_NGHIEP_VU_WAF_2026-11-05.md

# Kiểm thử nghiệp vụ hợp lệ qua WAF AgroFlow

Kết luận: **chưa nên bật chặn ngay**. Đã phát hiện hai nhóm cần hiệu chỉnh: PATCH hợp lệ bị chính sách phương thức chặn, và dấu nháy đơn trong tên file bị rule multipart nhận diện. Chưa sửa rule/cấu hình WAF trong phiên kiểm thử; vẫn DetectionOnly, PL1.

## Phạm vi và tài khoản

Kiểm thử HTTP/API qua https://10.20.50.10 từ Windows thật 10.20.50.254, có cookie phiên, CSRF token và Origin hợp lệ; dùng header kiểu trình duyệt. Cookie/CSRF/mật khẩu không ghi vào hồ sơ kết quả. Chứng chỉ lab chưa được máy thật tin cậy nên client kiểm thử bỏ qua xác minh CA, như đã ghi ở hồ sơ trước.

Một lần dùng mật khẩu trong hồ sơ cũ cho tài khoản Kinh doanh trả 401; không thử lại, không đổi mật khẩu và không gỡ khóa/tắt xác thực. Bộ đếm thất bại ghi nhận 1, tài khoản vẫn active và chưa bị khóa. Sau đó đã tạo 5 tài khoản tạm theo vai trò Sales, Warehouse, Accounting, Director, Admin với mật khẩu ngẫu nhiên, dùng xác thực/phiên backend thật. Các tài khoản này đã xóa sau thử. Việc tạo tài khoản tạm là bước chuẩn bị qua DB có ghi audit test.setup, không được tính là kiểm thử luồng đăng ký và quản trị phê duyệt tài khoản.

Mã dữ liệu thử: WAFBIZ-20261105-bf4cb19d. Đã backup đầy đủ lên Drive trước thử, exit 0. Lưu baseline hash/count 17 bảng nghiệp vụ trước khi tạo fixture.

## Kết quả tổng hợp

- 112 request trong bộ kiểm thử chính, tất cả đối chiếu được backend_request_id → transaction_id WAF.
- 103 request nghiệp vụ hợp lệ và 9 request đối chứng âm (thiếu CSRF, ngoài quyền hoặc dùng cookie đã logout).
- 112 kết quả backend đúng chính sách đã đối chiếu. Kỳ vọng ban đầu có hai mục nhầm rằng Kế toán được xem hợp đồng; triển khai thực tế chỉ cấp Kế toán invoice/payment/bank_receipt. Hai HTTP 403 đó là đúng backend, không phải WAF lỗi. api-results.json giữ kỳ vọng ban đầu để minh bạch; correlated-results.json ghi kỳ vọng theo policy thực tế.
- 4/103 request hợp lệ có rule WAF khớp và đạt ngưỡng anomaly; không suy rộng tỷ lệ này thành false-positive rate của hệ thống.
- Tám lần upload/download đối chiếu SHA-256 đều khớp, có PDF, DOCX, XLSX, PNG, JPEG và PDF khoảng 2/9 MiB.
- Thêm 4 phép thử chẩn đoán multipart không đăng nhập để tách riêng ảnh hưởng của tiếng Việt và dấu nháy trong tên file; không tạo thêm hồ sơ nghiệp vụ.

## Luồng đã chạy

| Nhóm | Nội dung | Kết quả |
|---|---|---|
| Đăng nhập/phiên | Đăng nhập thành công 5 vai trò, me, logout, cookie cũ sau logout | Đúng trạng thái; cookie cũ trả 401 |
| Chức năng đọc | Dashboard, lookups, hợp đồng/đơn/chứng từ, thông báo; kho/lô; thanh toán; Giám đốc; tài khoản/audit của Admin | Đúng quyền, không có WAF match trên request hợp lệ này |
| Tìm kiếm | Tiếng Việt, &, ngoặc và O'Brien trong giá trị tìm kiếm | Hoạt động; không thấy false positive |
| Đối tác | Tạo và PATCH hồ sơ thử, Unicode và O'Brien trong nội dung JSON | Backend thành công; PATCH có false positive 911100 |
| Sản phẩm | Tạo và PATCH sản phẩm với đơn vị tấn, quy cách có <, <=, %, &, ngoặc | Backend thành công; PATCH có false positive 911100 |
| Hợp đồng/đơn | Tạo cùng PDF, số lượng 12.500 tấn và điều khoản hợp lệ | 201; tên PDF có dấu nháy bị 920120 |
| Chuyển bước | Kinh doanh chuyển Kế toán; Kế toán gửi bước tiếp theo | Thành công, không WAF match |
| Chứng từ | Upload đúng loại của từng vai trò, xem/tải, kiểm tra hash | Thành công; riêng tên có dấu nháy bị 920120 |
| Dung lượng | PDF 2 MiB và 9 MiB | Upload 201, tải lại khớp hash; không WAF match |
| Giám đốc | Đọc dữ liệu và gửi thông báo cho chính tài khoản thử | Thành công, không WAF match |
| Đối chứng backend | Thiếu CSRF, Kho/Kế toán xem hợp đồng trái policy, cookie đã logout | 403/401 đúng kiểm soát; không nới quyền/WAF cho các trường hợp này |

Không thực hiện xuất/nhập kho thật, ghi nhận thu/chi, đổi quyền tài khoản thật hoặc đổi mật khẩu. Chưa tự động thao tác giao diện bằng trình duyệt và chưa chạy từ từng máy Windows phòng ban.

## Hai nhóm cần hiệu chỉnh trước khi bật chặn

### 1 Cho phép PATCH tại các API nghiệp vụ thực sự sử dụng

Hai request đã xác nhận hợp lệ:

- PATCH /api/partners/21: cập nhật đối tác thử, backend 200, WAF 911100 + 949110.
- PATCH /api/products/11: cập nhật sản phẩm thử, backend 200, WAF 911100 + 949110.

911100 kiểm tra REQUEST_METHOD. Chính sách phương thức hiện tại chưa cho PATCH. 949110 là hậu quả vượt ngưỡng anomaly, không phải rule gốc cần loại bỏ.

Đề xuất: bổ sung PATCH vào tx.allowed_methods theo danh sách URI rõ ràng, giữ backend xác thực/CSRF/phân quyền. Trước hết áp dụng cho /api/partners/{id}, /api/products/{id}. Mã nguồn còn có PATCH /api/contracts/{id} và /api/orders/{id}/correction; cần cho phép đúng phạm vi và kiểm thử trạng thái nghiệp vụ hợp lệ của hai route này trước nghiệm thu. Không mở PUT/DELETE hoặc tắt 911100 trên toàn site chỉ để hết cảnh báo.

### 2 Xử lý dấu nháy trong tên tệp multipart

Hai upload hợp lệ của bộ chính:

- Tạo hợp đồng với tên PDF Hợp đồng O'Brien.pdf: backend 201, WAF 920120 + 949110.
- Upload Phụ lục O'Brien - cà phê.pdf: backend 201, WAF 920120 + 949110.

Rule 920120 của CRS 3.3.5 kiểm tra FILES_NAMES|FILES và khớp dấu nháy/ký tự gây mơ hồ trong filename. Giá trị bị khớp trong hai request là FILES:file.

Chẩn đoán riêng bằng PNG hợp lệ, request không đăng nhập nên backend 401 theo dự kiến:

| Filename | 920120 |
|---|---|
| annex.png | Không |
| Phụ lục cà phê.png | Không |
| O'Brien.png | Có |
| Phụ lục O'Brien.png | Có |

Vì vậy **không cần bỏ dấu tiếng Việt hoặc nới kiểm tra UTF-8** để xử lý phát hiện này. Dấu nháy đơn là nguyên nhân được tách riêng trong phép thử.

Hai hướng hiệu chỉnh cần lựa chọn rồi kiểm thử:

1. Chuẩn hóa ký tự nháy gây mơ hồ trong filename gửi multipart, ví dụ O'Brien.pdf → O_Brien.pdf; giữ nguyên nội dung tệp và không loại bỏ tiếng Việt. Cần quyết định cách giữ tên hiển thị/tên tải về cho người dùng.
2. Nếu cần giữ nguyên dấu nháy trong tên gốc, dùng ngoại lệ đúng rule 920120 và đúng target FILES:file, chỉ tại POST /api/documents và POST /api/contracts hoặc /api/contracts/create-with-order, với multipart/form-data và kiểm tra filename/extension hợp lệ. Không tắt toàn bộ 920120, không bỏ kiểm tra multipart, không miễn trừ nội dung upload hay quyền backend. Phải kiểm thử thêm tên tệp độc hại trước khi duyệt ngoại lệ.

Chưa áp dụng một trong hai hướng vì phiên này được yêu cầu kiểm thử và báo các điểm cần hiệu chỉnh.

## Những điều không cần nới theo bằng chứng hiện có

- Không cần tăng giới hạn WAF chỉ để nhận file 2/9 MiB đã thử. Giữ giới hạn backend 10 MiB và Nginx/WAF 11 MiB; vẫn cần thử biên sát 10 MiB/over-limit sau này.
- Không thấy nhu cầu bỏ các rule SQLi/XSS cho toàn JSON body hoặc trường note/search. Các nội dung Unicode, O'Brien trong dữ liệu JSON/tìm kiếm và ký tự quy cách được thử không tạo false positive.
- Không tắt 949110, không tăng anomaly threshold để che bốn request trên; xử lý chính sách phương thức và filename tại gốc.
- Giữ PL1 trong giai đoạn này.
- Không mở quyền Kế toán/Kho đọc hợp đồng để chữa HTTP 403 đúng chính sách.

## Điều kiện nghiệm thu lại trước khi chuyển On

1. Áp dụng hiệu chỉnh hẹp cho hai nhóm trên, vẫn DetectionOnly.
2. Chạy lại PATCH hợp lệ và các tên tệp đã gây cảnh báo; thử thêm draft contract/order correction đúng trạng thái.
3. Chạy hồi quy SQLi, XSS, traversal, filename/path nguy hiểm, file sai loại và request vượt giới hạn để chắc chắn ngoại lệ không làm mất bảo vệ.
4. Kiểm tra thêm giao diện và thao tác từ các máy phòng ban; tài khoản hiện có cần mật khẩu đúng được xác nhận riêng, không dùng hồ sơ mật khẩu cũ để thử lặp.
5. Người 1 áp dụng rule Wazuh đã bàn giao và xác minh cảnh báo WAF trên Manager/Dashboard; Agent thu log chưa thay thế nghiệm thu cảnh báo.
6. Khi đủ bằng chứng, bật chặn trong đợt có người giám sát, kiểm tra request thực sự bị WAF từ chối và giữ phương án quay lại DetectionOnly.

## Dọn dữ liệu và trạng thái cuối

Đã xóa 1 đối tác, 1 sản phẩm, 1 hợp đồng, 1 đơn, 9 tài liệu/phiên bản và 5 tài khoản thử cùng phiên/idempotency của chúng. Các quan hệ con được kiểm tra và xóa theo đúng phạm vi mã thử; không có phát sinh stock/payment trên đơn thử. Audit và log được giữ.

Sau cleanup, hash và số bản ghi của 17 bảng nghiệp vụ khớp baseline; changed_tables rỗng. Không có tài khoản/đối tác mang mã thử còn lại. Mật khẩu ngẫu nhiên trong tệp tạm đã xóa trên Windows và WEB. Không tuyên bố toàn bộ bảng bảo mật không đổi: các lần đăng nhập, phiên, bộ đếm thất bại và audit có biến động bình thường do kiểm thử.

Nginx, AgroFlow, MySQL, WAF normalizer, Agent và Auditd active; health database connected; SecRuleEngine vẫn DetectionOnly. Không thay cấu hình/rule Wazuh Manager.

## Hồ sơ bằng chứng

- waf-business-evidence/api-results.json: kết quả HTTP ban đầu, không body/cookie/CSRF.
- waf-business-evidence/correlated-results.json: đối chiếu WAF và chính sách backend.
- waf-business-evidence/analysis-summary.json: số liệu tổng hợp.
- waf-business-evidence/filename-analysis.json: bốn phép thử tách nguyên nhân filename.
- waf-business-evidence/cleanup-verification.json: hash/count trước/sau 17 bảng.
- waf-business-evidence/initial-existing-account-attempt.json: một lần mật khẩu cũ bị từ chối; không chứa mật khẩu.

Nguyên tắc ngoại lệ theo đúng URI/target được tham khảo tại [OWASP CRS False Positives and Tuning](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/). Kết luận về hai rule và tham số ở trên dựa trên kiểm thử thực tế của hệ thống này.

---

<a id="ho-so-10"></a>
## 10. KIEM_THU_SURICATA_2026-11-05.md

# Kiểm thử Suricata — 05/11/2026

## Kết luận

Đạt phép thử phát hiện chữ ký DNS trên cả IT/em4 và SERVER/em5: 2 mẫu dương tạo đúng 2 alert SID 2062547, 2 mẫu âm có DNS event và không tạo alert trong cửa sổ thu log. Chưa nghiệm thu toàn bộ TC01–TC04, PH11 hoặc đường cảnh báo tới Wazuh. Không thay đổi rule/cấu hình, không bật chặn, không restart engine.

## Môi trường và bằng chứng

- pfSense 10.20.40.1, Suricata 7.0.8 RELEASE, hai tiến trình đang chạy IDS/AutoFP.
- IT PID 1765: /usr/local/etc/suricata/suricata_2224_em4/suricata.yaml; EVE /var/log/suricata/suricata_em42224/eve.json.
- SERVER PID 8815: /usr/local/etc/suricata/suricata_59865_em5/suricata.yaml; EVE /var/log/suricata/suricata_em559865/eve.json.
- Bằng chứng lưu tại suricata-evidence/: baseline.json, live-tests.json, it-new-eve.ndjson, server-new-eve.ndjson, postcheck.json, wazuh-check.json, syslog-runtime.txt, syslog-selectors.txt.
- baseline.json là dữ liệu chọn lọc, không phải backup cấu hình đầy đủ. Không lưu mật khẩu.

## Thiết kế thử

Kiểm tra rule SID 2062547 thực sự có trong suricata.rules của hai instance trước khi gửi. Gửi một DNS TXT query đối chứng và một query khớp chữ ký tới mỗi interface. Không cài malware, không thực thi exploit, không kết nối C2 thật. Tên mô phỏng nằm dưới .invalid và DNS recursion-desired tắt. Không tạo dữ liệu nghiệp vụ hay thay đổi tài khoản.

- Đối chứng: suricata-lab-control.invalid, transaction ID 27137.
- Mô phỏng: 100000000000000aa.com.suricata-lab.invalid, transaction ID 27138.
- Rule ET hiện có nhận diện mẫu tiền tố và đoạn com mà không neo cuối tên, nên tên .invalid này vẫn khớp. Cảnh báo chỉ là dữ liệu kiểm thử, không phải kết luận nhiễm Skitnet/Bossnet.
- Lấy byte offset EVE trước khi gửi và chỉ đọc phần mới sau thử; đối chiếu IP, cổng nguồn, qname, transaction ID và SID. Chờ 5 giây sau mẫu cuối trước khi thu.

## Kết quả thực tế (+07)

| Ca | Nguồn → đích | Thời gian EVE | Kết quả |
|---|---|---|---|
| IT âm | 10.20.40.254:63330 → 10.20.40.1:53 UDP | 23:29:50.388161 | Có DNS event, không alert |
| IT dương | 10.20.40.254:58124 → 10.20.40.1:53 UDP | 23:29:51.388790 | Có DNS event + alert 2062547, severity 1 |
| SERVER âm | 10.20.50.1:19545 → 10.20.50.10:53 UDP | 23:29:52.419538 | Có DNS event, không alert |
| SERVER dương | 10.20.50.1:38487 → 10.20.50.10:53 UDP | 23:29:53.448975 | Có DNS event + alert 2062547, severity 1 |

Hai alert có action allowed, phù hợp IDS chưa chặn. Hai sự kiện cũng xuất hiện trong alerts.log và system.log của pfSense. Việc có DNS event tại SERVER không chứng minh Ubuntu WEB có dịch vụ DNS; đây là gói mô phỏng gửi qua interface, không yêu cầu đích trả lời.

Giới hạn: ca SERVER phát từ chính pfSense ra em5; ca IT phát từ host tới gateway. Chưa phải một luồng phòng ban → WEB đi qua đồng thời hai instance. Chưa đo tỷ lệ mất gói hoặc chịu tải; bốn gói không đánh giá được khả năng phát hiện toàn bộ tấn công hoặc tỷ lệ cảnh báo giả tổng thể.

## Vấn đề phát hiện qua cấu hình/log

1. **IT lỗi nạp rule:** log khởi động 22:32 ghi 23.692 rule nạp thành công, 4 rule thất bại. Có lỗi JA3 chưa bật, parse SID 2058287 thất bại. Chưa xác định đầy đủ cả bốn rule, cần đối chiếu trước khi sửa. SERVER ghi 28.902 rule thành công, 0 thất bại.
2. **Flowbit:** cả hai có cảnh báo et.http.PK được kiểm tra nhưng không được set, liên quan SID 2019835 và một signature khác. Dù autoflowbits đang on, cần kiểm tra dependency thực tế; không coi mọi rule đều phát hiện đầy đủ.
3. **Phạm vi nội bộ:** HOME_NET gồm các subnet 10.20.10/20/30/40/50/60/70.0/24 và các địa chỉ tự sinh; EXTERNAL_NET = !$HOME_NET, HTTP_SERVERS = $HOME_NET. Các rule yêu cầu EXTERNAL_NET không khớp nguồn nội bộ thuộc HOME_NET. Đây là giới hạn quan trọng khi nghiệm thu di chuyển ngang/khai thác từ phòng ban; không thay EXTERNAL_NET toàn cục một cách máy móc.
4. **Offloading:** config.xml thiếu system/disablechecksumoffloading; có disablesegmentationoffloading và disablelargereceiveoffloading. GUI trước đó cảnh báo offloading. Tuy vậy ifconfig em4/em5 trong lượt này không liệt kê RXCSUM/TXCSUM/TSO/LRO hoạt động, và engine ghi không thấy checksum lỗi trong giai đoạn phát hiện ban đầu. Cần đối chiếu cấu hình lưu với runtime; không kết luận các lỗi TCP stream trước đây do offloading chỉ từ cảnh báo GUI. net.inet.tcp.tso=1 không tự chứng minh NIC đang bật TSO.
5. **Rule theo tài sản:** cả hai chọn cả nhóm sự kiện giao thức công nghiệp như DNP3/Modbus, chưa thấy tài sản tương ứng trong mô hình. Nên rà soát bộ rule sau khi đối chiếu tài sản; không tắt cả nhóm chỉ dựa tên. IT có emerging-netbios/web_client; SERVER có web_specific_apps.
6. **Tài nguyên tại thời điểm đọc:** hai engine RSS khoảng 435 MB và 484 MB, tổng gần 0,9 GB; ps báo 21,3% và 23,7% RAM. CPU tức thời thấp, filesystem 47 GB còn khoảng 41 GB. Đây là ảnh chụp tại thời điểm tải thấp, chưa đánh giá chịu tải. Cần cân nhắc RAM trước khi thêm instance.

## Đường log Wazuh

- pfSense đã cấu hình remote syslog 10.20.60.10:514, nguồn opt5/SOC = 10.20.60.1, định dạng RFC5424; có bật system và filter.
- /etc/syslog.conf include /var/etc/syslog.d; selector runtime gửi system notice lên remote. Hai alert mới có trong system.log mức PRI 141 (LOCAL1/NOTICE).
- Wazuh Manager thực sự có wazuh-remoted nghe UDP 514; remote syslog allowed-ips = 10.20.60.1.
- Không tìm thấy SID 2062547 hoặc qname mô phỏng trong tối đa 15.000 dòng cuối alerts.json và archives.json (nếu file tồn tại) lúc kiểm tra. Điều này chưa phân biệt mất gói, không lưu archive, decoder/rule không match, hoặc sự kiện nằm ngoài cửa sổ tìm; không kết luận Wazuh hoàn toàn không nhận syslog.
- EVE JSON hiện vẫn là file cục bộ; đường syslog trên chuyển thông báo dạng text, không đồng nghĩa gửi toàn bộ JSON/metadata EVE.

## Việc tiếp theo theo thứ tự

1. Khoanh vùng bốn rule IT lỗi, JA3 và flowbit; chọn bật parser/tính năng hoặc bỏ đúng signature không áp dụng, kiểm tra cấu hình trước reload.
2. Đối chiếu offloading lưu/runtime; xác định đúng chính sách mạng và bộ rule cho lưu lượng nội bộ.
3. Bắt gói syslog có lọc tại nguồn/Manager trong một lượt thử mới, kiểm tra decoder bằng log thật, rồi chứng minh alert Wazuh với SID/IP/thời gian trùng khớp. Chưa sửa cấu hình Manager trong lượt này.
4. Thử từ ITADMIN và máy phòng ban qua firewall tới WEB; bổ sung đường WAN và đường giữa phòng ban theo ma trận TC. Không suy từ phép thử DNS rằng TC01–TC04/PH11 đã đạt.
5. Sau hiệu chỉnh, kiểm thử hồi quy nghiệp vụ/âm tính, thu sức khỏe engine và mới xem xét chặn có chọn lọc.

Script tái sử dụng: suricata-lab-check.py, test-suricata-live.py, suricata-postcheck.py, check-suricata-wazuh.py. Nhận mật khẩu từ biến môi trường tạm; không hardcode hoặc ghi vào bằng chứng. Lượt chạy lại phải lưu tên đợt riêng vì hiện script ghi đè các tệp bằng chứng cùng tên.

---

<a id="ho-so-11"></a>
## 11. KIEM_TRA_SURICATA_PFSENSE_2026-11-05.md

# Kiểm tra Suricata trên pfSense — 05/11/2026

## Phạm vi và cách kiểm tra

Đọc giao diện pfSense đã đăng nhập; thử kết nối SSH và kiểm tra khả năng truy cập từ máy Windows host. Không Save/Apply cấu hình, không cập nhật chữ ký, không bật chặn hay sửa firewall. Đây là kiểm tra hiện trạng và log sẵn có, chưa phải một lượt kiểm thử tấn công đầu cuối mới.

## Địa chỉ đã xác minh

| Thành phần | Địa chỉ / vai trò |
|---|---|
| pfSense GUI | https://10.20.40.1 — truy cập HTTPS được |
| Windows host VMnet4 | 10.20.40.254/24 |
| Windows host VMnet5 | 10.20.50.254/24 |
| Ubuntu WEB | 10.20.50.10 — SSH cổng 22 truy cập được |
| ITADMIN trong cảnh báo | 10.20.40.10 |
| Wazuh Manager theo hồ sơ trước | 10.20.60.10; chưa xác minh nhận log Suricata trong lượt này |

Windows có route 10.20.60.0/24 qua 10.20.40.1. Kết nối pfSense 10.20.40.1:22 timeout trước xác thực; chưa thể đánh giá thông tin đăng nhập. 10.20.50.1:22 và :443 cũng chưa truy cập được từ host trong lượt thử. Không lưu mật khẩu vào hồ sơ.

## Kết quả đã đọc trực tiếp

| Nội dung | IT | SERVER |
|---|---|---|
| Interface | em4 | em5 |
| Mô tả | IDS_IT | IDS_SERVER |
| Trạng thái tại trang Interfaces | Running | Running |
| Pattern Match | AUTO | AUTO |
| Blocking Mode | DISABLED | DISABLED |
| Send Alerts to System Log | Bật | Bật |
| Syslog facility / priority | LOCAL1 / NOTICE | LOCAL1 / NOTICE |
| EVE JSON | Bật, output FILE | Bật, output FILE |

Trang Interfaces chỉ có hai instance trên; chưa thấy instance WAN hay các phòng ban khác. Không suy ra rằng mọi đường truyền đều đã được giám sát.

Trên IT đã đọc thêm: Block Offenders tắt, Run Mode AutoFP; EVE Alerts bật; không ghi payload/packet dump của alert. Có bật metadata HTTP và application layer. SERVER có HTTP log và extended HTTP log; các lựa chọn EVE sâu hơn chưa đối chiếu đầy đủ.

Cả hai trang Settings đều hiện cảnh báo yêu cầu tắt hardware checksum offloading, TCP segmentation offloading và LRO: ít nhất một mục chưa tắt. Chưa đọc riêng ba giá trị tại trang Networking nên chưa kết luận mục nào gây cảnh báo. Cần kiểm tra trước khi thay đổi.

## Chữ ký

Trang Updates ghi:

- Emerging Threats Open Rules: MD5 `9c3dbc70fc8f59c9e34bae35f919ab4c`.
- Signature date: Thursday, 05-Nov-26 15:38:56 +07.
- Last Update: Nov-05 2026 15:38; Result: success.
- Snort Subscriber, Snort GPLv2 Community, Feodo Tracker và ABUSE.ch SSL Blacklist: Not Enabled.

Trang Categories SERVER có danh sách Default Rules và ET Open. Chưa xác minh đầy đủ trạng thái chọn từng checkbox, số rule thực tế được nạp hoặc các lỗi khởi động; không coi danh sách hiển thị là bằng chứng mọi category đã bật.

## Bằng chứng cảnh báo sẵn có trên SERVER

Thời gian dưới đây là thời gian GUI hiển thị, chưa đối chiếu đồng bộ giờ giữa các máy.

| Thời điểm GUI | GID:SID | Nội dung | Nguồn → đích | Action / priority |
|---|---|---|---|---|
| 11/05/2026 20:45:30, 20:49:08, 20:56:00 | 1:1000002 | LAB ITADMIN HTTPS to WEB01 | 10.20.40.10 → 10.20.50.10:443 | ALERT / 3 |
| 11/05/2026 22:35:06–22:35:08, năm dòng hiển thị | 1:2210016 | SURICATA STREAM CLOSEWAIT FIN out of window | 10.20.50.10:443 → 10.20.50.254, cổng đích tạm thời | ALERT / 3 |

Điều này chứng minh SERVER có quan sát và sinh cảnh báo cho lưu lượng được ghi nhận. Rule LAB là bằng chứng đường quan sát, không chứng minh phát hiện khai thác HTTPS. Cảnh báo TCP stream chưa phải bằng chứng tấn công; cần đối chiếu phiên TCP, offloading và hoạt động hợp lệ trước khi hiệu chỉnh.

## Chưa xác minh và việc tiếp theo

1. Xác minh cổng SSH thực tế, địa chỉ listen và policy cho nguồn host 10.20.40.254; không tự mở rộng firewall chỉ để truy cập.
2. Đọc chính xác ba tùy chọn offloading, HOME_NET/EXTERNAL_NET, rule đang nạp và suricata.log của từng instance.
3. Xác minh đường dẫn EVE thật và cơ chế chuyển log. EVE output FILE chỉ chứng minh lựa chọn ghi file; Send Alerts to System Log chỉ chứng minh bật ghi system log. Chưa chứng minh remote syslog hay Wazuh nhận được dữ liệu.
4. Đối chiếu một sự kiện mới từ pfSense tới Wazuh theo thời gian, IP, SID; kiểm tra định dạng JSON/syslog và decoder thực tế trước khi tổng hợp rule.
5. Chạy kiểm thử lành tính có kiểm soát cho cả IT và SERVER, rồi mới kiểm thử chữ ký tấn công phù hợp. Chưa bật chặn.

## Đường dẫn GUI để dùng lại

- Interfaces: https://10.20.40.1/suricata/suricata_interfaces.php
- IT Settings: https://10.20.40.1/suricata/suricata_interfaces_edit.php?id=0
- SERVER Settings: https://10.20.40.1/suricata/suricata_interfaces_edit.php?id=1
- SERVER Categories: https://10.20.40.1/suricata/suricata_rulesets.php?id=1
- SERVER Alerts: https://10.20.40.1/suricata/suricata_alerts.php?instance=1
- Updates: https://10.20.40.1/suricata/suricata_download_updates.php

Người dùng hiện đảm nhiệm cả hai phần công việc; các bộ rule WEB/WAF trước đây mới được chuẩn bị bàn giao, không suy ra chúng đã được áp dụng lên Manager. WAF vẫn DetectionOnly và còn hai nhóm cảnh báo giả được ghi trong VIEC_CAN_LAM_TIEP.md.

---

<a id="ho-so-12"></a>
## 12. MA_TRAN_KIEM_SOAT_GIAM_SAT.md

# Ma trận kiểm soát giám sát AgroFlow

## Vùng giám sát và trách nhiệm

| Vùng | Điểm kiểm soát | Nguồn xem trong Wazuh | Bằng chứng và phần còn thiếu |
| --- | --- | --- | --- |
| Giữa các mạng phòng ban | pfSense áp chính sách trên interface nguồn | Firewall filterlog, đối chiếu tracker, IP và cổng | Đã sửa alias SALES thiếu subnet DIRECTOR. Chờ kiểm thử trực tiếp SMB/RDP hai chiều và đối chiếu đến Wazuh. |
| Mạng quản trị và mạng máy chủ | Suricata IDS tại IT/em4 và SERVER/em5 | Nhóm suricata, SID, interface, IP và cổng | Đã xác minh cảnh báo chữ ký và ca Inline IPS tạm thời 111104. Kiểm tra gần nhất cho thấy cả hai đang IDS. Phạm vi WAN và IPS thường trực chưa nghiệm thu. |
| Website HTTPS | Nginx và ModSecurity/CRS trên WEB | agroflow_waf_blocked, rule 111054, transaction_id và rule_ids | Đã bật chặn và xác minh tám ca. Dashboard chưa hiển thị trực tiếp loại phát hiện theo mã CRS. |
| Ứng dụng và MySQL | Backend thực thi phân quyền. MySQL thực thi quyền tài khoản DB | Các nhóm AgroFlow, 50106 và 111026 | Đã xác minh phiên, đổi quyền, tải liên tiếp, xác thực MySQL và lỗi quyền. 111006 chưa có ca lỗi toàn vẹn hoặc thiếu tệp. |
| Ubuntu WEB | Wazuh FIM và Auditd | 550/553/554 và 111025 | Đã thử thay đổi tệp trong vùng thử và shell dưới UID dịch vụ. 111040 còn là bản nháp. |
| Năm máy Windows | Windows Security, System và Defender | 111200–111205, 111210–111214 | Sáu rule Windows và 111210 có bằng chứng trên cả năm máy. 111211 có bằng chứng trên bốn máy. 111212–111214 chưa có ca riêng. |
| Sao lưu | Timer và tiến trình backup trên WEB | 111021–111024 | Đã thử thành công, lỗi, quá hạn và phục hồi. 111024 chưa thử lỗi khởi động lại ứng dụng. |
| Sức khỏe giám sát | Wazuh Manager và các agent | 111220–111221 | 111221 đã xác minh. 111220 đã thử nhưng chưa đạt và đang tạm gác. Mất một nguồn log và mất Manager cần ca riêng. |

## Cách rà chất lượng từng rule

| Mục rà | Bằng chứng cần lưu |
| --- | --- |
| Phạm vi | Máy, interface hoặc kênh log, hành vi và điều kiện khớp cụ thể. |
| Ca dương | Log tại nguồn và ID cảnh báo mong đợi trong index. Đối chiếu bằng Record ID, transaction ID hoặc SID cùng thời điểm và luồng. |
| Ca âm | Hành vi hợp lệ gần giống ca dương. Kiểm tra không phát nhầm cảnh báo mục tiêu và có bằng chứng nguồn vẫn hoạt động. |
| Hiển thị | Mở được bản ghi qua Discover. Nếu dashboard chuyên đề là yêu cầu, xác nhận bộ lọc và trường hiển thị tại đó. |
| Trạng thái | Phân loại riêng bản nháp, đã nạp, đã xác minh ca dương, đã nghiệm thu ca dương và âm, hoặc tạm gác. Rule nền level 0 dùng ca đối chứng để xác nhận cách phân loại. |

Danh mục ID chi tiết ở BO_RULE_WAZUH.md. Bảng này tổng hợp từ hồ sơ đã lưu, không thay cho kiểm tra cấu hình runtime của từng nguồn.

---

<a id="ho-so-13"></a>
## 13. NGHIEM_THU_BUOC_2_2026-11-07.md

# Nghiệm thu bước 2 trên Ubuntu WEB

| Hạng mục | Kết quả |
| --- | --- |
| Phiên đăng nhập | 7/7 request đúng kỳ vọng. Hai ca HTTP 401 khớp rule 111017 với lý do `expired` và `invalid_or_revoked`. Cookie và token không được đưa vào payload audit. Phiên đã xóa và token không xác định dùng chung lý do. |
| FIM/Auditd | Tạo, sửa, đổi mode và xóa tệp thử. Wazuh có FIM 554/550/553 kèm who-data và Auditd 80781/80790/80791. Dùng tệp riêng trong thư mục thử đã cấu hình. |
| MySQL | Tài khoản ứng dụng đọc được bảng nghiệp vụ. Hai truy vấn thử vào `mysql.user` và `performance_schema.accounts` bị từ chối. Một lần xác thực giả bị MySQL trả 1045 và Wazuh Manager ghi 50106 từ error log. |
| Backup và quá hạn | Lịch backup và kiểm tra quá hạn đang hoạt động. Ca lỗi thư mục staging cách ly sinh 111022. Ca trạng thái giả lập cũ 27 giờ sinh 111023. Đối chứng trạng thái mới không sinh cảnh báo quá hạn. |
| Phục hồi | Restic phục hồi snapshot từ Google Drive. Ba tệp khớp checksum, 22 bảng khớp số dòng và 66 phiên bản tài liệu khớp SHA-256 cùng kích thước. Schema MySQL tạm đã được xóa. |

MySQL duy trì `log_error_verbosity=3` bằng `SET PERSIST`, giữ `general_log=OFF`. Bộ thu mỗi phút lấy chênh lệch bộ đếm lỗi quyền từ Performance Schema cho tài khoản `agroflow_app`. Ca thử lỗi 1142 có `count_delta=1` và khớp 111026 trong index. Đây là tổng hợp theo tài khoản, máy nguồn và mã lỗi, không lưu câu SQL. Tài khoản ứng dụng còn quyền DML trên hai schema AgroFlow. Chưa có kết luận schema cũ có thể thu hồi quyền.

Lượt backup mới khớp 111021 ở cả ba giai đoạn bắt đầu, hoàn thành bản cục bộ và hoàn thành snapshot Google Drive. Bản phục hồi từ snapshot mới đã khởi động website trên loopback với tài khoản và schema tạm, dùng thư viện đã cài trên WEB. Trang chủ trả 200 và khớp bản HTML phục hồi. API health xác nhận kết nối database. Đây là smoke test tại máy hiện có.

Rule 111014 đã khớp request thứ 51 từ IP loopback thử, HTTP 429. Auditd theo dõi thực thi Bash/Dash 64-bit dưới UID dịch vụ AgroFlow. Ca chạy Dash vô hại bằng tài khoản dịch vụ khớp 111025, thể hiện khả năng phát hiện shell trong phạm vi cấu hình. Tệp rule Auditd là `/etc/audit/rules.d/72-agroflow-web-shell.rules`.

Bằng chứng tại `waf-acceptance-evidence/web-step2/` và `waf-acceptance-evidence/web-session/`.

---

<a id="ho-so-14"></a>
## 14. NGHIEM_THU_SURICATA_PHAN_DOAN_2026-11-06.md

# Nghiệm thu Suricata và phân đoạn mạng ngày 06/11/2026

## Luồng và bằng chứng

| Luồng | Interface | Kết quả |
| --- | --- | --- |
| SALES `10.20.10.10` → WEB `10.20.50.10` | SALES/em1 → SERVER/em5 | Có HTTP 200 thực tế trong access log Nginx và bằng chứng thử IDS/IPS trước đó trên em5. |
| DIRECTOR `10.20.70.10` → WEB | DIRECTOR/em7 → SERVER/em5 | Đã xác nhận tuyến và rule 80/443 đang nạp. Chưa có request đối chứng từ DIRECTOR trong lượt này. |
| SALES và DIRECTOR → Internet | SALES/em1 hoặc DIRECTOR/em7 → WAN/em0 | Bảng trạng thái pfSense có kết nối HTTPS hai chiều và bản ánh xạ NAT từ cả hai máy sang WAN `192.168.50.167`. |
| SALES ↔ DIRECTOR | Chặn tại interface vào em1 hoặc em7 | Hai chiều đã đối chiếu rule và alias hoạt động. Chưa có gói thử phát trực tiếp giữa hai máy sau khi sửa. |

Đã thêm `10.20.70.0/24` vào alias `SALES_OTHER_NETWORKS`. Trước đó subnet DIRECTOR nằm ngoài alias, nên HTTP/HTTPS có thể khớp rule đi Internet ở phía dưới. Chiều DIRECTOR → SALES đã thuộc `INTERNAL_NETWORKS`. Rule chặn tương ứng là 1791109414 và 1791888698. Đã sao lưu cấu hình tại `/conf/backup/agroflow-director-segmentation-before.xml`. Lần nạp qua PHP thiếu hàm phụ thuộc. Đã nạp lại bằng `/etc/rc.filter_configure_sync` và xác minh subnet trong bảng pf đang hoạt động.

## Ca chặn mới tới Wazuh

- 09:31:34 +07, `SERVER/em5`, SID `9901104`, TCP `10.20.50.254:54515 → 10.20.50.1:49381`.
- EVE ghi `alert.action=blocked` và `drop.reason=rules`. Syslog thật ghi `[Drop]`. Index Wazuh có hai bản ghi khớp hai SYN của cùng một kết nối, rule `111104`, nhóm `suricata_blocked`.
- Nguồn là máy quản trị trên mạng SERVER. Cổng đối chứng cũng timeout nên kết luận chặn dựa vào EVE và syslog, không dựa vào kết quả socket.
- Phiên Netmap chạy một rule thử và tự khôi phục IDS. Trạng thái sau thử là IDS trên IT/em4 và SERVER/em5. SERVER/em5 là điểm ưu tiên cho Inline IPS với bộ chữ ký chọn lọc. WAN/em0 là điểm quan sát tập trung cho Internet; em1/em7 là điểm xem trước NAT hoặc trước quyết định phân đoạn. Chưa kích hoạt thêm instance trên các interface đó.

Bằng chứng tại `suricata-evidence/director-segmentation-current.json`, `director-alias-applied.json`, `director-web-existing-access.json` và `inline-fresh-closeout.json`.

---

<a id="ho-so-15"></a>
## 15. NGHIEM_THU_WAF_2026-11-06.md

# Nghiệm thu WAF AgroFlow ngày 06/11/2026

WAF trên Ubuntu WEB `10.20.50.10` đang chạy `SecRuleEngine On` với OWASP CRS PL1 và ngưỡng anomaly hiện có. Manager Wazuh tại `10.20.60.10` đã nạp bộ rule WAF và bộ rule ứng dụng 111000–111009. Kiểm thử HTTPS thực hiện trong lab bằng dữ liệu và tài khoản tạm. Dọn dữ liệu sau kiểm thử và đối chiếu 17 bảng nghiệp vụ, không phát hiện thay đổi so với dữ liệu nền.

## Kết quả

| Phạm vi | Bằng chứng thực tế |
| --- | --- |
| Chế độ phát hiện sau hiệu chỉnh | 115/115 request đúng kỳ vọng, 115/115 giao dịch đối chiếu Nginx. |
| Chế độ chặn | 10/10 probe đúng kỳ vọng. Tám ca trả 403 tại WAF và không đến backend: SQLi, XSS query, traversal, mẫu RCE, user agent scanner, PATCH ngoài API cho phép, XSS JSON và tên file upload độc hại. Health trả 200. Host dạng IP kích hoạt 920350, dưới ngưỡng chặn và nhận 401 từ backend. |
| Nghiệp vụ khi chặn | 124/124 request đúng kỳ vọng trên 5 vai trò. 123/123 request có ID backend đối chiếu với Nginx. Upload PDF giả trả 400 ở backend; tệp 12 MiB trả 413 tại lớp web. Suite bao gồm phân quyền, upload/download có kiểm SHA-256, PATCH và CSRF. |
| Log WAF vào index | 9/9 audit của probe, 8/8 mẫu access Nginx trong phạm vi probe, 18/18 audit của đợt bổ sung. Tám sự kiện chặn thuộc rule 111054. |
| Log backend vào index | CSRF 111005, upload PDF giả 111009, lần login sai thứ 5 cùng IP 111007, lần từ chối quyền thứ 3 cùng actor 111008. |

Hiệu chỉnh gồm mở PATCH theo đường dẫn cho phép và ngoại lệ hẹp rule 920120 chỉ trên tên tệp đính kèm thuộc các API multipart chỉ định. Bản sao cấu hình trước khi sửa ở `/var/lib/agroflow-monitoring/waf-acceptance-20261106/` trên WEB. Lần reload đầu bị đo sớm khi worker cũ còn xử lý request và đã tự hoàn tác. Lần thử lại chờ worker mới thay thế hoàn toàn trước khi gửi probe.

Wazuh index các sự kiện audit đã lọc và các cảnh báo theo rule. Log HTTP thông thường vẫn được lưu tại nguồn, với rule mức 0 cho access thông thường. Xem ca WAF chặn bằng bộ lọc `rule.groups:agroflow_waf_blocked`.

## Đối chiếu phạm vi đồ án

- BV03, BV04, BV05 và GS03–GS04 có bằng chứng trong các ca đã chạy. BV04 còn cần kiểm thử hết hạn hoặc thu hồi phiên riêng. GS01 và CB01 đã chứng minh chuỗi thất bại theo IP, còn ca đăng nhập thành công sau chuỗi thất bại và tương quan riêng theo tài khoản.
- CB02 đã chứng minh bằng ba lần từ chối cùng actor. GS02/CB03, GS05, GS06–GS10 và CB05–CB06 cần bằng chứng riêng cho thay đổi tài khoản/quyền, tải hàng loạt, FIM/Auditd, tiến trình/persistence, Defender và mất agent.
- BV01–BV02, CB04 và BV06 cần hồ sơ nghiệm thu mạng và MySQL riêng. Phục hồi backup, kiểm thử từ trình duyệt máy phòng ban và tương quan WAF → máy WEB → kết nối ra ngoài cần ca đầu cuối riêng.

Bằng chứng máy đọc nằm trong `waf-acceptance-evidence/`, gồm `enforcement-probes.json`, `wazuh-index-verification.json` và thư mục `extended/`.

---

<a id="ho-so-16"></a>
## 16. PLAYBOOK_ALERTS_AGROFLOW.md

# Tiếp nhận cảnh báo ưu tiên AgroFlow

Trong Alerting → Alerts, chọn All alerts để xem cả Active, Acknowledged và Completed. Ghi tên trigger, thời điểm, tài sản, người tiếp nhận và kết quả điều tra. Acknowledge ghi nhận tiếp nhận. Completed phản ánh điều kiện monitor đã hết hiệu lực trong cửa sổ, có thể xảy ra trước khi điều tra xong.

| Nhóm | Bằng chứng cần xem trong Discover | Hướng xử lý |
| --- | --- | --- |
| WAF BLOCK | Rule 111054, loại phát hiện, IP, endpoint và transaction_id. Tìm bản phân loại cùng mã và đối chiếu Nginx. | Xác định request dừng trước backend. Nếu nghi chặn nhầm, tái hiện nghiệp vụ rồi kiểm thử lại ca hợp lệ và ca tấn công sau khi hiệu chỉnh. |
| Suricata | SID, tên chữ ký, IP/cổng, interface và EVE. | Với Inline Drop, xác nhận EVE ghi blocked/drop. Với phát hiện IDS, đối chiếu hoạt động của máy nguồn và các luồng liên quan. |
| Đăng nhập thất bại liên tiếp | 111007 và chuỗi 111003 theo IP. | Kiểm tra tài khoản đích, lý do thất bại, đăng nhập thành công và khóa tài khoản quanh thời điểm đó. |
| pfSense chặn lặp lại | 111110 tương quan các lần chặn 100100 cùng IP nguồn trong 45 giây. Đã xác minh qua WAN ảo. | Đối chiếu interface, IP, cổng đích và tracker trong filterlog để phân biệt dò quét và lưu lượng hợp lệ bị chặn. |
| Tải nhiều hồ sơ | 111016 áp dụng cho mọi bộ phận và kích hoạt ở hồ sơ thứ năm khác nhau tải thành công trong 120 giây theo actor_id. | Xem document_ids, vai trò, IP và yêu cầu bàn giao. Khi demo, dùng tài khoản Kho hoặc Kinh doanh có quyền tải năm hồ sơ thử. |
| Quyền và khóa tài khoản AgroFlow | 111008, 111011, 111013. Đối chiếu actor, đối tượng, IP và lý do. | Xác minh thay đổi đã duyệt và ghép các mục nếu cùng một đợt xác thực. |
| Windows | 111201, 111203–111205, máy, tài khoản và Record ID. | Kiểm tra phiên quản trị, thành viên được cấp quyền, chương trình của task/service và lịch triển khai. |
| Defender | 111210 và hành động 111211 theo máy và thời điểm. | Xác nhận Defender đã xử lý hay sự kiện cần kiểm tra thêm. |
| Shell trên WEB | 111025, dữ liệu Auditd, tiến trình cha, FIM và lưu lượng liên quan. | Đối chiếu lịch triển khai. Khoanh vùng máy và tài khoản nếu hành vi ngoài nghiệp vụ. |
| Thay đổi tệp quan trọng trên WEB | FIM 550/553/554, lọc agent Ubuntu WEB và đường dẫn mã nguồn, cấu hình hệ thống hoặc backup trong monitor. | Xem đường dẫn, loại thay đổi và dữ liệu who-data nếu có. Đối chiếu tài khoản thực hiện với lịch triển khai. |
| Quyền MySQL | 111026, tài khoản DB, máy nguồn, mã lỗi và số lỗi mới. | Đối chiếu tác vụ đang chạy và quyền hiện có. Tra audit ứng dụng nếu cần xác định request liên quan. |
| Backup | 111022 hoặc 111023, backup_id, phase và last-success. | Kiểm tra dung lượng, quyền, kết nối đích và chạy lại theo quy trình nếu cần. |
| Mất heartbeat access log WEB | Monitor kiểm tra tín hiệu 111067 mỗi phút và kích hoạt khi không thấy tín hiệu trong 4 phút. | Kiểm tra timer `agroflow-web-log-heartbeat.timer`, access log Nginx, agent WEB01 và quá trình lập chỉ mục. Theo dõi alert chuyển sang Completed sau khi tín hiệu trở lại. |
| Mất heartbeat log mạng | WEB gửi một gói nội bộ mỗi phút. pfSense ghi chặn theo tracker 1791214149 thành rule 111114. Suricata SERVER ghi chữ ký SID 2062547 cho đúng bộ IP/cổng của heartbeat thành rule 111107. Hai monitor kiểm tra riêng cửa sổ 4 phút. | Nếu cả hai mất, kiểm tra timer `agroflow-network-log-heartbeat.timer`, tuyến từ WEB và đường syslog chung. Nếu mất một tín hiệu, kiểm tra nguồn tương ứng. Tín hiệu Suricata xác minh interface SERVER. |
| Mất kết nối cổng agent Wazuh | Bộ kiểm tra độc lập trên Ubuntu WEB thử TCP 1514 mỗi phút và ghi thay đổi trạng thái trong journal cục bộ. | Trên Ubuntu WEB, chạy `journalctl -u agroflow-wazuh-reachability.service`. Kiểm tra tuyến mạng, firewall và tiến trình tiếp nhận của Manager. |

Ghi kết luận theo một trong các trạng thái: dấu hiệu tấn công đã bị chặn, hoạt động hợp lệ, cảnh báo giả cần hiệu chỉnh, hoặc cần điều tra tiếp. Khi thống kê WAF, đếm bản ghi 111054 theo transaction_id. Số alert OpenSearch theo monitor biểu thị số đợt kích hoạt, vì monitor truy vấn có thể gom các bản ghi cùng loại trong cửa sổ.

---

<a id="ho-so-17"></a>
## 17. SSH_PFSENSE_2026-11-05.md

# SSH pfSense — 05/11/2026

## Đã hoàn thành

- Người dùng xác nhận bật SSH cổng 22 và cho phép máy quản trị 10.20.40.254 truy cập 10.20.40.1:22.
- Bật Enable Secure Shell tại System > Advanced > Admin Access, giữ chế độ Password or Public Key và cổng mặc định 22. Không đổi mật khẩu.
- Thêm rule đầu danh sách IT/em4: Pass IPv4 TCP, nguồn một địa chỉ 10.20.40.254, source port any, đích một địa chỉ 10.20.40.1, destination port 22; bật log. Mô tả: Allow Admin Host SSH to pfSense.
- GUI báo áp dụng thành công; rule runtime xác minh qua pfctl có tracker/ridentifier 1793895278.
- Đăng nhập thành công bằng Paramiko, đối chiếu host key OpenSSH đã ghi nhận. Kết quả hostname pfSense.home.arpa; admin ánh xạ uid=0(root), nhóm wheel; uname -r: 14.0-CURRENT.
- sockstat xác nhận sshd lắng nghe IPv4/IPv6 trên cổng 22. Không lưu mật khẩu trong hồ sơ hoặc script.

## Giới hạn truy cập cần biết

Rule mới chỉ cho nguồn được duyệt trên IT. Tuy nhiên runtime còn rule tự động có sẵn:

`pass in quick on em1 proto tcp from any to (em1) port = ssh ... label "anti-lockout rule"`

em1 là SALES theo giao diện rule. Do đó chưa thể khẳng định SSH trên toàn firewall chỉ cho máy quản trị 10.20.40.254. Chưa thử đăng nhập từ SALES; rule thể hiện quyền cho phép nhưng kết nối thực tế còn phụ thuộc đường mạng và xác thực. Chưa tắt anti-lockout hoặc thay đổi chính sách SALES vì cần chuẩn bị đường quản trị thay thế trước để tránh khóa truy cập.

## Dùng lại

- Endpoint: 10.20.40.1:22.
- Username: admin; mật khẩu do người dùng cung cấp, không ghi ở đây.
- Nguồn được rule IT mới cho phép: 10.20.40.254.
- Hai lần OpenSSH qua terminal tương tác đã đóng phiên sau lúc nhập mật khẩu, không kết luận sai mật khẩu. Paramiko xác thực và chạy lệnh chỉ đọc thành công.
- Công cụ cục bộ: Python runtime Codex; Paramiko tại .local-tools/ssh trong workspace. Thư viện được cài từ PyPI để tránh phụ thuộc nhập mật khẩu qua terminal tương tác Windows; không cài gói lên pfSense.
- Cấu hình Suricata chưa được thay đổi trong tác vụ này.

## Bước kế tiếp

Đọc cấu hình Suricata qua SSH để đối chiếu offloading, HOME_NET, rule đang nạp, log EVE và đường chuyển log Wazuh. Hồ sơ hiện trạng trước: KIEM_TRA_SURICATA_PFSENSE_2026-11-05.md. Trạng thái SSH timeout trong hồ sơ trước đã được thay thế bởi kết quả xác thực thành công ở tài liệu này.

---

<a id="ho-so-18"></a>
## 18. suricata-evidence/SALES-IPS-2026-11-06.md

# Kiểm thử SALES → WEB ngày 06/11/2026

Máy SALES 10.20.10.10 trên em1 truy cập WEB 10.20.50.10 qua pfSense. Instance SERVER trên em5 quan sát được luồng này.

| Ca | Kết quả |
|---|---|
| HTTP hợp lệ | 301 |
| HTTPS hợp lệ | 200 |
| Mẫu có header kiểm thử khi chạy IDS | 301. EVE allowed và Wazuh 111103, SID 9901101, cổng nguồn 50014 |
| HTTP hợp lệ trong phiên IPS | 301 |
| HTTPS hợp lệ trong phiên IPS | 200 |
| Cùng mẫu trong phiên IPS | Timeout, HTTP 000. EVE blocked và drop.reason=rules, SID 9901101, cổng nguồn 50473, 07:45:01 +07 |

Phiên IPS Netmap tạm thời chỉ nạp một chữ ký thử trên SERVER. Bộ giám sát đã khôi phục SERVER về IDS sau khi kết thúc thử. Bằng chứng EVE và trạng thái tiến trình nằm trong sales-ips-pilot.txt.

Syslog của lần chặn thật có tiền tố [Drop], bị decoder cũ bỏ qua. Đã bổ sung decoder và rule 111104–111106, xác minh logtest với mẫu chặn thật rồi nạp lại Wazuh. Một dòng phát lại có nhãn REPLAY đi từ pfSense tới Wazuh đã khớp rule 111104 và nhóm suricata_blocked. Bản ghi phát lại nằm trong sales-drop-replay-wazuh.ndjson. Phép thử trực tiếp mới sau khi cập nhật decoder còn chờ xác minh.

SERVER bao phủ SALES → WEB. Luồng giữa các phòng ban khác, lưu lượng Internet của phòng ban và lưu lượng cùng VLAN cần đánh giá riêng theo đường đi. Firewall có rule chặn SALES đi ngang. Cần bật FINANCE để thử đường SALES → FINANCE và đối chiếu firewall log trước khi chọn bổ sung interface. WAF tiếp tục phụ trách kiểm tra nội dung HTTP tại nơi kết thúc TLS.

---

<a id="ho-so-19"></a>
## 19. TICH_HOP_SURICATA_WAZUH_2026-11-05.md

# Hiệu chỉnh IT và xác minh Suricata → Wazuh — 05/11/2026

## Kết quả cuối cùng

- IT đã bật JA3, chạy PID 31498, log khởi động 23:47:27 ghi 23.696 rule nạp thành công, 0 rule thất bại; Engine started 23:47:44 +07.
- SERVER giữ nguyên cấu hình/PID 8815, không restart trong đợt này.
- Hai mẫu DNS mô phỏng mới đều được Suricata phát hiện và Wazuh Manager sinh alert rule 111101, level 12. IP/cổng/SID trùng khớp giữa EVE và alert Wazuh.
- Hai mẫu DNS âm có DNS event tại pfSense nhưng không alert Suricata trong cửa sổ kiểm thử. Không bật logall/archives để lưu toàn bộ log trên Manager.
- Wazuh Manager active; WEB01 ID007 Active sau restart. Chưa xác minh bản ghi trong index/Dashboard; kết quả xác nhận tới alerts.json của Manager.
- Suricata vẫn IDS, không bật block offenders. WAF vẫn DetectionOnly.

## Nguyên nhân và thay đổi đã áp dụng

### Suricata IT

Runtime YAML có `ja3-fingerprints: off`, trong khi rule được chọn yêu cầu JA3. Chỉ bật JA3 trong bản cấu hình tạm đã làm số rule nạp tăng từ 23.692 lên 23.696 và số thất bại giảm từ 4 về 0. Sau đó lưu `tls_ja3_fingerprint=on` bằng API cấu hình package pfSense, sinh lại YAML bằng suricata_generate_yaml. Diff YAML chỉ đổi dòng JA3 từ off thành on; kiểm tra `suricata -T --init-errors-fatal` thành công trước kích hoạt.

Backup giữ trên chính firewall, quyền hạn chế, không tải config.xml chứa dữ liệu nhạy cảm về workspace:

- /root/agroflow-suricata-backup-20261105/config-before-ja3.xml (0600)
- /root/agroflow-suricata-backup-20261105/it-before-ja3.yaml (0600)
- /root/agroflow-suricata-backup-20261105/it-engine-before-restart.log (0600)

Lần stop/start đầu gặp race: hàm package đợi 3 giây nhưng tiến trình chưa dọn pidfile xong, nên lần start bị từ chối. Kiểm tra sau đó xác nhận tiến trình cũ đã thoát, pidfile đã tự dọn; gọi start riêng IT lần nữa và chờ Engine started. Không xóa pidfile thủ công, không kill toàn bộ Suricata. Có gián đoạn giám sát IT từ khoảng 23:46:04 đến 23:47:44; SERVER không bị dừng. Các bằng chứng lỗi/start/recovery được giữ, không coi lần start đầu là thành công.

### Wazuh Manager

Bắt gói tại Manager xác nhận syslog từ 10.20.60.1:514 tới 10.20.60.10:514. Logtest trên thông báo RFC5424 thật ban đầu báo No decoder matched. Đây là nguyên nhân trực tiếp cảnh báo không được nhận dạng; không phải bằng chứng mất kết nối UDP.

Đã thêm đúng hai file riêng, không sửa local_rules.xml, local_decoder.xml hay rule hệ thống:

- /var/ossec/etc/decoders/agroflow_pfsense_suricata.xml
- /var/ossec/etc/rules/agroflow_pfsense_suricata.xml

Quyền root:wazuh 0640. Bản tương ứng tại workspace: pfsense-suricata-decoders.xml và pfsense-suricata-rules.xml. Các đường dẫn đích chưa tồn tại trước khi triển khai; cập nhật hiệu chỉnh chỉ tác động hai file riêng vừa tạo. Đã đối chiếu không trùng ID với các file rule khác.

Decoder dành cho syslog Suricata RFC5424, trích gid/SID/rev/signature/category/priority/protocol/srcip/srcport/dstip/dstport. Nhận được full_log thực tế sau remoted đã bỏ PRI, vẫn giải mã đúng. Không thay định dạng syslog toàn firewall. Đây là đường alert text, chưa chuyển toàn bộ EVE JSON; metadata DNS/TLS và in_iface không tự có trong alert syslog.

| ID Wazuh | Level | Mục đích |
|---|---|---|
| 111100 | 3 | Thông báo Suricata giải mã đầy đủ, fallback |
| 111101 | 12 | Priority 1 |
| 111102 | 8 | Priority 2 |
| 111103 | 5 | Priority 3 |
| 111109 | 3 | Signature bắt đầu LAB, phân loại test kết nối |

Các level là chính sách ban đầu của mô hình, cần hiệu chỉnh theo kết quả nghiệp vụ; không suy ra mọi priority 1 đều là sự cố thật. Hai cảnh báo DNS mô phỏng mang tên ET MALWARE là dữ liệu test có chủ đích, không chứng minh nhiễm malware. Không gán thêm MITRE tự động cho mọi alert.

Đã kiểm tra analysisd -t thành công. Sáu ca logtest kiểm tra ưu tiên 1/2/3, LAB, ứng dụng khác, priority sai định dạng. Bốn ca dương match đúng rule, hai ca âm không sinh rule. Trong quá trình xây dựng đã sửa regex ký tự mũi tên sang PCRE `\x3e` để trích xuất hoạt động đúng. Kết quả cuối kiểm bằng công cụ legacy đọc file mới; sau restart đã có bằng chứng live từ analysisd hiện tại. Chưa kiểm thử riêng IPv6/TCP/ICMP hoặc biến thể syslog khác.

Restart Wazuh Manager sau kiểm tra; listener UDP514 tiếp tục hoạt động, agent WEB01 vẫn Active. Các bộ WEB/WAF chuẩn bị trước đây chưa được áp dụng trong tác vụ này.

## Bằng chứng thử lại (+07 và UTC)

Đợt thử 23:48:11–23:48:25 +07. Tên miền dương 100000000000000aa.com.suricata-lab.invalid; âm suricata-lab-control.invalid; không kết nối C2 thật, DNS recursion-desired tắt.

| Instance | Luồng dương | SID | Wazuh alert ID | Thời điểm Manager UTC |
|---|---|---|---|---|
| IT/em4 | 10.20.40.254:55466 → 10.20.40.1:53 UDP | 2062547 | 1793897298.2185975 | 2026-11-05 16:48:18.402 +0000 |
| SERVER/em5 | 10.20.50.1:10930 → 10.20.50.10:53 UDP | 2062547 | 1793897300.2186785 | 2026-11-05 16:48:20.095 +0000 |

Cả hai có rule 111101/level12, decoder pfsense-suricata-rfc5424, location 10.20.60.1; agent.id=000 do nhận syslog trực tiếp qua Manager, không phải agent cài trên pfSense. Hai bản ghi phân biệt bằng IP/cổng và full_log có PID khác nhau; syslog hiện không cung cấp trường interface riêng.

Thời gian Manager UTC và pfSense +07 chênh múi giờ, cần quy đổi khi tra cứu; không tự kết luận lệch đồng hồ 7 giờ.

## Bằng chứng lưu trong workspace

Trong suricata-evidence/integration-followup/:

- diagnostics.json: lỗi ban đầu, trạng thái Manager, logtest không match.
- details.json: mã package đã đối chiếu, cấu hình syslog, gói vận chuyển thử bằng logger. Gói logger chỉ kiểm tra vận chuyển, không dùng để tuyên bố phát hiện chữ ký thật.
- ja3-preflight.json và ja3-applied-config-test.json: kiểm tra tạm và cấu hình đã lưu, diff YAML.
- wazuh-staging-tests.json: kiểm thử bản decoder/rule cuối.
- activation.json và it-recovery.json: kết quả kích hoạt, lỗi race và khôi phục IT.
- retest/live-tests.json, retest/it-new-eve.ndjson, retest/server-new-eve.ndjson: bốn gói thử thật, EVE mới.
- live-wazuh-alerts.json: hai alert Manager và trạng thái agent/dịch vụ.

Các tệp bằng chứng cũ tại suricata-evidence/ được giữ nguyên. Script nhận mật khẩu từ biến môi trường tạm, không lưu mật khẩu trong script/báo cáo.

## Các mục vẫn còn trước nghiệm thu đầy đủ

1. Cảnh báo flowbit et.http.PK vẫn còn trên IT và trước đó trên SERVER; chưa xử lý vì cần tìm đúng rule setter/dependency. Không bỏ rule rộng để làm sạch cảnh báo.
2. HOME_NET/EXTERNAL_NET chưa hiệu chỉnh; cần bộ rule/đường quan sát cho tấn công nội bộ, không chỉ các chữ ký EXTERNAL_NET.
3. Chưa chạy từ máy ITADMIN/phòng ban qua firewall tới WEB hoặc từ WAN; chưa kết luận TC01–TC04/PH11 đạt. Ca SERVER phát từ chính pfSense ra em5.
4. Chưa kiểm tra index/Dashboard nhận alert, và chưa triển khai chuyển EVE JSON đầy đủ.
5. Chưa thay cấu hình offloading; cần đối chiếu lưu/runtime trước quyết định. Chưa thử tải hoặc mất gói kéo dài.
6. SSH anti-lockout sẵn trên SALES còn cho phép SSH; rule IT mới không đồng nghĩa firewall chỉ nhận SSH từ host trên mọi interface.

## Hoàn tác có phạm vi

- Wazuh: di chuyển hai file agroflow_pfsense_suricata.xml ra khỏi thư mục decoders/rules sang thư mục backup, chạy analysisd -t rồi restart Manager. Không sửa/xóa local_rules.xml hay local_decoder.xml.
- IT: dùng package cấu hình trả riêng tls_ja3_fingerprint về giá trị trước off, sinh YAML, kiểm tra rồi stop/chờ dừng hoàn toàn/start riêng IT. Cách này tái tạo bốn rule không nạp như ban đầu; chỉ dùng khi cần rollback. Không chép đè toàn bộ config.xml nếu đã có thay đổi khác sau thời điểm backup.

---

<a id="ho-so-20"></a>
## 20. VIEC_CAN_LAM_TIEP.md

# Việc cần nhắc khi người dùng hỏi làm gì tiếp

## WAF đã bật chặn và nghiệm thu trong lab ngày 06/11/2026

- Ubuntu WEB 10.20.50.10 chạy SecRuleEngine On với OWASP CRS PL1. Tám ca giả lập đã bị chặn, suite bổ sung đạt 124/124 request đúng kỳ vọng.
- Wazuh đã xác minh các mẫu audit và access theo ID, cùng cảnh báo WAF chặn, CSRF, upload giả, login sai liên tiếp và từ chối quyền liên tiếp.
- Các mục còn lại và bằng chứng xem NGHIEM_THU_WAF_2026-11-06.md. Ghi chú chờ bật chặn ngày 05/11 đã được thay thế.

## Suricata đã kiểm tra hiện trạng

- IT/em4 và SERVER/em5 chạy, Blocking DISABLED; EVE JSON FILE và alerts vào system log bật trên cả hai.
- ET Open cập nhật thành công ngày 05/11/2026 15:38. SERVER có cảnh báo LAB SID 1000002 và TCP stream SID 2210016.
- Còn cảnh báo offloading; chưa đối chiếu chính xác ba giá trị.
- SSH 10.20.40.1:22 đã bật và xác thực admin thành công; rule IT giới hạn nguồn 10.20.40.254. Có anti-lockout sẵn trên SALES/em1 cũng cho SSH, chưa thay đổi. Chi tiết: SSH_PFSENSE_2026-11-05.md.
- Chưa chứng minh đường chuyển log Suricata đến Wazuh. Ưu tiên xác minh đường log và một sự kiện đầu cuối trước khi tổng hợp rule/bật chặn.
- Hồ sơ: KIEM_TRA_SURICATA_PFSENSE_2026-11-05.md.

## Kết quả kiểm thử mới Suricata 23:29 ngày 05/11

- Hai ca DNS mô phỏng dương đều sinh alert ET SID 2062547 trên IT/SERVER; hai ca âm có DNS log và không alert trong cửa sổ thu. Không bật chặn, không sửa cấu hình.
- IT: 23.692 rule nạp, 4 lỗi, có JA3; SERVER: 28.902 rule nạp, 0 lỗi. Cả hai có cảnh báo dependency flowbit et.http.PK.
- EXTERNAL_NET=!HOME_NET cần rà soát cho kịch bản tấn công nội bộ. Chưa kiểm thử luồng routed giữa phòng ban/WAN.
- Remote syslog pfSense trỏ Wazuh UDP514, source SOC10.20.60.1; Manager có listener/allowed-ips phù hợp. Chưa tìm thấy hai sự kiện mới trong phần alerts/archives đã đọc; cần bắt gói và đối chiếu decoder, không kết luận đã hoàn tất tích hợp.
- Hồ sơ và giới hạn phép thử: KIEM_THU_SURICATA_2026-11-05.md; bằng chứng tại suricata-evidence/.

## Cập nhật sau hiệu chỉnh và thử lại 23:48 ngày 05/11

- Đã bật JA3 riêng IT bằng cấu hình package; engine chạy lại, 23.696 rule nạp thành công, 0 lỗi. Đã xử lý lỗi race pidfile trong lần restart đầu; xem hồ sơ để biết khoảng gián đoạn IT.
- Đã thêm decoder/rule syslog Suricata RFC5424 lên Manager trong file riêng agroflow_pfsense_suricata.xml, ID 111100–111103 và 111109. WEB/WAF trước đây vẫn chưa được áp dụng.
- Đã chứng minh hai alert Suricata thật từ thử DNS lab đi tới alerts.json Wazuh, rule111101 level12, đúng SID/IP/cổng. Vấn đề “chưa tìm thấy log” phía trên là trạng thái cũ, đã được giải quyết tới Manager.
- Còn flowbit et.http.PK; ma trận tấn công nội bộ và kiểm thử routed/WAN; xác minh index/Dashboard và offloading. Không coi đã đạt toàn bộ nghiệm thu.
- Hồ sơ mới nhất: TICH_HOP_SURICATA_WAZUH_2026-11-05.md; bằng chứng tại suricata-evidence/integration-followup/.

---

<a id="ho-so-21"></a>
## 21. WAF_BAN_GIAO_2026-11-05/CAI_DAT_WAF_2026-11-05.md

# Kết quả cài WAF trên Ubuntu WEB

Ngày 05/11/2026. WAF đã được cài và hoạt động trên Ubuntu WEB 10.20.50.10. Chế độ **DetectionOnly**, paranoia level 1. Chưa bật chặn; chưa thay đổi cấu hình/rule trên Wazuh Manager trong phiên này.

## Kiến trúc và phiên bản

Máy phòng ban → Nginx HTTPS 443 + ModSecurity → AgroFlow 127.0.0.1:3000 → MySQL localhost.

Gói từ APT Ubuntu, không biên dịch hoặc tải script cài bên ngoài:

- Nginx 1.24.0-2ubuntu7.19.
- Connector libnginx-mod-http-modsecurity 1.0.3-1build3.
- libmodsecurity3t64 3.0.12-1.1build2.
- OWASP CRS modsecurity-crs 3.3.5-2.

Đây là phiên bản ghi nhận tại lúc cài, không phải tuyên bố đã đánh giá toàn bộ CVE hoặc đạt chứng nhận bảo mật. Khi nâng cấp Nginx/module/CRS phải kiểm tra lại tương thích và các ngoại lệ.

Nginx đã nạp module và báo 923 local rules sau khi thêm chính sách Host. WAF bật tại server HTTPS AgroFlow nên áp dụng cho các location kế thừa của website. Cổng 80 vẫn redirect HTTPS; backend vẫn chỉ nghe loopback. Request từ tiến trình cục bộ gọi trực tiếp 127.0.0.1:3000 không đi qua WAF.

## Cấu hình chính

| Thành phần | Đường dẫn |
|---|---|
| Nginx site | /etc/nginx/sites-available/agroflow |
| Module | /usr/lib/nginx/modules/ngx_http_modsecurity_module.so |
| WAF entry point | /etc/agroflow-waf/main.conf |
| ModSecurity settings | /etc/agroflow-waf/modsecurity.conf |
| Chính sách cục bộ | /etc/agroflow-waf/policy.conf |
| CRS setup | /etc/modsecurity/crs/crs-setup.conf |
| CRS rules | /usr/share/modsecurity-crs/rules/ |
| Log thô WAF, chỉ đọc cục bộ | /var/log/agroflow-waf/audit.jsonl |
| Nginx error chi tiết cho HTTPS site | /var/log/agroflow-waf/nginx-error.log |
| Log WAF đã chọn trường gửi Agent | /var/log/agroflow-waf/events.jsonl |
| Log tương quan request | /var/log/nginx/agroflow-waf-access.jsonl |
| Bộ chuẩn hóa | /usr/local/lib/agroflow-waf/normalizer.py |
| Dịch vụ chuẩn hóa | agroflow-waf-log.service |
| Trạng thái đọc log | /var/lib/agroflow-waf/offset.json |
| Logrotate | /etc/logrotate.d/agroflow-waf |

SecRuleEngine DetectionOnly; request body inspection On, JSON body parser theo config khuyến nghị của gói; giới hạn tổng body 11 MiB và body không tính file 1 MiB. Nginx vẫn có giới hạn 11m trước đó. Response body inspection Off, không tuyên bố giám sát/chặn nội dung phản hồi hoặc rò rỉ dữ liệu qua response.

Ngoại lệ hẹp: bỏ rule 920350 chỉ khi Host là chính xác 10.20.50.10 hoặc 10.20.50.10:443, vì địa chỉ IP là cách truy cập hợp lệ của lab. Không bỏ rule trên toàn hệ thống, không bỏ rule SQLi/XSS/traversal. Tên miền agroflow.internal không cần ngoại lệ numeric Host. Mã chính sách ModSecurity cục bộ: 100010 và 100011; không nhầm với ID rule Wazuh.

## Bảo vệ dữ liệu trong log

- Audit dùng JSON, các phần AHZ; không chủ động ghi request body, request/response header hoặc response body trong audit. Tuy vậy message của rule có thể chứa dữ liệu khớp, nên log thô vẫn được coi là nhạy cảm.
- Module Ubuntu không hỗ trợ modsecurity_use_error_log. Vì vậy error log của riêng HTTPS site chuyển sang tệp được bảo vệ /var/log/agroflow-waf/nginx-error.log; không thu tệp này vào Agent. Nginx error.log cũ vẫn tồn tại cho các context khác. Đây là thay đổi nguồn log cần lưu ý khi điều tra lỗi HTTPS/upstream.
- Agent chỉ thu events.jsonl đã allowlist và correlation JSONL. Không thu audit.jsonl hoặc nginx-error.log thô.
- events.jsonl không có cookie, Authorization, body, matched-data hoặc query string. Có transaction_id, event_id, IP, method, path, status, rule_ids, severity và engine_mode.
- Correlation log không có query/header/body; transaction_id nối với WAF, backend_request_id nối với request_id của AgroFlow. Hai log access (combined và correlation) có mục đích riêng, không được cộng thành hai lần tấn công.
- Bộ chuẩn hóa chạy bằng tài khoản hệ thống riêng agroflow-waf-log, có giới hạn systemd, không chạy root. Offset được lưu qua restart; raw log có quyền đọc hạn chế.
- Đã thử marker mật khẩu/cookie/Authorization giả; chúng không xuất hiện trong hai log chuyển tiếp. Không dùng mật khẩu thật để tạo phép thử này.

Logrotate quay vòng theo ngày, giữ 7 thế hệ và kiểm tra maxsize 20M khi logrotate chạy. Dùng copytruncate để giữ descriptor của ModSecurity; phương pháp này có cửa sổ mất dữ liệu khi copy/truncate dưới tải, nên không coi đây là hệ thống lưu log không mất mát. Đã kiểm tra dry-run; chưa kiểm thử quay vòng dưới tải lớn.

## Kết quả kiểm thử

Thử từ Windows thật 10.20.50.254; các tham số tấn công GET được gửi vào /api/health chỉ đọc, không nhằm đọc tệp thật hoặc thay đổi database.

| Phép thử cuối | Kết quả |
|---|---|
| Health hợp lệ qua IP đã duyệt | 200, không có rule WAF khớp |
| Health hợp lệ qua Host agroflow.internal | 200, không có rule WAF khớp |
| SQLi trong query | 200; CRS 942100 và 949110 |
| XSS trong query | 200; CRS 941100/941110/941160 và 949110 |
| Traversal trong query | 200; CRS 930100/930110/930120, 932160 và 949110 |
| Host numeric khác 192.0.2.44 | 200; vẫn có 920350, chứng minh ngoại lệ không mở rộng |
| XSS trong JSON body đăng nhập với thông tin giả | Backend trả 401; WAF phát hiện 941100/941110/941160 và 949110 |

7/7 phép thử phân biệt kết quả mong đợi đạt. 949110 cho biết vượt ngưỡng anomaly của CRS; với DetectionOnly, điều này không chứng minh request đã bị WAF chặn. HTTP 200 ở API health cũng không chứng minh SQLi/XSS đã khai thác thành công.

Trang chủ HTTPS trả 200, HTTP chuyển 301 sang HTTPS, backend health status ok và database connected. Agent đã thu log WAF và correlation với drops=0 trong bộ đếm được chụp. Tệp cấu hình WAF, CRS, normalizer, service và module đều có baseline FIM.

Chưa kiểm thử đăng nhập thành công, upload/download và toàn bộ quy trình bằng tài khoản nghiệp vụ trong phiên cài WAF. Chưa bật chặn, chưa đánh giá tải lớn và chưa kiểm thử phục hồi WAF từ backup. Duy trì DetectionOnly cho đến khi kiểm thử các luồng hợp lệ và hiệu chỉnh hoàn tất.

## Backup và hoàn tác

- Backup đầy đủ trước cài đã thành công lên Drive, exit 0. Cấu hình Nginx và Agent trước đổi còn tại /var/lib/agroflow-monitoring/waf-setup-20261105/nginx.before và ossec.conf.before.
- Đã cập nhật danh sách backup trong /usr/local/lib/agroflow-backup/backup.py để có /etc/agroflow-waf, /etc/modsecurity, normalizer, service, logrotate và log WAF đã chọn trường. Bản code backup trước sửa lưu trong thư mục hồ sơ cài được bảo vệ.
- Backup đầy đủ sau cài cũng đã thành công, exit 0. Dữ liệu trạng thái/snapshot gần nhất xem /var/lib/agroflow-backup/last-success.json.
- Khôi phục trên máy mới cần cài các gói đúng phiên bản/tương thích và tạo tài khoản dịch vụ; restore config đơn thuần không thay thế cài dependency. Chưa thực hiện restore trong phiên này.
- Nếu cần tắt WAF tạm thời có phê duyệt, đổi modsecurity on thành off trong đúng site, nginx -t rồi reload. Không tắt backend validation hoặc đổi quyền người dùng để bỏ qua lỗi WAF.
- Nếu hoàn tác toàn bộ phiên cài, dùng config Nginx/Agent trước đổi, kiểm tra trước reload/restart; dừng/disable normalizer sau khi bỏ nguồn log tương ứng. Gỡ gói chỉ sau khi bỏ tham chiếu module và kiểm tra dependency. Giữ hồ sơ/bằng chứng.

## Bàn giao Người 1

agroflow-waf-rules.xml đề xuất dải 111050–111069, chưa áp dụng và chưa kiểm thử matching trong dịch vụ Manager. XML đã kiểm tra cấu trúc tại workspace. Người 1 kiểm tra trùng ID, sao lưu và chạy analysisd -t/logtest trước khi nạp.

- 111050: phân loại JSON metadata WAF.
- 111051: rule WAF khớp, level 5.
- 111052: ngưỡng anomaly 949110 xuất hiện, level 7; không kết luận bị chặn/xâm nhập.
- 111053: chỉ numeric Host 920350, level 3.
- 111060: correlation access metadata, level 0; không tạo alert mỗi request.

Không cần decoder riêng vì log đã được chuẩn hóa thành JSON phẳng. Manager hiện không lưu toàn bộ archives; log level 0 không tự xuất hiện thành cảnh báo Dashboard. Không khẳng định WAF đã có alert riêng trên Dashboard trước khi Người 1 triển khai và kiểm tra.

## Tài liệu đối chiếu

- https://github.com/owasp-modsecurity/ModSecurity-nginx
- https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v3.x%29
- https://coreruleset.org/docs/2-how-crs-works/2-1-anomaly_scoring/
- https://packages.ubuntu.com/noble/modsecurity-crs
