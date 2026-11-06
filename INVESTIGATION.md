# Suricata, IP reputation, монгол тайлбар, incident timeline — v0.5

## Түргэн demo

`Start-Investigation-Demo.bat` нээгээд дуусахыг хүлээнэ. Эсвэл **Tools → Suricata + auth incident demo** сонгоно.

Synthetic demo нь нэг source/target дээр 8 портын flow → нэг Suricata signature → 5 SSH login алдаа → нэг амжилттай login гэсэн **15 normalized log** өгнө. Хүлээгдэх үр дүн **4 alert, 1 sequence candidate**. Энэ нь бодит scan, Suricata engine execution, API lookup биш.

Alert мөр сонгоод **Investigate / Шинжлэх**:

- **Яагаад? Offline explanation (MN)** — шалтгаан, дүрэм, threshold, хугацааны цонх, оноо, log ID болон хадгалсан log-ийн жишээ.
- **Incident timeline** — сонгосон alert-ийн source IP, тухайн цагийн ±15 минутын event ба alert-уудыг дарааллаар харуулна.
- **IP reputation** — локал шалтгаан, provider-ийн report/engine үнэлгээ, эх сурвалж, огноо. Demo IP нь documentation range тул гадаад API руу илгээхгүй.

Багцын `examples/investigation/` нь зөвхөн synthetic эх файлуудтай. Runtime demo-ийн хавтаст `report.json`, `timeline.json`, `explanation-<id>.json`, alert CSV/JSON болон SQLite үүснэ.

## Suricata eve.json импорт

**Tools → Import Suricata eve.json…**, эсвэл:

```powershell
python -m sentinelai import-log suricata eve.json --output normalized-eve.jsonl
python -m sentinelai monitor normalized-eve.jsonl --db incident.sqlite3
python -m sentinelai alerts --db incident.sqlite3 --source suricata --attack-type external_ids --json
```

Нэг мөр нь нэг JSON object байна. `alert`, TCP/UDP `flow` event-ийг дэмжинэ; бусад төрлийг skipped гэж тоолно. Буруу timestamp/IP/port/required signature талбарыг invalid гэж тоолно. Timezone-тай timestamp шаардаж UTC болгоно. Alert нь `ids_alert`, flow нь `connection` болж тус тусад нь хадгалагдана. Signature match-ийг дахин connection болгож тоолохгүй.

`signature_id`, signature, category, native severity, action, `flow_id`, community_id, file SHA-256 болон мөрийн дугаар хадгалагдана. Packet payload, HTTP body зэрэг EVE-ийн бүх талбарыг хадгалахгүй. IP нь sender гэдгийг илэрхийлнэ; rule-ийн target definition-оос хамааран заавал халдагч биш.

Suricata native severity → SentinelAI priority: **1 → 90/critical, 2 → 70/high, 3 болон түүнээс их → 50/medium**. Энэ бол локал mapping; халдлагын магадлал биш. Native signature-д local window threshold нэмдэггүй. Өөр SID-уудыг нэг source IP гэдгээр дарахгүй; эх EVE row-ийн тогтвортой hash-аар яг давтагдсан alert-ийг дарах механизмтай.

Импорт нь 20 MiB / 100,000 мөрийн хязгаартай. Чиглэлийн/протоколын бусад формат, arbitrary EVE event types, Suricata process удирдах болон live EVE rotation adapter энэ хувилбарт ороогүй. Convert хийсэн JSONL-ийг ердийн monitor уншина; raw EVE file-д шууд `--follow` хийхгүй.

## IP reputation: AbuseIPDB / VirusTotal

API key-г чат, код, ZIP-д бичихгүй. Windows PowerShell-ийн тухайн session-д environment variable тохируулж, тэр session-оос app-аа нээнэ:

```powershell
$env:ABUSEIPDB_API_KEY = 'YOUR_ABUSEIPDB_KEY'
$env:VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_KEY'
.\Start-SentinelAI.bat
```

Нэг provider ашиглахад тэр provider-ийн key байхад болно. Placeholder-уудыг өөрийн key-ээр солино. Environment key-г өөрчлөхөөс өмнө нээсэн app шинэ утгыг авахгүй; дахин нээнэ. Source code эдгээр key-г автоматаар `.env`-ээс уншихгүй, SQLite/cache/export-д хадгалахгүй.

API хүсэлт нь **зөвхөн хэрэглэгч Lookup/refresh дарахад** гарна. Window нээх, log импортлох, explanation/timeline үзэхэд API дуудахгүй. Public IP болон authentication header л provider-т очно; log, username, signature payload-ийг явуулахгүй. Private/local/documentation/multicast/reserved IP-г гадагш илгээхгүй. VirusTotal-ийн баримтаар query хийсэн IoC provider-ийн scan/dataset inclusion-д орж болно; нууц indicator-оо query хийхээс өмнө үүнийг тооцно.

```powershell
# PUBLIC_IP-г өөрийн шалгах эрхтэй public IP-аар солино.
python -m sentinelai reputation PUBLIC_IP --provider abuseipdb --db incident.sqlite3
python -m sentinelai reputation PUBLIC_IP --provider virustotal --refresh --db incident.sqlite3
python -m sentinelai reputation PUBLIC_IP --provider both --db incident.sqlite3
```

| Талбар | Утга |
| --- | --- |
| `reason_mn` | Яагаад report/flag байгааг provider-ийн бодит тоон evidence-ээр тайлбарлана; халдлагын төрлийг таахгүй. Локал rule-ийн шалтгааныг dashboard тусад нь үзүүлнэ. |
| `provider_updated_at` | AbuseIPDB: `lastReportedAt` буюу сүүлийн report; VirusTotal: `last_analysis_date` буюу сүүлийн analysis. Хоёр утга ижил хэмжүүр биш. |
| `fetched_at` | Бид хариуг татсан UTC цаг. Provider-ийн мэдээлэл шинэчлэгдсэн цаг гэж орлуулахгүй. |
| `source_url`, `provider` | Аль эх сурвалжаас авсныг заана. |
| `freshness` | Локал display heuristic: cache 24 цагаас эсвэл provider-ийн огноо 30 хоногоос хуучин бол stale; provider огноо байхгүй/ирээдүй бол unknown. Энэ нь provider-ийн баталгаажуулалт биш. |

AbuseIPDB-ийн сүүлийн 90 хоногийн report count, confidence score-г авна; хувь хүмүүсийн comments-ийг татаж хадгалахгүй. VirusTotal-ийн malicious/suspicious/harmless/undetected тоог харуулна. **0 report/flag нь safe гэсэн үг биш.** `reported`, `flagged`, `no_reports`, `no_flags`, `unknown`, `unavailable`, `not_applicable` төлвүүдийг ялгана.

CLI нь 24 цагийн cache ашиглана; `--refresh` нь шинэ таталт шаардана. GUI Lookup/refresh нь тухайн сонгосон provider-т шинэ хүсэлт гаргана. Timeout 12 секунд/provider; automatic retry хийхгүй. 401/403, quota 429, буруу response/огноо, сүлжээний алдааг “clean” болгохгүй. Өмнөх cache байвал огноог нь шинэчлэхгүй, refresh_failed гэж тодорхой харуулна. Provider unavailable/refresh_failed үед CLI exit code 2; private IP not_applicable нь error биш. Key бүхий redirect-ийг дагахгүй.

Lookup нь background thread дээр тул UI-г хүлээлгэхгүй. Rate/quota нөхцөл нь таны account/provider-оос хамаарна. Reputation нь alert үүссэн үеийн мэдээлэл биш байж болно; одоогийн cached report-оор өнгөрсөн үйл явдлыг батлахгүй. Reputation нь alert-ийн severity-г автоматаар өөрчлөхгүй.

## Offline монгол explanation

Таны сонголтоор **LLM/API ашиглахгүй**. `AI explanation` гэсэн бүтээгдэхүүний санааг энэ хувилбарт evidence-д суурилсан deterministic тайлбараар хэрэгжүүлсэн; AI ажилласан, шинэ intelligence зохиосон гэж нэрлээгүй.

```powershell
python -m sentinelai explain 3 --db incident.sqlite3
python -m sentinelai explain 3 --db incident.sqlite3 --json
```

Alert үүсэх үеийн config threshold, window start/end, observed count, normalized log ID-г хадгална. Одоогийн config-ийг хуучин alert-ийн шийдвэр мэт хэрэглэхгүй. Хамгийн ихдээ 20 log sample-г харуулж, бүх холбоотой ID болон full evidence-г JSON export-д үлдээнэ. Suricata-д native SID/action/severity-ийг тайлбарлаж, local window хамаарахгүйг заана.

v0.4 болон түүнээс өмнөх alert-д raw log/threshold байхгүй бол **мэдээлэл хадгалагдаагүй** гэж хэлнэ; үйл явдал зохиохгүй. Эх input-ийг шинэ database-д дахин monitor/import хийхэд шинэ ledger/evidence үүснэ.

## Incident timeline

```powershell
python -m sentinelai timeline --ip 192.0.2.10 --db incident.sqlite3 --export timeline.json
python -m sentinelai timeline --ip 192.0.2.10 --since 2026-10-21T00:00:00Z --until 2026-10-22T00:00:00Z --gap 900 --db incident.sqlite3
```

Ижил source IP болон **ижил destination IP**-г event-time дарааллаар, default 15 минутын inactivity gap-аар бүлэглэнэ. Target тодорхойгүй event-ийг мэдэгдсэн target-тай нэгтгэхгүй. Port-scan alert → SSH brute-force alert → дараах successful auth-ийг, тэдгээрийн хооронд нэг username/service-ийн 3-аас доошгүй failure log байгаагаар sequence candidate гэж тэмдэглэнэ. Тэнцүү timestamp-ийг хатуу дараалал гэж тооцохгүй.

Энэ холбоос нь NAT/shared IP, DHCP, legitimate scanner эсвэл хэрэглэгчийн үйлдлээр тайлбарлагдаж болно. Alert-ийн rule өөрөө source-оор aggregate хийдэг; timeline target-ийг тусад нь бүлэглэдэг. Correlation нь causal proof, confirmed compromise, attacker identity биш. Legacy/missing trigger-log ID-тай alert-ийг unlinked гэж үлдээнэ. Хугацааны хүрээ/limit-д таслагдсан хэсгийг truncated гэж заана. Default хамгийн сүүлийн 5,000 event/alert; limit дээд тал нь 10,000.

## Хадгалалт ба баталгаажуулалт

Normalized event ledger нь SQLite-д persist хийнэ. Whitelist нь timestamp, endpoint/port, username/service/outcome, native signature metadata болон provenance-г хадгална; arbitrary password/payload field хадгалахгүй. Энэ нь raw packet/full log archive биш. Ижил source-native ID эсвэл яг адил normalized record-ийг давхар event болгохгүй; native unique ID өгөөгүй ижил timestamp/content бүхий хоёр жинхэнэ үйл явдлыг ялгаж чадахгүй байж болно. Шинэ process input file-ээ дахин уншиж detection window-оо сэргээнэ; ledger-ээс автоматаар detector window сэргээдэггүй. Late log timeline-д орж болох ч local window дүрэмд орсон эсэхийг late flag-аар харуулна.

Event ledger болон session dedup set-д автомат retention/дээд хэмжээ байхгүй. Modest-volume local deployment-д зориулагдсан; урт хугацаанд disk/memory usage-аа хянаж, DB backup/retention бодлого хэрэгтэй. Бодит үйлдвэрлэлийн SIEM-ийн availability/throughput баталгаа биш.

Автомат тестүүд synthetic EVE/auth fixture, тайлбарын баримт, цаг/target/username-ийн буруу холбоосоос сэргийлэлт, signature replay, cache болон API mock хариуг шалгана. Энэ орчинд API key тохируулаагүй тул AbuseIPDB/VirusTotal live authentication/response-ийг туршаагүй. Suricata executable engine ажиллуулаагүй; зөвхөн EVE adapter-ийг шалгасан. Windows Wi-Fi native API-ийн sandbox Access Denied хязгаар хэвээр.

Эх сурвалж: [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html), [AbuseIPDB API](https://docs.abuseipdb.com/), [VirusTotal IP report](https://docs.virustotal.com/reference/ip-info), [VirusTotal IP timestamps/stats](https://docs.virustotal.com/reference/ip-object).
