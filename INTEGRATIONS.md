# IP / порт шүүлтүүр, Nmap / Wireshark / Zeek — v0.4

## IP болон порттой ажиллах

Dashboard-ийн **Filters → IP / ports / protocol…** цонх:

- **Source IP / CIDR:** `192.0.2.10`, `192.0.2.0/24`, `2001:db8::/32`.
- **Destination IP / CIDR:** холболтын зорилтот төхөөрөмж. Анхааруулгын evidence-д байгаа үед үйлчилнэ.
- **Destination port(s):** `443`, `22,80,443`, `1000-1010`, эсвэл `22,443,1000-1010`.
- **Protocol:** TCP, UDP, эсвэл хоосон буюу бүгд.
- **Telemetry source:** JSONL, TShark, Zeek, Windows Wi-Fi.

Эдгээрийг Attack/risk, severity, status-тай хамт хэрэглэнэ. Шүүлтүүр нь мөрийн limit-ээс өмнө үйлчилнэ. IP + порт + protocol сонговол шинэ alert-ийн нэг flow дотор хамт таарч байх ёстой. Анхааруулгын бүх flow нийлсэн evidence-ээс утгуудыг өөр өөр холболтоос тааруулдаггүй. Хуучин alert-д зөвхөн байгаа metadata-гаар шүүнэ. Порт нь мэдэгдэхгүй мөр `22` гэсэн шүүлтүүрт таарахгүй; SSH нэртэй гэдгээр 22 гэж таадаггүй.

Alert хүснэгтэд **PORTS** багана нэмэгдсэн. Бүрэн IP/port/protocol evidence нь CSV/JSON экспортод орно. **Filters → Reset all filters** бүх шүүлтүүрийг цэвэрлэнэ. Demo эхлүүлэхэд шүүлтүүрийг цэвэрлэж, demo-ийн үр дүнг бүрэн харуулна.

```powershell
python -m sentinelai alerts --db alerts.sqlite3 --src-ip 192.0.2.0/24 --dst-ip 198.51.100.80 --port 22,443,1000-1010 --protocol tcp --source tshark --export selected.csv
```

## Nmap + Wireshark simulation

`Start-Tools-Demo.bat` нээнэ, эсвэл **Tools → Nmap + Wireshark simulation** сонгоно. Энэ нь offline synthetic simulation: Nmap/TShark executable ажиллуулахгүй, сүлжээг scan/capture хийхгүй.

| Artifact | Агуулга |
| --- | --- |
| `nmap.xml` | 50 зорилтот төхөөрөмж, төхөөрөмж бүрт 22/80/443 нээлттэй гэж өгсөн inventory: нийт 150 service |
| `wireshark.pcap` | Ethernet/IPv4/TCP форматтай 85 synthetic SYN packet, зөв IP/TCP checksum-тай; payload байхгүй |
| `wireshark.csv` | Тэр packet-уудын TShark field export-той нийцсэн metadata |
| `zeek_conn.jsonl` | Ижил чиглэл/цаг/портын Zeek JSON conn.log хэлбэрийн fixture |
| `manifest.json` | Synthetic гэдгийг тэмдэглэсэн expected counts |

Packet simulation нь **50 source IP** ашиглана: эхний 5 IP тус бүр 8 порт руу, үлдсэн 45 IP тус бүр ганц 443 порт руу холбогдох SYN үүсгэнэ. Тусдаа lab destination нь `198.51.100.80`; destination-ийг нэмбэл бүх endpoint 51 болно. Хүлээгдэх үр дүн **85 record, 5 port-scan indicator**. Анхны 50-IP SSH demo-гийн 120 record/15 alert-тай өөр scenario юм.

Nmap inventory болон packet timeline нь тусдаа fixture; бодит scan-аас хоёуланг нь авсан гэж үзэхгүй. Нээлттэй порт нь халдлага, vulnerability эсвэл тухайн төхөөрөмж халдагч гэдгийг батлахгүй.

```powershell
python -m sentinelai tools-demo --gui
python -m sentinelai tools-demo --interval 0
```

Багцын `examples/network_tools/` хавтаст шууд нээх жишээнүүд бий. Simulation run бүр өөрийн user-data дотор fixture, JSONL, SQLite, CSV/JSON alert болон `report.json` үүсгэнэ. `wireshark.pcap`-ийг өөрийн суулгасан Wireshark-аар нээж болно. Бид энэ орчинд Wireshark executable-ээр задлан баталгаажуулаагүй; PCAP header, packet length, IP/TCP checksum болон CSV/Zeek өгөгдлийн таарцыг автомат тестээр шалгасан.

## Бодит tool export импортлох

**Tools** цэснээс:

1. **Import Nmap XML inventory…** — inventory цонх нээгдэнэ. Target IP/CIDR ба портын шүүлтүүр, filtered CSV/JSON export-той. Attack alert үүсгэхгүй. Down эсвэл open port-гүй host нь full inventory JSON-д үлдэнэ; service хүснэгтэд open service-ууд л харагдана.
2. **Import Wireshark / TShark CSV…** — normalized JSONL үүсгээд тусдаа SQLite-д нэг удаа шинжилнэ. GUI нь CSV форматыг дэмжинэ; arbitrary Wireshark GUI CSV болон raw PCAP-ийг шууд import хийхгүй.
3. **Import Zeek JSON conn.log…** — TCP/UDP originator → responder холболтыг уншина. TSV log дэмжихгүй.

Өөрийн өмнө нь авсан PCAP-аас TShark CSV гаргах жишээ (offline read, capture биш):

```powershell
tshark -n -r capture.pcap -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.time_epoch -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tcp.dstport -e udp.dstport -e tcp.flags.syn -e tcp.flags.ack > packets.csv
```

Файлыг UTF-8 текстээр хадгална. Windows PowerShell 5.1 redirection нь UTF-16 үүсгэж болох тул шаардлагатай бол output-ийг `Set-Content -Encoding UTF8`-аар хадгална. TShark CSV нь дээрх баганын нэрстэй байх ёстой. Хоёр flag багана байвал зөвхөн эхний TCP SYN (SYN=1, ACK=0)-г scan analysis-д авна; SYN/ACK болон payload packet-уудыг skip хийнэ. Flag-гүй CSV-д чиглэлийг найдвартай ялгахгүйг warning-аар мэдээлнэ. UDP metadata-г тусад нь TCP/UDP-аар шүүж болно. Tunnel доторх олон давхар IP утга эсвэл TCP+UDP давхардсан ambiguity-г автоматаар таахгүй. PCAP-д application payload тайлах боломжгүй тул SSH password failure эсвэл compromise гэж дүгнэхгүй.

```powershell
python -m sentinelai import-log tshark packets.csv --output flows.jsonl
python -m sentinelai monitor flows.jsonl --db packet-alerts.sqlite3
python -m sentinelai import-log zeek conn.log --output zeek-flows.jsonl
python -m sentinelai import-log nmap scan.xml --output inventory.json
python -m sentinelai inventory scan.xml --ip 192.0.2.0/24 --port 22,443 --protocol tcp --export services.csv
```

Импортын файл 20 MiB, packet/flow record 100,000 хүртэл. Том файлаа хэсэглэнэ. Invalid/skipped мөрийн тоог тайлагнаж, импортын timeline-ийг цагийн дарааллаар эрэмбэлнэ. Эх файл дээр дарж бичих импорт зөвшөөрөхгүй. GUI импорт нь modest-size файлд зориулагдсан; enterprise log pipeline биш.

## Ямар бэлэн төсөл дээр тулгуурласан бэ?

| Төсөл | SentinelAI-д ашигласан бодит хэсэг | Албан ёсны эх сурвалж |
| --- | --- | --- |
| Nmap | Зөвлөдөг machine-readable XML интерфейс; target/service inventory adapter | [Nmap XML](https://nmap.org/book/output-formats-xml-output.html) |
| Wireshark / TShark | PCAP жишээ болон `-T fields` CSV field export adapter | [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html) |
| Zeek | JSON `conn.log`-ийн originator/responder/port/time schema | [Zeek connection log](https://docs.zeek.org/en/current/reference/logs/conn.html) |

Энэ нь tool ecosystem-ийн өгөгдөлтэй interoperability нэмсэн хэрэг; тэдгээрийн detection engine-ийг SentinelAI-д хуулсан гэсэн үг биш. Гуравдагч талын source code/executable-ийг багцлаагүй, автоматаар суулгаагүй. Nmap, Wireshark, Zeek нь тусдаа төсөл бөгөөд SentinelAI-г баталгаажуулсан эсвэл дэмжсэн гэх утгагүй. Nmap-ийн executable-ийг цааш түгээхээр бол [Nmap-ийн өөрийн лиценз](https://nmap.org/npsl/)-ийг тусад нь шалгах шаардлагатай.

Энэ компьютерт Nmap/TShark олдоогүй тул actual binary integration test хийгээгүй. Хэрэглэгчийн бодит export файл, сүлжээний ачаалал, төхөөрөмжийн байрлалд турших шаардлагатай. Public Wi-Fi дээр өөр хэрэглэгчийн урсгалыг харах боломж хязгаарлагдмал; энэ нэмэлт hotspot-ийн бүх хэрэглэгчийг хамарсан хяналт болгохгүй. Detection-ийн бодит accuracy хэмжигдээгүй.
