# SentinelAI v0.3 — Public Wi-Fi хяналт

Энэ горим нь Windows компьютерийн **өөрийн Wi-Fi холболтыг** бодитоор уншина. Demo биш. Сүлжээний бусад хэрэглэгчийг scan хийхгүй, packet болон нууц үг цуглуулахгүй, firewall эсвэл Windows тохиргоог автоматаар өөрчлөхгүй.

## Ажиллуулах

1. ZIP файлыг задлаад `Start-Public-WiFi.bat` нээнэ. Эсвэл dashboard дээр **Public Wi-Fi** дарна.
2. Эхний мэдээлэл иртэл `COLLECTING` харагдана. Дараа нь 30 секунд тутам холболтоо дахин уншина.
3. Анхааруулга сонгоход SSID, хамгаалалтын төрөл, gateway, DNS болон хийх үйлдлийн зөвлөмж харагдана. IP баганад таны төхөөрөмжийн локал IP харагдана; энэ нь халдагчийн IP гэсэн үг биш.
4. **Acknowledge**, **Dismiss**, **Export visible alerts** өмнөх хувилбартай адил ажиллана. **Stop** хяналтыг зогсооно.

Terminal:

```powershell
python -m sentinelai wifi --once --json
python -m sentinelai wifi
python SentinelAI.pyz wifi --gui
```

## Ямар дохио шалгах вэ?

| Дохио | Утга |
| --- | --- |
| `wifi_open` | Wi-Fi сувгийн шифрлэлт байхгүй. HTTPS болон итгэлтэй VPN ашиглах эсэхээ шийдэх дохио. |
| `wifi_legacy_security` | WEP/TKIP эсвэл хуучин WPA тохиргоо. |
| `wifi_unknown_security` | Хамгаалалтын төрлийг таньсангүй; хамгаалагдсан гэж дүгнээгүй. |
| `wifi_nonpublic_profile` | Public hotspot-д Private/Domain профиль ашиглаж байна. Тохиргоогоо шалгах сануулга. |
| `wifi_firewall_disabled` | Public профиль идэвхтэй байхад Windows Public firewall-ийн effective тохиргоо унтарсан. |
| `wifi_gateway_changed` | Ижил SSID дээр gateway солигдсон. DHCP зэрэг энгийн шалтгаантай байж болно. |
| `wifi_dns_changed` | DNS жагсаалт солигдсон. VPN/DHCP-тай холбоотой эсэхийг шалгана. |
| `wifi_access_point_changed` | Ижил SSID дээр AP/BSSID солигдсон. Roaming байж болно; evil twin батлагдсан гэсэн үг биш. |

Дүрмийн оноо нь шалгах дарааллын heuristic; халдлагын магадлал эсвэл нарийвчлал биш. Шинэ SSID дээр анхны baseline үүсгэнэ. Ижил SSID-ийн өөрчлөлтийг өмнөх baseline-тай харьцуулна. Анхааруулгыг rule/local-IP бүрээр 5 минут давхардуулахгүй. Wi-Fi дүрмийн оноо, хугацаа нь энэ хувилбарт тогтмол; `config.json` нь JSONL-ийн гурван дүрэмд үйлчилнэ.

## Access denied / мэдээлэл дутуу үед

**UNAVAILABLE** гэвэл хяналт хийгдээгүй. **PARTIAL** гэвэл мэдээллийн зарим хэсгийг авч чадаагүй. **NO WI-FI** гэвэл холбогдсон Wi-Fi adapter олдоогүй. Эдгээрийн аль нь ч “аюулгүй” гэсэн дүгнэлт биш.

Windows нь Wi-Fi мэдээллийн зарим API-д Location зөвшөөрөл шаарддаг. **Wi-Fi permissions** товч Windows-ийн Location тохиргоог нээнэ. Өөрөө Location services болон desktop app-ийн зөвшөөрлийг шалгаад, Stop → Public Wi-Fi дарж дахин оролдоно. Байгууллагын policy, WLAN AutoConfig үйлчилгээ, sandbox болон PowerShell/CIM эрх мөн мэдээлэл авахад саад болж болно. Администратор болгон ажиллуулах нь Location зөвшөөрлийг орлохгүй. SentinelAI зөвшөөрөл, firewall, network profile-ийг өөрөө өөрчлөхгүй.

## Хадгалалт ба хязгаар

Dashboard-ийн **Attack / risk** шүүлтүүрээр `Wi-Fi security risk` болон `Wi-Fi network change`-ийг тусад нь сонгоно. Эхнийх нь тохиргооны эрсдэл (`configuration_risk`), дараагийнх нь өөрчлөлтийн дохио (`change_indicator`); батлагдсан халдлага гэсэн утгагүй. SSH brute force, port scanning, suspicious login нь `attack_indicator` ангилалтай. Severity, status шүүлтүүртэй хамт хэрэглэж болно. CSV/JSON гаргалтад ангилал мөн орно.

Анхааруулга болон interface бүрийн сүүлийн baseline `%LOCALAPPDATA%\SentinelAI\wifi-alerts.sqlite3` файлд хадгалагдана. SSID/BSSID, локал IP, DNS зэрэг сүлжээний мэдээлэл ордог тул экспорт болон database-аа бусдад өгөхдөө анхаарна. Бүх snapshot-ийн түүх, packet хадгалдаггүй.

Энэ нь локал posture monitor. HTTPS interception, DNS poisoning, ARP spoofing, rogue AP эсвэл бүх төрлийн халдлагыг баталгаатай илрүүлэх систем биш. WPA2/WPA3 гэсэн нэр өөрөө hotspot найдвартайг батлахгүй. VPN байгаа эсэх, captive portal, интернетийн хүртээмжийг энэ хувилбар шалгахгүй. Нээлттэй сүлжээн дээр Wi-Fi-ийн бүх хэрэглэгчийг хамарсан хяналт хийхэд операторын зөвшөөрөлтэй router/AP telemetry шаардлагатай.

## Баталгаажуулалтын бодит хязгаар

Автомат тестүүд fixture болон mock collector ашиглан дүрэм, baseline, дахин асаалт, UI, эрхийн алдаа болон background ажиллагааг шалгадаг. Энэ хөгжүүлэлтийн sandbox дээр бодит Windows WLAN API `Access denied` буцаасан тул амьд hotspot-ийн бүтэн мэдээлэл болон бодит халдлагаар end-to-end туршилт баталгаажаагүй. Таны Windows төхөөрөмж дээр зөвшөөрөлтэй ажиллуулж, авсан мэдээлэл сүлжээний тохиргоотой таарч байгааг шалгах шаардлагатай. Production accuracy гэсэн баталгаа өгөөгүй.

Албан ёсны API тайлбар: [WlanQueryInterface](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlanqueryinterface), [Wi-Fi ба Location зөвшөөрөл](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes), [IP configuration](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration), [Firewall profile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile).
