# SentinelAI AI Bot

Desktop: **AI BOT / Туслах** цэс. Alert сонгосон бол тухайн alert, хадгалсан log sample болон timeline-ийг ашиглана. Сонгоогүй бол сүүлийн 20 alert-ийг ашиглана. Цонх нээх үеийн snapshot; шинэ логийн хувьд дахин нээнэ.

Энэ нь локал Ollama LLM integration. Дүрмийн heuristic оноог AI probability гэж нэрлэхгүй. AI bot нэмэгдсэн ч detection engine одоогоор rule-based хэвээр. AI зөвлөгөө алдаатай байж болно; log ID, alert ID, эх нотолгоотой тулгаж шалгана. Prompt injection-ийг prompt заавраар хязгаарлах нь бүрэн хамгаалалт биш. Bot-д команд ажиллуулах, IP хаах, систем өөрчлөх хэрэгсэл байхгүй.

## Ажиллуулах

1. [Ollama](https://ollama.com/download) суулгаж ажиллуулна.
2. Өөрийн компьютерийн боломж болон Монгол хэлний чанарт тохирох локал model татна: `ollama pull <model-name>`.
3. `ollama list` дээрх суулгасан model нэрийг bot цонхонд оруулна. Хүсвэл `SENTINELAI_BOT_MODEL` environment variable-д тохируулна.
4. Demo эсвэл monitoring ажиллуулаад alert сонгож **AI BOT / Туслах** нээнэ. Асуулт бичээд **Send / Илгээх** дарна.

Model weights бүтээгдэхүүнд багтаагүй. Эхний таталт интернет болон нэмэлт диск/RAM шаарддаг; шаардлага model-оос хамаарна. Local model ажиллаж байгаа эсэх, Монгол хэлний чанарыг тухайн төхөөрөмж дээр шалгана. Cloud model ашиглахгүй. Ollama local-only тохиргоог өөрөө шалгана.

```powershell
python -m sentinelai bot "Яагаад энэ alert үүссэн бэ?" --db "C:\path\alerts.sqlite3" --alert 1 --model "your-installed-model"
```

Холболт зөвхөн `http://127.0.0.1:11434/api/chat`. HTTP proxy болон redirect ашиглахгүй. Нотолгоо, асуулт, цонхны сүүлийн 6 conversation message-ийг энэ local service-д дамжуулна. Chat-ийг дискэнд хадгалахгүй; Ollama-ийн өөрийн logging тусдаа. Context хязгаарлагдвал partial гэж тэмдэглэнэ. SQLite normalized evidence whitelist ашиглана; username/IP нь хувийн мэдээлэл байж болно.

Холболт/model байхгүй эсвэл 60 секундэд хариу өгөхгүй бол **AI unavailable**. Offline template тайлбарыг AI мэт орлуулж харуулахгүй. **Яагаад? Offline explanation** нь тусдаа, model шаардахгүй.

API contract: [Ollama official API documentation](https://github.com/ollama/ollama/blob/main/docs/api.md). Automated tests use mocked model responses, evidence retrieval and real Tk widgets. These tests do not validate an installed LLM or answer quality.
