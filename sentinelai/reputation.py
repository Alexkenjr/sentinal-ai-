"""On-demand, read-only public-IP reputation with provenance and bounded caching."""
import ipaddress
import json
import os
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, build_opener, HTTPRedirectHandler

PROVIDERS = ('abuseipdb', 'virustotal')
KEYS = {'abuseipdb': 'ABUSEIPDB_API_KEY', 'virustotal': 'VIRUSTOTAL_API_KEY'}


def utc_now():
    return datetime.now(timezone.utc)


def iso(value):
    if value is None:
        return None
    if isinstance(value, (float, int)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    stamp = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Provider timestamp lacks timezone')
    return stamp.astimezone(timezone.utc).isoformat()


class ProviderError(ValueError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(url, headers):
    try:
        with build_opener(NoRedirect()).open(Request(url, headers=headers), timeout=12) as response:
            data = response.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ProviderError('Provider response exceeds 2 MiB')
        return json.loads(data)
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise ProviderError('API key эсвэл provider-ийн эрхийг шалгана уу (HTTP 401/403).') from None
        if exc.code == 429:
            raise ProviderError('Provider-ийн quota/rate limit хүрсэн (HTTP 429). Дараа дахин оролдоно уу.') from None
        raise ProviderError(f'Provider HTTP error {exc.code}; cached мэдээллийг баталгаатай шинэчилсэнгүй.') from None
    except (URLError, TimeoutError, OSError):
        raise ProviderError('Provider-т холбогдсонгүй; сүлжээ болон proxy тохиргоогоо шалгана уу.') from None
    except (ValueError, UnicodeError):
        raise ProviderError('Provider response is not valid JSON') from None


def integer(value):
    if type(value) is not int or value < 0:
        raise ValueError('Invalid provider count')
    return value


def fetch(ip, provider):
    if provider not in PROVIDERS:
        raise ValueError('Unknown reputation provider')
    key = os.environ.get(KEYS[provider], '').strip()
    if not key:
        raise ProviderError(f'{KEYS[provider]} environment variable тохируулаагүй.')
    if provider == 'abuseipdb':
        data = request_json('https://api.abuseipdb.com/api/v2/check?' + urlencode(dict(ipAddress=ip, maxAgeInDays=90)),
                            {'Key': key, 'Accept': 'application/json'})['data']
        if str(ipaddress.ip_address(data['ipAddress'])) != ip:
            raise ValueError('Provider returned a different IP')
        total, score = integer(data['totalReports']), integer(data['abuseConfidenceScore'])
        if score > 100:
            raise ValueError('Invalid confidence score')
        updated = iso(data.get('lastReportedAt'))
        reason = f'Сүүлийн 90 хоногт {total} report; AbuseIPDB confidence={score}/100. Энэ нь provider-ийн үнэлгээ, халдлагын баталгаа биш.'
        status = 'reported' if total else 'no_reports'
        result = dict(status=status, reason_mn=reason, provider_updated_at=updated,
            update_meaning='lastReportedAt: хамгийн сүүлд report ирсэн цаг',
            evidence=dict(total_reports=total, abuse_confidence_score=score, report_window_days=90),
            source_url=f'https://www.abuseipdb.com/check/{quote(ip, safe="")}')
    else:
        data = request_json('https://www.virustotal.com/api/v3/ip_addresses/' + quote(ip, safe=''),
                            {'x-apikey': key, 'Accept': 'application/json'})['data']
        if str(ipaddress.ip_address(data['id'])) != ip:
            raise ValueError('Provider returned a different IP')
        attributes = data['attributes']
        stats = attributes.get('last_analysis_stats')
        if not isinstance(stats, dict):
            stats = {}
        counts = {name: integer(stats[name]) for name in ('malicious','suspicious','harmless','undetected','timeout') if name in stats}
        flagged = counts.get('malicious', 0) + counts.get('suspicious', 0)
        status = 'flagged' if flagged else 'no_flags' if sum(counts.values()) else 'unknown'
        result = dict(status=status,
            reason_mn=f'VirusTotal: malicious={counts.get("malicious", 0)}, suspicious={counts.get("suspicious", 0)}, нийт үнэлгээ={sum(counts.values())}. Тэг flag нь аюулгүй гэсэн баталгаа биш.',
            provider_updated_at=iso(attributes.get('last_analysis_date')),
            update_meaning='last_analysis_date: provider-ийн сүүлийн analysis цаг', evidence=counts,
            source_url=f'https://www.virustotal.com/gui/ip-address/{quote(ip, safe="")}')
    result.update(ip=ip, provider=provider, fetched_at=utc_now().isoformat())
    return result


def ensure_schema(store):
    store.db.execute('CREATE TABLE IF NOT EXISTS reputation_cache (ip TEXT, provider TEXT, data TEXT NOT NULL, PRIMARY KEY(ip,provider))')
    store.db.commit()


def freshness(result):
    result = dict(result)
    now = utc_now()
    result['cache_age_seconds'] = max(0, int((now-datetime.fromisoformat(result['fetched_at'])).total_seconds()))
    result['cache_expired'] = result['cache_age_seconds'] >= 86400
    updated = result.get('provider_updated_at')
    result['provider_age_days'] = round((now-datetime.fromisoformat(updated)).total_seconds()/86400, 2) if updated else None
    result['freshness'] = ('unknown' if not updated or result['provider_age_days'] < -0.01 else
                           'stale' if result['cache_expired'] or result['provider_age_days'] > 30 else 'recent')
    return result


def cached(store, ip, provider=None):
    ensure_schema(store)
    rows = store.db.execute('SELECT data FROM reputation_cache WHERE ip=?' + (' AND provider=?' if provider else ''),
                            (ip, provider) if provider else (ip,)).fetchall()
    return [freshness(json.loads(row[0])) for row in rows]


def lookup(store, ip, provider='abuseipdb', refresh=False):
    address = ipaddress.ip_address(ip)
    if getattr(address, 'ipv4_mapped', None):
        address = address.ipv4_mapped
    ip = str(address)
    if provider not in PROVIDERS:
        raise ValueError('Unknown reputation provider')
    if not address.is_global or address.is_multicast or address.is_reserved:
        return dict(ip=ip, provider=provider, status='not_applicable', freshness='unknown',
            provider_updated_at=None, fetched_at=None,
            reason_mn='Private/local/documentation IP тул public reputation API руу илгээгээгүй. Орон нутгийн log дохиог тусад нь шалгана.')
    previous = cached(store, ip, provider)
    if previous and not refresh and not previous[0]['cache_expired']:
        return {**previous[0], 'cached': True}
    try:
        result = fetch(ip, provider)
    except (ProviderError, KeyError, ValueError, TypeError, OverflowError) as exc:
        error = str(exc) if isinstance(exc, ProviderError) else 'Provider-ийн IP metadata эсвэл timestamp буруу; шинэчилсэнгүй.'
        if previous:
            return {**previous[0], 'cached': True, 'lookup_error': error, 'refresh_failed': True, 'freshness': 'refresh_failed'}
        return dict(ip=ip, provider=provider, status='unavailable', freshness='unknown',
                    provider_updated_at=None, fetched_at=None, reason_mn=error)
    with store.db:
        store.db.execute('INSERT OR REPLACE INTO reputation_cache VALUES (?,?,?)', (ip, provider, json.dumps(result)))
    return {**freshness(result), 'cached': False}
