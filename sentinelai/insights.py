"""Offline Mongolian explanations and conservative event-time incident grouping."""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone


def epoch(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Time filters require a timezone')
    return stamp.timestamp()


def explain(store, alert_id):
    alert = store.get_alert(alert_id)
    evidence = alert['evidence']
    ids = list(dict.fromkeys(evidence.get('log_ids', [])))
    selected = ids if len(ids) <= 20 else ids[:10] + ids[-10:]
    logs = []
    for log_id in selected:
        row = store.db.execute('SELECT timestamp,data,late FROM events WHERE event_id=?', (log_id,)).fetchone()
        if row:
            logs.append(dict(log_id=log_id, timestamp=row[0], data=json.loads(row[1]), late=bool(row[2])))
    rule = alert['rule']
    count, threshold, window = evidence.get('count'), evidence.get('threshold'), evidence.get('window_seconds')
    titles = {'port_scan': 'Олон порт руу хандсан дохио', 'ssh_brute_force': 'SSH login олон удаа амжилтгүй болсон',
              'suspicious_auth': 'Login алдааны дараа амжилттай нэвтэрсэн', 'suricata_alert': 'Suricata signature таарсан'}
    if rule == 'port_scan':
        reason = f'Ижил source IP-ээс {window} секундийн цонхонд {count} ялгаатай destination порт ажиглагдсан.'
    elif rule == 'ssh_brute_force':
        reason = f'Ижил source IP-ээс {window} секундийн цонхонд SSH authentication {count} удаа амжилтгүй болсон.'
    elif rule == 'suspicious_auth':
        reason = f'Ижил source IP-ийн {window} секундийн цонхонд {count} authentication алдаа бүртгэгдсэний дараа амжилттай login ажиглагдсан.'
    elif rule == 'suricata_alert':
        reason = (f'Suricata signature_id={evidence.get("signature_id")}, signature={evidence.get("signature")!r}, '
                  f'category={evidence.get("category")!r} таарсан. Native severity={evidence.get("ids_severity")}; '
                  f'action={evidence.get("action")!r}; flow_id={evidence.get("flow_id")}. SentinelAI-ийн хугацааны threshold хэрэглээгүй.')
    elif rule.startswith('wifi_'):
        notes = {'wifi_open': 'Wi-Fi сувгийн шифрлэлтгүй гэсэн дохио бүртгэгдсэн.',
            'wifi_legacy_security': 'Хуучин Wi-Fi хамгаалалтын төрөл илэрсэн гэсэн дохио бүртгэгдсэн.',
            'wifi_unknown_security': 'Wi-Fi хамгаалалтын төрлийг таньж чадаагүй; хамгаалагдсан гэж үзээгүй.',
            'wifi_nonpublic_profile': 'Public hotspot-д тохирох эсэхийг Private/Domain profile дээр шалгах дохио бүртгэгдсэн.',
            'wifi_firewall_disabled': 'Public firewall идэвхгүй гэсэн тохиргооны дохио бүртгэгдсэн.',
            'wifi_gateway_changed': 'Ижил SSID дээр gateway өөрчлөгдсөн; DHCP/roaming байж болно.',
            'wifi_dns_changed': 'Ижил SSID дээр DNS жагсаалт өөрчлөгдсөн; VPN/DHCP байж болно.',
            'wifi_access_point_changed': 'Ижил SSID дээр access point өөрчлөгдсөн; энгийн roaming байж болно.'}
        reason = (notes.get(rule, f'Windows Wi-Fi rule={rule} бүртгэгдсэн.') +
                  f' Хадгалсан SSID={evidence.get("ssid")!r}, auth={evidence.get("auth")!r}, cipher={evidence.get("cipher")!r}.')
    else:
        reason = f'Хадгалсан rule={rule}; танигдаагүй дүрмийн шалтгааныг автоматаар тааж тайлбарласангүй.'
    caveats = ['Энэ нь offline evidence тайлбар; LLM/API дуудаагүй. Халдлага эсвэл compromise батлагдсан гэсэн үг биш.',
               'IP нь илгээгчийн хаяг; NAT, shared IP эсвэл Suricata rule target-оос шалтгаалан халдагчийг дангаараа нотлохгүй.']
    if rule == 'suspicious_auth':
        caveats.append('Энэ дүрэм source IP-ээр агрегатлана; өөр username эсвэл service холилдсон байж болно. Timeline дээр нэг target/username-ийн log-ийг тусад нь шалгана.')
    if threshold is None and rule in ('port_scan','ssh_brute_force','suspicious_auth'):
        caveats.append('Хуучин alert-ийн threshold хадгалагдаагүй; одоогийн config-ийн утгыг өнгөрсөн шийдвэрт орлуулсангүй.')
    if not logs:
        caveats.append('Холбоотой raw normalized log хадгалагдаагүй. Хуучин alert-аас event зохиогоогүй; эх логийг дахин импортолж ledger үүсгэнэ.')
    elif len(logs) < len(ids):
        caveats.append(f'{len(ids)} log ID-гаас хамгийн ихдээ 20 жишээг харуулж байна; ID бүрийн хадгалалт болон full export-ийг шалгана.')
    return dict(method='offline_evidence', language='mn', alert_id=alert['id'], title_mn=titles.get(rule, alert['attack_label']),
        reason_mn=reason, rule=rule, source_ip=alert['src_ip'], alert_time=alert['timestamp'],
        decision=dict(observed_count=count, threshold=threshold, window_seconds=window,
            window_start=evidence.get('window_start'), window_end=evidence.get('window_end'),
            severity=alert['severity'], score=alert['score'], score_meaning='Дүрмийн heuristic priority; ML probability биш'),
        log_ids=ids, log_samples=logs, evidence=evidence, caveats_mn=caveats)


def explanation_text(result):
    decision = result['decision']
    window_text = (f"{decision['window_start'] or '?'} → {decision['window_end'] or '?'} ({decision['window_seconds']}s)"
                   if decision['window_seconds'] is not None else 'Local хугацааны цонх хамаарахгүй / хадгалагдаагүй')
    return (f"{result['title_mn']}\nAlert #{result['alert_id']} | {result['alert_time']} | IP {result['source_ip']}\n\n"
        f"Яагаад?\n{result['reason_mn']}\n\n"
        f"Дүрэм: {result['rule']}\nThreshold: {decision['threshold'] if decision['threshold'] is not None else 'хадгалагдаагүй / хамаарахгүй'}\n"
        f"Цонх: {window_text}\n"
        f"Оноо: {decision['score']} / 100; severity={decision['severity']}\n"
        f"Холбогдсон log ID: {len(result['log_ids'])}; харуулсан жишээ: {len(result['log_samples'])}\n\n"
        + '\n'.join(result['caveats_mn']) + '\n\nLOG SAMPLES (normalized, local):\n'
        + json.dumps(result['log_samples'], ensure_ascii=False, indent=2))


def timeline(store, ip, since=None, until=None, gap_seconds=900, limit=5000):
    ip = str(ipaddress.ip_address(ip))
    if not 1 <= gap_seconds <= 86400 or not 1 <= limit <= 10000:
        raise ValueError('Gap must be 1..86400 seconds and limit 1..10000')
    start = epoch(since) if since else float('-inf')
    end = epoch(until) if until else float('inf')
    if start > end:
        raise ValueError('since must not be after until')
    rows = store.db.execute('SELECT event_id,event_time,data,late FROM events WHERE src_ip=? AND event_time>=? AND event_time<=? ORDER BY event_time DESC,event_id DESC LIMIT ?',
                            (ip, start, end, limit+1)).fetchall()
    truncated = len(rows) > limit
    rows = list(reversed(rows[:limit]))
    incidents, active, event_incident = [], {}, {}
    for event_id, event_time, data, late in rows:
        event = json.loads(data)
        target = event.get('dst_ip') or 'unknown'
        incident = active.get(target)
        if incident is None or event_time-incident['_last'] > gap_seconds:
            incident = dict(incident_id=hashlib.sha256((ip+'|'+target+'|'+event_id).encode()).hexdigest()[:16],
                src_ip=ip, dst_ip=target, start=event['timestamp'], end=event['timestamp'], events=[], alerts=[], _last=event_time)
            incidents.append(incident)
            active[target] = incident
        incident['events'].append(dict(log_id=event_id, late=bool(late), **event))
        incident['end'], incident['_last'] = event['timestamp'], event_time
        event_incident[event_id] = incident
    unlinked = []
    bounds = [datetime.fromtimestamp(start, timezone.utc).isoformat() if since else '0001-01-01T00:00:00+00:00',
              datetime.fromtimestamp(end, timezone.utc).isoformat() if until else '9999-12-31T23:59:59+00:00']
    alert_rows = store.db.execute('SELECT id,timestamp FROM alerts WHERE src_ip=? AND julianday(timestamp) BETWEEN julianday(?) AND julianday(?) ORDER BY timestamp DESC,id DESC LIMIT ?',
                                 (ip, *bounds, limit+1)).fetchall()
    truncated = truncated or len(alert_rows) > limit
    for row in reversed(alert_rows[:limit]):
        alert = store.get_alert(row[0])
        if not start <= epoch(alert['timestamp']) <= end:
            continue
        ids = alert['evidence'].get('log_ids', [])
        anchor = alert['evidence'].get('trigger_log_id') or (ids[-1] if ids else None)
        if anchor in event_incident:
            event_incident[anchor]['alerts'].append(alert)
        else:
            unlinked.append(dict(id=alert['id'], timestamp=alert['timestamp'], rule=alert['rule'],
                                 reason_mn='Энэ хүрээнд холбох normalized log ID байхгүй; event зохиосонгүй.'))
    for incident in incidents:
        del incident['_last']
        scans = [a for a in incident['alerts'] if a['rule'] == 'port_scan']
        brute = [a for a in incident['alerts'] if a['rule'] == 'ssh_brute_force']
        chain = False
        for success in [e for e in incident['events'] if e.get('outcome') == 'success' and e.get('event_type') == 'auth']:
            for scan in scans:
                failures = [e for e in incident['events'] if e.get('outcome') == 'failure' and
                    e.get('username') == success.get('username') and e.get('service') == success.get('service') and
                    epoch(scan['timestamp']) < epoch(e['timestamp']) < epoch(success['timestamp'])]
                if len(failures) >= 3 and any(epoch(scan['timestamp']) < epoch(a['timestamp']) < epoch(success['timestamp']) for a in brute):
                    chain = True
        incident['sequence_candidate'] = chain
        incident['title_mn'] = ('Port scan → олон login алдаа → амжилттай login: цагийн холбоостой сэжигтэй дараалал'
                                if chain else 'Ижил source/target-ийн цагийн дараалал; attack chain батлагдаагүй')
    return dict(ip=ip, gap_seconds=gap_seconds, truncated=truncated, incidents=incidents, unlinked_alerts=unlinked,
        limitations_mn=['Ижил source IP, target IP, хугацааны ойролцоо байдал нь шалтгаан эсвэл халдагчийн identity-г нотлохгүй.',
            'Target нь мэдэгдэхгүй log-ийг target нь мэдэгдсэн log-той автоматаар нэгтгэхгүй.',
            'Late log нь timeline-д харагдаж болно; local window detection-д орсон эсэхийг late талбараар ялгана.'])
