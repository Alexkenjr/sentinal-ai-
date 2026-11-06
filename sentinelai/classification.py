"""Explain rule indicators without asserting that an attack is confirmed."""
TYPES = {
    'brute_force': ('SSH brute force', 'attack_indicator', ('ssh_brute_force',)),
    'port_scan': ('Port scanning', 'attack_indicator', ('port_scan',)),
    'suspicious_login': ('Suspicious login', 'attack_indicator', ('suspicious_auth',)),
    'external_ids': ('Suricata IDS alert', 'external_ids_indicator', ('suricata_alert',)),
    'wifi_security': ('Wi-Fi security risk', 'configuration_risk',
        ('wifi_open', 'wifi_legacy_security', 'wifi_unknown_security', 'wifi_nonpublic_profile', 'wifi_firewall_disabled')),
    'wifi_change': ('Wi-Fi network change', 'change_indicator',
        ('wifi_gateway_changed', 'wifi_dns_changed', 'wifi_access_point_changed')),
    'other': ('Other / unclassified', 'unclassified', ()),
}


def classify(rule):
    for key, (label, classification, rules) in TYPES.items():
        if rule in rules:
            return dict(attack_type=key, attack_label=label, classification=classification)
    return dict(attack_type='other', attack_label=TYPES['other'][0], classification='unclassified')


def classified(alert):
    return {**alert, **classify(alert['rule'])}
