from cybersec_platform.parsing import detect_log_format, normalize_log_entry


def test_detect_json_format():
    assert detect_log_format('{"message":"ok"}') == 'json'


def test_detect_apache_format():
    sample = '127.0.0.1 - - [24/Jun/2026:11:15:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
    assert detect_log_format(sample) == 'apache_or_nginx'


def test_normalize_json_entry():
    raw = '{"message":"ok","status":200}'
    normalized = normalize_log_entry(raw)
    assert normalized['format'] == 'json'
    assert normalized['message'] == 'ok'
