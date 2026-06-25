from cybersec_platform.feature_engineering import extract_features


def test_extract_features_basic():
    entry = {
        'remote_addr': '10.0.0.1',
        'request_uri': '/login',
        'status': '401',
        'body_bytes_sent': '512',
        'raw_message': 'failed login attempt',
    }
    features = extract_features(entry)
    assert features['source_ip'] == '10.0.0.1'
    assert features['status_code'] == 401
    assert features['bytes_sent'] == 512
    assert features['message_length'] == len(entry['raw_message'])
