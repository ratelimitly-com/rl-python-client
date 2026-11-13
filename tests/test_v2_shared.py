import json, struct
from pathlib import Path
import unittest
from ratelimitly.auth import parse_auth_key
from ratelimitly.protocol import *
from ratelimitly.types import ResourceRequest
F=Path(__file__).parent/'fixtures'
def load(name): return json.loads((F/(name+'.json')).read_text())
def check_shared_caps():
    corpus=load('api_key_v2_test_vectors')
    for v in corpus['valid_credentials']+corpus['historical_v2_credentials']:
        if v['auth_method']=='none': continue
        info=parse_auth_key(v['bech32'])
        assert info.format_version==2
        assert info.window_cap==v['quotas']['rate_window_size_ms_max']
    for v in corpus['invalid_credentials']:
        with unittest.TestCase().assertRaises(ValueError): parse_auth_key(v['bech32'])
def check_shared_ids():
    for v in load('resource_id_v2_vectors')['vectors']:
        assert r_client_derive_bucket_id(bytes.fromhex(v['bucket_name_hex']),v['window_size_ms'],v['rate_limit']).hex()==v['bucket_id_hex']
def check_shared_wire():
    auth=parse_auth_key('rl-cookie1qgyqwps9qspsyqgqqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7ragtruhc7885pu')
    for v in load('rate_window_v2_vectors')['vectors']:
        wide=v['request_tag']=='QW'
        rs=v.get('resources',[v])
        resources=[ResourceRequest(bytes.fromhex(r['bucket_id_hex']),r['window_size_ms'],100,1) for r in rs]
        body=build_rate_request_body(resources,[],wide=wide)
        assert build_rate_request_pdu(300,body,wide=wide).hex()==v['request_pdu_hex']
        response=build_authenticated_packet(bytes.fromhex(v['response_pdu_hex']),auth,bytes(16),1)
        _,result=parse_rate_response_packet(response,auth,wide=wide)
        assert result.success and len(result.resources)==len(resources)
        with unittest.TestCase().assertRaises(ValueError): parse_rate_response_packet(response,auth,wide=not wide)

class TestV2Shared(unittest.TestCase):
    test_shared_caps = staticmethod(check_shared_caps)
    test_shared_ids = staticmethod(check_shared_ids)
    test_shared_wire = staticmethod(check_shared_wire)
