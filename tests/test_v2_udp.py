"""Loopback QW/RW transport, cap admission and no-fallback pins."""
import json
import socket
import struct
import threading
from pathlib import Path
import unittest
from ratelimitly import RateLimitlyClient, ResourceRequest, RequestPolicy, FixedSchedule, RCLIENT_OK, RCLIENT_ERR_PROTOCOL
from ratelimitly.auth import parse_auth_key
from ratelimitly.discovery import ServerEndpoint
from ratelimitly.protocol import _extract_authenticated_pdu, build_authenticated_packet, r_client_derive_bucket_id
KEYS=json.loads((Path(__file__).parent/'fixtures/api_key_v2_test_vectors.json').read_text())['valid_credentials']
def key(method,code=31): return next(v['bech32'] for v in KEYS if v['auth_method']==method and v['window_code']==code)
def check_actual_long_udp_and_identical_replay(method,window):
    auth=parse_auth_key(key(method))
    if method=='aes':
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        AESGCM(auth.secret)
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0));server.settimeout(2)
    endpoint=ServerEndpoint(socket.AF_INET,server.getsockname(),7,'local.test')
    received=[]; errors=[]
    def respond():
        try:
            first,address=server.recvfrom(1200); received.append(first)
            packet,address=server.recvfrom(1200); received.append(packet)
            rid,_,pdu,_=_extract_authenticated_pdu(packet,auth)
            assert pdu[:2]==b'QW' and len(pdu)==76
            assert struct.unpack_from('<Q',pdu,28)[0]==60000
            assert struct.unpack_from('<Q',pdu,60)[0]==window
            body=bytearray(pdu);body[:2]=b'RW';body[4:8]=bytes(4)
            for off in (12,44):struct.pack_into('<IHH',body,off+24,1,0,0)
            server.sendto(build_authenticated_packet(body,auth,rid,1,tenant_id=7,steering_feedback=True),address)
        except Exception as error:errors.append(error)
    thread=threading.Thread(target=respond);thread.start()
    resources=[ResourceRequest(r_client_derive_bucket_id('checkout',w,100),w,100,1) for w in [60000,window]]
    policy=RequestPolicy(unit_ms=80,replay_count=1,replay_gap=FixedSchedule(1),final_receive_units=1,completion_delivery=False)
    client=RateLimitlyClient(key(method),policy=policy,resolver=lambda _: [endpoint],wide_rate_requests=True)
    try:
        status,result=client.check_rate_limit(resources);thread.join(2)
        assert not errors
        assert status==RCLIENT_OK and result.success
        assert received[0]==received[1]
    finally:client.close();server.close()
def check_opt_in_and_caps_before_dns():
    calls=[];resource=ResourceRequest(bytes(16),31536000000,1,1)
    for code,opt in [(31,False),(6,True)]:
        client=RateLimitlyClient(key('cookie',code),resolver=lambda _: calls.append(1),wide_rate_requests=opt)
        assert client.check_rate_limit([resource])[0]==RCLIENT_ERR_PROTOCOL
        assert not calls
        client.close()

class TestV2Udp(unittest.TestCase):
    def test_actual_long_udp_and_identical_replay(self):
        for method in ['cookie','aes']:
            for window in [7776000000,15724800000,31536000000]:
                with self.subTest(method=method,window=window):
                    check_actual_long_udp_and_identical_replay(method,window)
    test_opt_in_and_caps_before_dns = staticmethod(check_opt_in_and_caps_before_dns)
