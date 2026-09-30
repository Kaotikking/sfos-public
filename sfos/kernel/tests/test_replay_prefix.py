"""Existing replay lifecycle prefix semantics; inert signed fixtures only."""
import importlib.util
from pathlib import Path

import pytest

_SPEC=importlib.util.spec_from_file_location('kernel_replay_prefix',Path(__file__).parents[1]/'payload/runtime/replay_store.py')
replay=importlib.util.module_from_spec(_SPEC);_SPEC.loader.exec_module(replay)
KEY=b'x'*32
NOW='2026-09-30T12:00:04Z'


def fixture():
    def ident(index):return f'11111111-2222-4333-8444-{index:012d}'
    descriptor=replay.make_descriptor(store_id=ident(1),backend_identity='fixture-only',
        issuer='fixture',observer='fixture',key=KEY,key_receipt=ident(2),vm_id='FIXTURE',
        boot_id=ident(3),parent='a'*40,commit='b'*40,tree='c'*40)
    unused=replay.make_unused(descriptor,key=KEY,receipt_id=ident(4),run_id=ident(5),
        action_nonce=ident(6),observed_at='2026-09-30T12:00:00Z',expires_at='2026-09-30T12:10:00Z')
    reserved=replay.transition(unused,expected_hash=replay.receipt_hash(unused),operation='RESERVE',
        receipt_id=ident(7),at='2026-09-30T12:00:01Z',key=KEY)
    consumed=replay.transition(reserved,expected_hash=replay.receipt_hash(reserved),operation='CONSUME',
        receipt_id=ident(8),at='2026-09-30T12:00:02Z',key=KEY)
    return descriptor,[unused,reserved,consumed]


@pytest.mark.parametrize('length',(1,2,3))
def test_valid_prefix_is_verified_without_admission(length):
    descriptor,chain=fixture()
    result=replay.verify_lifecycle(chain[:length],descriptor=descriptor,key=KEY,current_time=NOW,require_consumed=False)
    assert result['state']==('UNUSED','RESERVED','CONSUMED')[length-1]
    assert result['authority_effect']=='NONE'


@pytest.mark.parametrize('length',(1,2))
@pytest.mark.parametrize('field,value',(('state','CONSUMED'),('operation','CONSUME'),
                                     ('result','CONSUMED'),('transition_effect','CONSUMPTION')))
def test_signed_invalid_partial_sequence_is_rejected(length,field,value):
    descriptor,chain=fixture();chain=chain[:length]
    body={**chain[-1]['body'],field:value};chain[-1]=replay.signed(body,KEY)
    with pytest.raises(ValueError,match='(state|operation|effect) sequence'):
        replay.verify_lifecycle(chain,descriptor=descriptor,key=KEY,current_time=NOW,require_consumed=False)


def test_a_fourth_signed_revision_is_not_a_valid_partial_prefix():
    descriptor,chain=fixture();prior=chain[-1]
    body={**prior['body'],'receipt_id':'11111111-2222-4333-8444-000000000009',
          'revision':3,'prior_revision':2,'prior_receipt_sha256':replay.receipt_hash(prior),
          'observed_at':'2026-09-30T12:00:03Z'}
    chain.append(replay.signed(body,KEY))
    with pytest.raises(ValueError,match='receipt chain'):
        replay.verify_lifecycle(chain,descriptor=descriptor,key=KEY,current_time=NOW,require_consumed=False)
