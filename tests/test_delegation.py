import unittest
from neuruh_authority_delegation_contract import *

def root(**kw):
    d=dict(delegation_id="del-root",principal_id="principal",delegate_id="manager",authorities=("approve",),capabilities=("synthetic.tool",),domains=("synthetic",),allowed_action_ids=("act-1","act-2"),issued_at="2026-08-09T19:00:00Z",not_before="2026-08-09T19:00:00Z",expires_at="2026-08-09T21:00:00Z",max_spend=100,can_redelegate=True,max_depth=2)
    d.update(kw); return create_root_delegation(**d)
def child(parent=None,**kw):
    parent=parent or root()
    d=dict(delegation_id="del-child",delegate_id="human-1",authorities=("approve",),capabilities=("synthetic.tool",),domains=("synthetic",),allowed_action_ids=("act-1",),issued_at="2026-08-09T19:01:00Z",not_before="2026-08-09T19:01:00Z",expires_at="2026-08-09T20:00:00Z",max_spend=10,can_redelegate=False)
    d.update(kw); return derive_delegation(parent,**d)
class Tests(unittest.TestCase):
    def bad(self,fn):
        with self.assertRaises(DelegationValidationError): fn()
    def test_root_valid(self): root().validate()
    def test_child_valid(self): self.assertTrue(verify_child(root(),child()))
    def test_roundtrip(self): self.assertEqual(AuthorityDelegation.from_mapping(root().to_dict()),root())
    def test_digest_deterministic(self): self.assertEqual(root().delegation_digest,root().delegation_digest)
    def test_bad_schema(self):
        x=root().to_dict(); x["schema_version"]="x"; self.bad(lambda:AuthorityDelegation.from_mapping(x))
    def test_unknown_field(self):
        x=root().to_dict(); x["wat"]=1; self.bad(lambda:AuthorityDelegation.from_mapping(x))
    def test_self_delegation(self): self.bad(lambda:root(delegate_id="principal"))
    def test_empty_authority(self): self.bad(lambda:root(authorities=()))
    def test_empty_capability(self): self.bad(lambda:root(capabilities=()))
    def test_empty_domain(self): self.bad(lambda:root(domains=()))
    def test_duplicate_authority(self): self.bad(lambda:root(authorities=("approve","approve")))
    def test_bad_time(self): self.bad(lambda:root(issued_at="wat"))
    def test_not_before_before_issue(self): self.bad(lambda:root(not_before="2026-08-09T18:59:00Z"))
    def test_expiry_before_start(self): self.bad(lambda:root(expires_at="2026-08-09T18:59:00Z"))
    def test_negative_spend(self): self.bad(lambda:root(max_spend=-1))
    def test_bool_spend(self): self.bad(lambda:root(max_spend=True))
    def test_bad_depth(self): self.bad(lambda:AuthorityDelegation("x","p","d",("a",),("c",),("d",),(),"2026-08-09T19:00:00Z","2026-08-09T19:00:00Z","2026-08-09T20:00:00Z",0,False,-1,0).seal())
    def test_depth_over_max(self): self.bad(lambda:AuthorityDelegation("x","p","d",("a",),("c",),("d",),(),"2026-08-09T19:00:00Z","2026-08-09T19:00:00Z","2026-08-09T20:00:00Z",0,False,2,1,"parent",sha256_ref("p")).seal())
    def test_redelegate_at_max_depth_invalid(self): self.bad(lambda:root(max_depth=0,can_redelegate=True))
    def test_root_parent_forbidden(self): self.bad(lambda:AuthorityDelegation("x","p","d",("a",),("c",),("d",),(),"2026-08-09T19:00:00Z","2026-08-09T19:00:00Z","2026-08-09T20:00:00Z",0,False,0,0,"p",sha256_ref("x")).seal())
    def test_child_missing_parent_invalid(self): self.bad(lambda:AuthorityDelegation("x","p","d",("a",),("c",),("d",),(),"2026-08-09T19:00:00Z","2026-08-09T19:00:00Z","2026-08-09T20:00:00Z",0,False,1,2).seal())
    def test_parent_no_redelegation(self): self.bad(lambda:child(root(can_redelegate=False,max_depth=2)))
    def test_child_widens_authority(self): self.bad(lambda:child(authorities=("approve","admin")))
    def test_child_widens_capability(self): self.bad(lambda:child(capabilities=("synthetic.tool","shell")))
    def test_child_widens_domain(self): self.bad(lambda:child(domains=("synthetic","prod")))
    def test_child_widens_action(self): self.bad(lambda:child(allowed_action_ids=("act-3",)))
    def test_child_widens_spend(self): self.bad(lambda:child(max_spend=101))
    def test_child_starts_before_parent(self): self.bad(lambda:child(not_before="2026-08-09T18:59:00Z"))
    def test_child_outlives_parent(self): self.bad(lambda:child(expires_at="2026-08-09T22:00:00Z"))
    def test_child_cycle_to_root_principal(self): self.bad(lambda:child(delegate_id="principal"))
    def test_authorize_valid(self):
        self.assertTrue(authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1",spend=5))
    def test_wrong_delegate(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="x",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1"))
    def test_wrong_authority(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="admin",capability="synthetic.tool",domain="synthetic",action_id="act-1"))
    def test_wrong_capability(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="shell",domain="synthetic",action_id="act-1"))
    def test_wrong_domain(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="prod",action_id="act-1"))
    def test_wrong_action(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-2"))
    def test_spend_exceeded(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1",spend=11))
    def test_not_yet_active(self): self.bad(lambda:authorize(child(),now="2026-08-09T19:00:30Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1"))
    def test_expired(self): self.bad(lambda:authorize(child(),now="2026-08-09T20:00:01Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1"))
    def test_revoke_valid(self):
        r=revoke_delegation(child(),revoked_at="2026-08-09T19:20:00Z",reason="synthetic revoke"); self.assertEqual(r.status,"revoked")
    def test_revoked_cannot_authorize(self):
        r=revoke_delegation(child(),revoked_at="2026-08-09T19:20:00Z",reason="synthetic revoke")
        self.bad(lambda:authorize(r,now="2026-08-09T19:30:00Z",delegate_id="human-1",authority="approve",capability="synthetic.tool",domain="synthetic",action_id="act-1"))
    def test_second_revoke_rejected(self):
        r=revoke_delegation(child(),revoked_at="2026-08-09T19:20:00Z",reason="synthetic revoke"); self.bad(lambda:revoke_delegation(r,revoked_at="2026-08-09T19:21:00Z",reason="again"))
    def test_active_with_revocation_fields_invalid(self):
        x=root().to_dict(); x["revoked_at"]="2026-08-09T19:10:00Z"; x["delegation_digest"]=sha256_ref("wrong"); self.bad(lambda:AuthorityDelegation.from_mapping(x))
    def test_tamper_digest(self):
        x=root().to_dict(); x["max_spend"]=99; self.bad(lambda:AuthorityDelegation.from_mapping(x))
