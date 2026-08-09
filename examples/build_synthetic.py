from pathlib import Path
import json,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from neuruh_authority_delegation_contract import *
r=create_root_delegation(
    delegation_id="del-synthetic",principal_id="principal-synthetic",delegate_id="human-synthetic",
    authorities=("operator",),capabilities=("synthetic.tool",),domains=("synthetic-domain",),allowed_action_ids=("act-synthetic",),
    issued_at="2026-08-09T19:00:00Z",not_before="2026-08-09T19:00:00Z",expires_at="2026-08-09T20:00:00Z",
    max_spend=10,can_redelegate=False,max_depth=0,
)
Path(__file__).with_name("delegation.synthetic.json").write_text(json.dumps(r.to_dict(),indent=2,sort_keys=True)+"\n")
print(r.delegation_digest)
