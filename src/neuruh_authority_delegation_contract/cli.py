from __future__ import annotations
import sys as _sys
from .core import DelegationValidationError
import argparse,json
from pathlib import Path
from .core import AuthorityDelegation, authorize

def _main(argv=None):
    p=argparse.ArgumentParser(prog="neuruh-authority-delegation")
    sp=p.add_subparsers(dest="cmd",required=True)
    for name in ("validate","digest","inspect"):
        x=sp.add_parser(name); x.add_argument("file")
    a=sp.add_parser("authorize")
    a.add_argument("file"); a.add_argument("--now",required=True); a.add_argument("--delegate-id",required=True)
    a.add_argument("--authority",required=True); a.add_argument("--capability",required=True); a.add_argument("--domain",required=True)
    a.add_argument("--action-id",required=True); a.add_argument("--spend",type=float,default=0)
    a=p.parse_args(argv)
    obj=AuthorityDelegation.from_mapping(json.loads(Path(a.file).read_text()))
    if a.cmd=="validate": print(json.dumps({"ok":True,"delegation_id":obj.delegation_id,"status":obj.status},sort_keys=True))
    elif a.cmd=="digest": print(obj.delegation_digest)
    elif a.cmd=="inspect": print(json.dumps(obj.to_dict(),indent=2,sort_keys=True))
    else:
        ok=authorize(obj,now=a.now,delegate_id=a.delegate_id,authority=a.authority,capability=a.capability,domain=a.domain,action_id=a.action_id,spend=a.spend)
        print(json.dumps({"authorized":ok,"delegation_id":obj.delegation_id},sort_keys=True))


def main(argv=None):
    """Report bad input as a message and an exit code, never as a traceback."""
    try:
        return _main(argv)
    except (OSError, ValueError, DelegationValidationError) as exc:
        print(f"error: {exc}", file=_sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
