from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json, math, re
from typing import Any, Mapping, Sequence

SCHEMA_VERSION="neuruh.authority-delegation-contract.v0.1"
STATUSES={"active","revoked"}
HEX64=re.compile(r"^[0-9a-f]{64}$")

class DelegationValidationError(ValueError):
    """Fail-closed refusal for malformed, widened, expired, revoked, or replayed delegation authority."""

def canonical_json(value:Any)->str:
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)

def sha256_ref(value:str|bytes)->str:
    if isinstance(value,str): value=value.encode("utf-8")
    return "sha256:"+sha256(value).hexdigest()

def _nonempty(value:Any,name:str)->str:
    if not isinstance(value,str) or not value.strip(): raise DelegationValidationError(f"{name} must be a non-empty string")
    return value

def _sha(value:Any,name:str)->str:
    value=_nonempty(value,name)
    if not value.startswith("sha256:") or not HEX64.fullmatch(value[7:]): raise DelegationValidationError(f"{name} must be sha256:<64 lowercase hex>")
    return value

def _time(value:Any,name:str)->datetime:
    value=_nonempty(value,name)
    try: d=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc: raise DelegationValidationError(f"{name} must be RFC3339/ISO-8601") from exc
    if d.tzinfo is None: raise DelegationValidationError(f"{name} must include a timezone")
    return d.astimezone(timezone.utc)

def _keys(raw:Mapping[str,Any],required:set[str],optional:set[str],context:str)->None:
    missing=sorted(required-set(raw)); unknown=sorted(set(raw)-required-optional)
    if missing: raise DelegationValidationError(f"{context} missing required field(s): {', '.join(missing)}")
    if unknown: raise DelegationValidationError(f"{context} contains unknown field(s): {', '.join(unknown)}")

def _strings(values:Any,name:str,*,allow_empty:bool=False)->tuple[str,...]:
    if not isinstance(values,list): raise DelegationValidationError(f"{name} must be an array")
    out=tuple(_nonempty(v,f"{name} item") for v in values)
    if not allow_empty and not out: raise DelegationValidationError(f"{name} must not be empty")
    if len(out)!=len(set(out)): raise DelegationValidationError(f"{name} must not contain duplicates")
    return out

def _spend(v:Any)->float:
    if isinstance(v,bool) or not isinstance(v,(int,float)): raise DelegationValidationError("max_spend must be numeric")
    x=float(v)
    if not math.isfinite(x) or x<0: raise DelegationValidationError("max_spend must be finite and non-negative")
    return x

@dataclass(frozen=True)
class AuthorityDelegation:
    delegation_id:str
    principal_id:str
    delegate_id:str
    authorities:tuple[str,...]
    capabilities:tuple[str,...]
    domains:tuple[str,...]
    allowed_action_ids:tuple[str,...]
    issued_at:str
    not_before:str
    expires_at:str
    max_spend:float
    can_redelegate:bool
    depth:int
    max_depth:int
    parent_delegation_id:str|None=None
    parent_delegation_digest:str|None=None
    status:str="active"
    revoked_at:str|None=None
    revocation_reason:str|None=None
    delegation_digest:str|None=None

    def body_dict(self)->dict[str,Any]:
        return {
            "schema_version":SCHEMA_VERSION,"delegation_id":self.delegation_id,"principal_id":self.principal_id,"delegate_id":self.delegate_id,
            "authorities":list(self.authorities),"capabilities":list(self.capabilities),"domains":list(self.domains),
            "allowed_action_ids":list(self.allowed_action_ids),"issued_at":self.issued_at,"not_before":self.not_before,"expires_at":self.expires_at,
            "max_spend":self.max_spend,"can_redelegate":self.can_redelegate,"depth":self.depth,"max_depth":self.max_depth,
            "parent_delegation_id":self.parent_delegation_id,"parent_delegation_digest":self.parent_delegation_digest,
            "status":self.status,"revoked_at":self.revoked_at,"revocation_reason":self.revocation_reason,
        }

    def calculated_digest(self)->str: return sha256_ref(canonical_json(self.body_dict()))

    def validate(self,*,check_digest:bool=True)->None:
        for v,n in [(self.delegation_id,"delegation_id"),(self.principal_id,"principal_id"),(self.delegate_id,"delegate_id")]: _nonempty(v,n)
        if self.principal_id==self.delegate_id: raise DelegationValidationError("principal_id and delegate_id must differ")
        for seq,name,empty in [(self.authorities,"authorities",False),(self.capabilities,"capabilities",False),(self.domains,"domains",False),(self.allowed_action_ids,"allowed_action_ids",True)]:
            if not isinstance(seq,tuple): raise DelegationValidationError(f"{name} must be a tuple")
            if not empty and not seq: raise DelegationValidationError(f"{name} must not be empty")
            for x in seq: _nonempty(x,f"{name} item")
            if len(seq)!=len(set(seq)): raise DelegationValidationError(f"{name} must not contain duplicates")
        issued=_time(self.issued_at,"issued_at"); start=_time(self.not_before,"not_before"); exp=_time(self.expires_at,"expires_at")
        if start<issued: raise DelegationValidationError("not_before cannot precede issued_at")
        if exp<=start: raise DelegationValidationError("expires_at must be after not_before")
        _spend(self.max_spend)
        if not isinstance(self.can_redelegate,bool): raise DelegationValidationError("can_redelegate must be boolean")
        if isinstance(self.depth,bool) or not isinstance(self.depth,int) or self.depth<0: raise DelegationValidationError("depth must be a non-negative integer")
        if isinstance(self.max_depth,bool) or not isinstance(self.max_depth,int) or not 0<=self.max_depth<=8: raise DelegationValidationError("max_depth must be integer 0..8")
        if self.depth>self.max_depth: raise DelegationValidationError("depth cannot exceed max_depth")
        if self.can_redelegate and self.depth>=self.max_depth: raise DelegationValidationError("delegation at max_depth cannot permit redelegation")
        if self.depth==0:
            if self.parent_delegation_id is not None or self.parent_delegation_digest is not None:
                raise DelegationValidationError("root delegation cannot name a parent")
        else:
            if self.parent_delegation_id is None or self.parent_delegation_digest is None:
                raise DelegationValidationError("child delegation requires parent id and digest")
            _nonempty(self.parent_delegation_id,"parent_delegation_id"); _sha(self.parent_delegation_digest,"parent_delegation_digest")
            if self.parent_delegation_id==self.delegation_id: raise DelegationValidationError("delegation cannot parent itself")
        if self.status not in STATUSES: raise DelegationValidationError(f"unknown status: {self.status}")
        if self.status=="active":
            if self.revoked_at is not None or self.revocation_reason is not None:
                raise DelegationValidationError("active delegation cannot contain revocation fields")
        else:
            if self.revoked_at is None or self.revocation_reason is None:
                raise DelegationValidationError("revoked delegation requires revoked_at and revocation_reason")
            rev=_time(self.revoked_at,"revoked_at")
            if rev<issued: raise DelegationValidationError("revoked_at cannot precede issued_at")
            _nonempty(self.revocation_reason,"revocation_reason")
        if check_digest:
            if self.delegation_digest is None: raise DelegationValidationError("delegation_digest is required")
            _sha(self.delegation_digest,"delegation_digest")
            if self.delegation_digest!=self.calculated_digest(): raise DelegationValidationError("delegation_digest mismatch")

    def seal(self)->"AuthorityDelegation":
        self.validate(check_digest=False)
        sealed=AuthorityDelegation(**{**self.__dict__,"delegation_digest":self.calculated_digest()})
        sealed.validate(); return sealed

    def to_dict(self)->dict[str,Any]:
        self.validate(); out=self.body_dict(); out["delegation_digest"]=self.delegation_digest; return out

    @classmethod
    def from_mapping(cls,raw:Mapping[str,Any])->"AuthorityDelegation":
        req={"schema_version","delegation_id","principal_id","delegate_id","authorities","capabilities","domains","allowed_action_ids","issued_at","not_before","expires_at","max_spend","can_redelegate","depth","max_depth","parent_delegation_id","parent_delegation_digest","status","revoked_at","revocation_reason","delegation_digest"}
        _keys(raw,req,set(),"delegation")
        if raw["schema_version"]!=SCHEMA_VERSION: raise DelegationValidationError("unsupported schema_version")
        obj=cls(
            delegation_id=_nonempty(raw["delegation_id"],"delegation_id"),principal_id=_nonempty(raw["principal_id"],"principal_id"),delegate_id=_nonempty(raw["delegate_id"],"delegate_id"),
            authorities=_strings(raw["authorities"],"authorities"),capabilities=_strings(raw["capabilities"],"capabilities"),domains=_strings(raw["domains"],"domains"),
            allowed_action_ids=_strings(raw["allowed_action_ids"],"allowed_action_ids",allow_empty=True),issued_at=_nonempty(raw["issued_at"],"issued_at"),
            not_before=_nonempty(raw["not_before"],"not_before"),expires_at=_nonempty(raw["expires_at"],"expires_at"),max_spend=_spend(raw["max_spend"]),
            can_redelegate=raw["can_redelegate"],depth=raw["depth"],max_depth=raw["max_depth"],parent_delegation_id=raw["parent_delegation_id"],
            parent_delegation_digest=raw["parent_delegation_digest"],status=_nonempty(raw["status"],"status"),revoked_at=raw["revoked_at"],
            revocation_reason=raw["revocation_reason"],delegation_digest=_sha(raw["delegation_digest"],"delegation_digest"),
        ); obj.validate(); return obj

def create_root_delegation(*,delegation_id:str,principal_id:str,delegate_id:str,authorities:Sequence[str],capabilities:Sequence[str],domains:Sequence[str],allowed_action_ids:Sequence[str]=(),issued_at:str,not_before:str,expires_at:str,max_spend:float=0,can_redelegate:bool=False,max_depth:int=0)->AuthorityDelegation:
    return AuthorityDelegation(delegation_id,principal_id,delegate_id,tuple(authorities),tuple(capabilities),tuple(domains),tuple(allowed_action_ids),issued_at,not_before,expires_at,_spend(max_spend),can_redelegate,0,max_depth).seal()

def verify_child(parent:AuthorityDelegation,child:AuthorityDelegation)->bool:
    parent.validate(); child.validate()
    if parent.status!="active": raise DelegationValidationError("revoked parent cannot authorize child")
    if not parent.can_redelegate: raise DelegationValidationError("parent does not permit redelegation")
    if child.parent_delegation_id!=parent.delegation_id or child.parent_delegation_digest!=parent.delegation_digest:
        raise DelegationValidationError("child parent binding mismatch")
    if child.principal_id!=parent.delegate_id: raise DelegationValidationError("child principal must be parent delegate")
    if child.delegate_id in {parent.principal_id,parent.delegate_id}: raise DelegationValidationError("child delegate creates immediate delegation cycle/self-delegation")
    if child.depth!=parent.depth+1: raise DelegationValidationError("child depth mismatch")
    if child.max_depth!=parent.max_depth: raise DelegationValidationError("child cannot change max_depth")
    if not set(child.authorities).issubset(parent.authorities): raise DelegationValidationError("child widens authority")
    if not set(child.capabilities).issubset(parent.capabilities): raise DelegationValidationError("child widens capability scope")
    if not set(child.domains).issubset(parent.domains): raise DelegationValidationError("child widens domain scope")
    if parent.allowed_action_ids and not set(child.allowed_action_ids).issubset(parent.allowed_action_ids): raise DelegationValidationError("child widens action scope")
    if child.max_spend>parent.max_spend: raise DelegationValidationError("child widens spend authority")
    if _time(child.not_before,"child not_before") < _time(parent.not_before,"parent not_before"): raise DelegationValidationError("child starts before parent")
    if _time(child.expires_at,"child expires_at") > _time(parent.expires_at,"parent expires_at"): raise DelegationValidationError("child outlives parent")
    if child.issued_at < parent.issued_at: raise DelegationValidationError("child issued_at precedes parent issued_at")
    return True

def derive_delegation(parent:AuthorityDelegation,*,delegation_id:str,delegate_id:str,authorities:Sequence[str],capabilities:Sequence[str],domains:Sequence[str],allowed_action_ids:Sequence[str]=(),issued_at:str,not_before:str,expires_at:str,max_spend:float=0,can_redelegate:bool=False)->AuthorityDelegation:
    parent.validate()
    child=AuthorityDelegation(
        delegation_id=delegation_id,principal_id=parent.delegate_id,delegate_id=delegate_id,authorities=tuple(authorities),capabilities=tuple(capabilities),domains=tuple(domains),
        allowed_action_ids=tuple(allowed_action_ids),issued_at=issued_at,not_before=not_before,expires_at=expires_at,max_spend=_spend(max_spend),
        can_redelegate=can_redelegate,depth=parent.depth+1,max_depth=parent.max_depth,parent_delegation_id=parent.delegation_id,parent_delegation_digest=parent.delegation_digest
    ).seal()
    verify_child(parent,child); return child

def revoke_delegation(delegation:AuthorityDelegation,*,revoked_at:str,reason:str)->AuthorityDelegation:
    delegation.validate()
    if delegation.status!="active": raise DelegationValidationError("only active delegation can be revoked")
    return AuthorityDelegation(**{**delegation.__dict__,"status":"revoked","revoked_at":revoked_at,"revocation_reason":reason,"delegation_digest":None}).seal()

def authorize(delegation:AuthorityDelegation,*,now:str,delegate_id:str,authority:str,capability:str,domain:str,action_id:str,spend:float=0)->bool:
    delegation.validate()
    if delegation.status!="active": raise DelegationValidationError("delegation is revoked")
    current=_time(now,"now"); start=_time(delegation.not_before,"not_before"); exp=_time(delegation.expires_at,"expires_at")
    if current<start: raise DelegationValidationError("delegation not active yet")
    if current>exp: raise DelegationValidationError("delegation has expired")
    if delegate_id!=delegation.delegate_id: raise DelegationValidationError("delegate identity mismatch")
    if authority not in delegation.authorities: raise DelegationValidationError("authority not delegated")
    if capability not in delegation.capabilities: raise DelegationValidationError("capability not delegated")
    if domain not in delegation.domains: raise DelegationValidationError("domain not delegated")
    if delegation.allowed_action_ids and action_id not in delegation.allowed_action_ids: raise DelegationValidationError("action_id outside delegated scope")
    if _spend(spend)>delegation.max_spend: raise DelegationValidationError("spend exceeds delegated maximum")
    return True
