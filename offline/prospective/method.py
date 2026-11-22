"""Query-local proof obligations for the frozen finite attribution contract.

Ordinary augmenting-path matching is used, not claimed as a new algorithm.
Input validation and policy formatting are shared with B1; inference is separate.
The exact enumeration reference and corpus are not imported or inspected here.
"""
from __future__ import annotations
import copy,time
from baseline import _validate, _authorize

PRE=('rule_empty','tcp_failed','health_ok','order_ok')
POST=('new_tcp','http_ok','order_ok')

def solve(case):
    start=time.perf_counter_ns()
    try:_validate(case)
    except (ValueError,TypeError) as e:
        return {'method':'M','status':'INVALID_INPUT','processing':'INVALID_INPUT','effect':'INVALID_INPUT','authorization':'INVALID_INPUT','blockers':[str(e)],'cost':{}}
    q=case['query'];qo=('request',q);rs={r['id']:r for r in case['requests']};acts={a['id']:a for a in case['actions']};c=case['contract'];cap=c['single_action_per_request']
    processing=rs[q]['processing'] if q in rs else 'NO_TARGET_RECORD' if c['owners_complete'] else 'UNKNOWN'
    domains={}
    for a in acts.values():
        d={('request',rid) for rid in a['candidates'] if rs[rid]['processing']!='REJECTED'}
        if not c['owners_complete'] and not a['hard_parent']:d.add(('external',a['id']))
        domains[a['id']]=d
    cost={'matching_checks':0,'edge_visits':0,'requests':len(rs),'actions':len(acts),'candidate_edges':sum(map(len,domains.values()))}
    def feasible(force=None,forbid=frozenset()):
        cost['matching_checks']+=1
        ds={a:{o for o in d if (a,o) not in forbid} for a,d in domains.items()}
        if force:
            a,o=force
            if o not in ds.get(a,set()):return False,None
            ds[a]={o}
            if cap:
                for other in ds:
                    if other!=a:ds[other].discard(o)
        if any(not d for d in ds.values()):return False,None
        if not cap:return True,{a:min(d) for a,d in ds.items()}
        owner_to_act={}
        def aug(a,seen):
            for o in sorted(ds[a]):
                cost['edge_visits']+=1
                if o in seen:continue
                seen.add(o)
                if o not in owner_to_act or aug(owner_to_act[o],seen):
                    owner_to_act[o]=a;return True
            return False
        for a in sorted(ds,key=lambda a:(len(ds[a]),a)):
            if not aug(a,set()):return False,None
        return True,{a:o for o,a in owner_to_act.items()}
    ok,first=feasible()
    def fmt(m):return {a:(o[1] if o[0]=='request' else 'EXTERNAL_FOR_ACTION:'+o[1]) for a,o in (m or {}).items()}
    if not ok:
        cost['elapsed_ns']=time.perf_counter_ns()-start
        return {'method':'M','status':'CONFLICT','processing':'CONFLICT','effect':'CONFLICT','authorization':'CONFLICT','blockers':['no_feasible_assignment'],'cost':cost,'witness':{'candidate_domains':{a:[list(o) for o in sorted(d)] for a,d in domains.items()}}}
    success_true=[a for a in acts if acts[a]['success'] is True]
    avoid={(a,qo) for a in success_true}
    can_avoid,negative=feasible(forbid=avoid)
    must=not can_avoid
    positive=None;positive_action=None
    for a in acts:
        if acts[a]['success'] is not False and qo in domains[a]:
            possible,m=feasible(force=(a,qo))
            if possible:positive=m;positive_action=a;break
    may=positive is not None
    hidden=False
    if not c['actions_complete'] and q in rs and processing!='REJECTED':
        if not cap:hidden=True;hidden_assignment=first
        else:
            hidden,hidden_assignment=feasible(forbid={(a,qo) for a in acts})
        if hidden and positive is None:positive=hidden_assignment
        may=may or hidden
    missing=[f'{group}.{key}' for group,ks in [('pre',PRE),('post',POST)] for key in ks if case.get(group,{}).get(key) is not True]
    blockers=[];other_possible=False;other_example=None
    qresource=rs[q].get('resource') if q in rs else None
    # Probe alternatives only when the other reopening obligations are met.
    if must and not missing and c['owners_complete'] and c['actions_complete']:
        for a in acts:
            if acts[a]['success'] is False or acts[a].get('resource',qresource)!=qresource:continue
            for owner in sorted(domains[a]-{qo}):
                possible,m=feasible(force=(a,owner))
                if possible:other_possible=True;other_example=fmt(m);break
            if other_possible:break
    if processing=='UNKNOWN':effect='UNKNOWN';blockers.append('target_processing_unobserved')
    elif processing=='NO_TARGET_RECORD':effect='NO_TARGET_ACTION'
    elif must:
        effect='REOPENED' if not missing and c['owners_complete'] and c['actions_complete'] and not other_possible else 'ACTION_ONLY'
    elif not may:effect='NO_TARGET_ACTION'
    else:effect='UNKNOWN'
    if must and effect!='REOPENED':
        blockers+=['missing:'+v for v in missing]
        if not c['owners_complete']:blockers.append('owner_capture_not_complete')
        if not c['actions_complete']:blockers.append('action_capture_not_complete')
        if other_possible:blockers.append('other_successful_writer_possible')
    if effect=='UNKNOWN':
        if hidden:blockers.append('unobserved_target_action_permitted')
        if may and not must:blockers.append('both_target_success_and_non_success_feasible')
    auth=_authorize(effect,case,blockers)
    cost['elapsed_ns']=time.perf_counter_ns()-start
    projection_applicable=q in rs and processing!='UNKNOWN'
    return {'method':'M','status':'OK','processing':processing,'effect':effect,'authorization':auth,'projection_applicable':projection_applicable,'must_success':must if projection_applicable else None,'may_success':may if projection_applicable else None,'internal_projection':{'must_success':must,'may_success':may},'blockers':blockers,'coverage':copy.deepcopy(c),'cost':cost,'witness':{'one_feasible_assignment':fmt(first),'avoid_target_success_feasible':can_avoid,'avoid_target_success_assignment':fmt(negative) if can_avoid else None,'target_success_assignment':fmt(positive) if may else None,'target_success_action':positive_action,'hidden_success_possible':hidden,'other_writer_assignment':other_example,'certificate_scope':'declared finite assignment and observation contract, not an unconditional causal theorem'}}

def ablate(case,component):
    x=copy.deepcopy(case)
    if component=='identity':
        for a in x['actions']:
            a['candidates']=list(a.get('coarse_candidates',a['candidates']));a['hard_parent']=False
    elif component=='coverage':x['contract']['owners_complete']=True;x['contract']['actions_complete']=True
    elif component=='lifecycle':
        for k in PRE:x['pre'][k]=True
        for k in POST:x['post'][k]=True
    else:raise ValueError(component)
    result=solve(x);result['method']='M_without_'+component;result['ablated_obligation']=component
    return result
