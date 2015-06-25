from crypto import *

CAP_KEY = 'capability'
BODY_KEY = 'body'
PERMIT = 'permit'
DENY = 'deny'
UNKNOWN = 'unknown'

def evaluate(req, policy=None):
    '''
    evaluate a new request to see if it should be permitted or denied
    the request can optionally contain a signed capability
    '''
    if CAP_KEY in req:
        # using signed capabilities, skip the queue
        return eval_with_cap(req, req[CAP_KEY])
    else:
        return eval_without_cap(req, policy)

def eval_without_cap(req, policy):
    '''
    see policy/policy.py for fast_match construction
    this function uses policy.fast_match to quickly get relevant rules
    then dedup rules, and get the decision according to each rule
    '''
    match_bucket = set()
    for key, vals in req[BODY_KEY].items():
        # vals are attributes, and can be a list,
        # e.g. 'subject.type': ['app', 'vip']
        last_mobj = get_last_mobj(policy.fast_match, key)
        if last_mobj is None:
            continue
        if isinstance(vals, list):
            for val in vals:
                rule = get_rule(last_mobj, val)
                if rule is not None:
                    match_bucket.add(rule)
        else:
            rule = get_rule(last_mobj, vals)
            if rule is not None:
                match_bucket.add(rule)
    # now we have a set of rules and we want to get each's decision
    rules = list(match_bucket)
    pid = None
    pdefault = get_pdefault(policy)
    decisions = []
    # TODO: also consider rule.priority value
    for rule in rules:
        print type(rule)
        # if rules come from different Policys, then error
        if pid is None:
            pid = rule.pid
            pdefault = rule.pdefault
        elif rule.pid != pid:
            return UNKNOWN
        decisions.append((rule.decision, rule))
    for decision, rule in decisions:
        if decision != pdefault:
            return decision
    return pdefault

def eval_with_cap(req, cap):
    if not check_sig(cap):
        # should we disregard the cap and go through the normal process?
        return
    if not check_expire(cap):
        # capability is expired, so we renew for them
        # the new cap may be different!
        cap = renew_cap(cap)
    # TODO

def get_last_mobj(mobj, key):
    keys = key.split('.', 1)
    if len(keys) == 1:
        # base case
        if keys[0] in mobj:
            return mobj[keys[0]]
    elif len(keys) == 2:
        if keys[0] in mobj:
            return get_last_mobj(mobj[keys[0]], keys[1])
    # 0 or >2 for some reason
    return None

def get_rule(mobj, val):
    if val in mobj:
        return mobj[val]
    return None

def get_pdefault(policy):
    pset = policy.get_policyset()
    if len(pset) == 0:
        return None
    pdefault = None
    for p in pset:
        if pdefault is None:
            pdefault = p.default
        elif p.default != pdefault:
            return None
    return pdefault

