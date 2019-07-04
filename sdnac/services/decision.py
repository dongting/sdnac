import scapy.all
import base64

import crypto
import capability

META_KEY = 'meta'
CAP_KEY = 'capability'
BODY_KEY = 'body'
PERMIT = 'permit'
DENY = 'deny'
UNKNOWN = 'unknown'
RULE_KEY = 'rule'

def evaluate(req, policy=None):
    '''
    evaluate a new request to see if it should be permitted or denied
    the request can optionally contain a signed capability
    '''
    if CAP_KEY in req[META_KEY]:
        # using signed capabilities, skip the queue
        return eval_with_cap(req, req[META_KEY][CAP_KEY], policy.fast_match)
    else:
        return eval_without_cap(req, policy.fast_match, issue_cap=True)

def eval_without_cap(req, fast_match, issue_cap=True):
    match_bucket = set()
    # subject
    for key, val in req[META_KEY].items():
        sub_key = 'subject.' + key
        match_bucket.update(get_rule(sub_key, val, fast_match))
    
    # action
    for key, val in req[BODY_KEY].items():
        of_op = 'resource.' + key
        match_bucket.update(get_rule(of_op, 'true', fast_match))
        break  # there should be only one
    
    # object
    flat_body = flatten_body(req[BODY_KEY], 'resource')
    # print flat_body
    for key, vals in flat_body.items():
        # vals are attributes, and can be a list,
        # e.g. 'subject.type': ['app', 'vip']
        if key in fast_match:
            if isinstance(vals, list):
                for val in vals:
                    match_bucket.update(get_rule(key, val, fast_match))
            else:
                match_bucket.update(get_rule(key, vals, fast_match))
    
    # specifics
    if 'resource.OFPPacketIn.data' in flat_body:
        ether_raw = base64.b64decode(flat_body['resource.OFPPacketIn.data'][0])
        ether = scapy.all.Ether(ether_raw)
        pfx = 'resource.OFPPacketIn'
        # print ether.src, ether.dst
        match_bucket.update(get_rule(pfx+'.dl_src', ether.src, fast_match))
        match_bucket.update(get_rule(pfx+'.dl_dst', ether.dst, fast_match))
        match_bucket.update(get_rule(pfx+'.ethertype', str(hex(ether.type)), fast_match))
        if ether.haslayer(scapy.all.IP):
            ip = ether.getlayer(scapy.all.IP)
            # print ip.src, ip.dst, ip.proto
            match_bucket.update(get_rule(pfx+'.nw_src', ip.src, fast_match))
            match_bucket.update(get_rule(pfx+'.nw_dst', ip.dst, fast_match))
            match_bucket.update(get_rule(pfx+'.nw_proto', ip.proto, fast_match))
        if ether.haslayer(scapy.all.UDP):
            udp = ether.getlayer(scapy.all.UDP)
            # print udp.sport, udp.dport
            match_bucket.update(get_rule(pfx+'.tp_src', udp.sport, fast_match))
            match_bucket.update(get_rule(pfx+'.tp_dst', udp.dport, fast_match))
            # if udp.dport == 8008 or udp.sport == 8008:
                # print udp.load

    if 'resource.OFPPacketOut.data' in flat_body:
    #     ether_raw = base64.b64decode(flat_body['resource.OFPPacketOut.data'][0])
    #     ether = scapy.all.Ether(ether_raw)
    #     print ether
        pfx = 'resource.OFPPacketOut'
        buffer_id = flat_body[pfx+'.buffer_id']
        if buffer_id != -1:  # OF specification
            match_bucket.update(get_rule(pfx+'.buffer_id', 'true', fast_match))
    # if 'resource.OFPFlowMod.priority' in flat_body:
    #     print flat_body['resource.OFPFlowMod']
    
    # now we have a set of rules and we want to get each's decision
    rules = list(match_bucket)
    # print rules
    pid = None
    pdefault = DENY
    decisions = []
    # TODO: also consider rule.priority value
    for rule in rules:
        # special case for when rule comes from cap
        if isinstance(rule, dict):
            return (PERMIT, None)
        
        # regular case (rule of type Rule):
        # if rules come from different Policys, then error
        if pid is None:
            pid = rule.pid
            pdefault = rule.pdefault
        elif rule.pid != pid:
            return (UNKNOWN, None)
        decisions.append((rule.decision, rule))
    for decision, rule in decisions:
        if decision != pdefault:
            # cap = capability.issue(rule.to_dict())
            new_cap = None
            if issue_cap:
                cap = capability.issue(rule.to_dict())
            return (decision, new_cap)
    return (pdefault, None)

def eval_with_cap(req, cap, fast_match):
    '''
    we iterate through the cap to find a match, if matched then return permit
    (we can possibly just return a deny instead of falling back to lookup)
    '''
    # if 'OFPPacketIn' in req[BODY_KEY] and 'data' in req[BODY_KEY]['OFPPacketIn']:
    #     ether_raw = base64.b64decode(req[BODY_KEY]['OFPPacketIn']['data'])
    #     ether = scapy.all.Ether(ether_raw)
    #     if ether.haslayer(scapy.all.UDP):
    #         udp = ether.getlayer(scapy.all.UDP)
    #     else:
    #         print 'no'
    # else:
    #     print 'no'
    
    cap_body = crypto.check_cap(req, cap)
    if cap_body:
        # checks the signature but not the content
        if isinstance(cap_body, list):
            for c in cap_body:
                result = match_cap(req, c)
                if result is True:
                    return 'permit', cap
        elif isinstance(cap_body, dict):
            result = match_cap(req, cap_body)
            if result is True:
                return 'permit', cap
        return 'deny', cap
    else:
        return eval_without_cap(req, fast_match, issue_cap=True)

def match_cap(req, cap_body):
    # use existing code from eval_without_cap
    fast_match = dict()
    rule = cap_body[RULE_KEY]  # this is a dict not a Rule type
    
    for key, val in rule['match'].items():
        if key not in fast_match:
            fast_match[key] = dict()
        if val not in fast_match[key]:
            fast_match[key][val] = []
        fast_match[key][val].append(rule)
    return eval_without_cap(req, fast_match, issue_cap=False)

def flatten_body(rbody, prefix):
    '''
    transforms a nested request body (in jsondict) to a flat dict
    where each val is a list of primitive types without nesting
    '''
    fbody = dict()
    if isinstance(rbody, dict):
        for key, val in rbody.items():
            if prefix == '':
                adjusted_key = key
            else:
                adjusted_key = prefix + '.' + key
            rec_fbody = flatten_body(val, adjusted_key)
            for rkey, rval in rec_fbody.items():
                if rkey not in fbody:
                    fbody[rkey] = []
                fbody[rkey].extend(rval)
    elif isinstance(rbody, list):
        adjusted_key = prefix
        for elt in rbody:
            rec_fbody = flatten_body(elt, adjusted_key)
            for rkey, rval in rec_fbody.items():
                if rkey not in fbody:
                    fbody[rkey] = []
                fbody[rkey].extend(rval)
    else:
        adjusted_key = prefix
        if adjusted_key not in fbody:
            fbody[adjusted_key] = []
        fbody[adjusted_key].append(rbody)
    return fbody

def get_rule(key, val, fm):
    rules = set()
    sval = str(val)
    if key in fm and sval in fm[key]:
        rule = fm[key][sval]
        if rule is not None:
            if isinstance(rule, list):
                for elt in rule:
                    rules.add(elt)
            else:
                rules.add(rule)
    return rules

def get_last_mobj(mobj, key):
    '''
    recursively deconstruct and compare if the incoming request (key) has a match in my policy's matching pattern (mobj)
    '''
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

def get_mobj_rule(mobj, val):
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

