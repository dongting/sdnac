import json
from model import * 

class Parser(object):
    def __init__(self, policy_file):
        self.policy_file = policy_file
        self.policyset = self.parse()
    
    def get_policyset(self):
        return self.policyset
    
    def parse(self):
        # returns the object version of policy_file, type PolicySet
        policyset = PolicySet()
        policy = None
        with open(self.policy_file, 'r') as f:
            for line in f:
                line = line.strip()
                if len(line) == 0:
                    continue
                if line[0] == '#':
                    continue
                if line[0] == '[':
                    policy = Policy()
                    policyset.policies.append(policy)
                    
                    title = line.lstrip('[').rstrip(']')
                    for elt in title.split(','):
                        key, val = elt.split('=')
                        setattr(policy, key, val)
                else:
                    if policy is None:
                        continue
                    rule = Rule()
                    rule.pid = policy.id
                    rule.pdefault = policy.default
                    
                    for elt in line.split(','):
                        key, val = elt.split('=')
                        if key == 'decision' or key == 'priority' or key == 'id':
                            setattr(rule, key, val)
                        else:
                            rule.match.attribute[key] = val
                    policy.rules.append(rule)
        return policyset
    
    def serialize(self, pobj):
        # returns the serialized version (i.e. string) of object
        pass
    