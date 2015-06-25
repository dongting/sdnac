from model import * 
import json_parser as parser
import json # for debugging

TYPES = ['subject', 'resource', 'action', 'environment']  # corresponds to model.py

class PolicyEngine(object):
    def __init__(self, policy_file):
        self.fast_match = dict()
        self.pobj = parser.Parser(policy_file)
        self.policyset = self.pobj.get_policyset()
        self.load_policyset()
        
        print self.policyset
        # for p in self.policyset:
        #     for r in p:
        #         for key, val in r:
        #             print str(key) + '=' + str(val)
        # print self.fast_match
    
    def policyset_to_str(self, obj):
        return self.pobj.serialize(obj)
    
    def load_policyset(self):
        '''
        fast_match converts a mapping of (key, val) in the format of
        a.b.c.d=val
        where a.b.c.d forms the key in a hierarchical form
        and converts it to fast_match[a][b][c][d][val]=rule (note last element val)
        so given an incoming request we can quickly identify relevant rules
        '''
        # load an policyset object into memory for fast matching
        for policy in self.policyset.policies:
            #pid = policy.id
            #pdefault = policy.default
            for rule in policy.rules:
                #rid = rule.id
                #rpriority = rule.priority
                rmatch = rule.match
                #raction = rule.action
                for key, val in rmatch.attribute.items():
                    if key not in self.fast_match:
                        self.fast_match[key] = dict()
                    if val not in self.fast_match[key]:
                        self.fast_match[key][val] = []
                    self.fast_match[key][val].append(rule)
    
    def get_policyset(self):
        return self.policyset
    
    def get_policy_for_app(self, app):
        return self.fast_match['subject']['app'][app]
    
    def get_policy_for_switch(self, switch):
        return self.fast_match['subject']['switch'][switch]
    
    def get_policy_for_ipblock(self, ipblock):
        pass


