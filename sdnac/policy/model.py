class PolicySet(object):
    def __init__(self):
        self.policies = []  # list of Policy
    
    def __str__(self):
        result = ''
        for p in self.policies:
            result += 'BEGIN POLICY' + '\n' + str(p) + 'END POLICY' + '\n'
        return result
    
    def __iter__(self):
        for p in self.policies:
            yield p
    
    def __len__(self):
        return len(self.policies)

class Policy(object):
    def __init__(self):
        self.id = None  # int
        self.name = None  # name
        self.default = None  # 'permit' or 'deny', the default decision of this Policy (note this is opposite of "override" concept)
        self.rules = []  # list of Rule
    
    def __str__(self):
        result = '\tID: ' + str(self.id) + ' NAME: ' + str(self.name) + ' DEFAULT: ' + str(self.default) + '\n'
        for r in self.rules:
            result += str(r) + '\n'
        return result
    
    def __iter__(self):
        for r in self.rules:
            yield r
    
    def __len__(self):
        return len(self.rules)

class Rule(object):
    def __init__(self):
        self.id = None  # int
        self.pid = None  # int, the id of the Policy it belongs
        self.pdefault = None  # 'permit' or 'deny'
        self.priority = None  # int
        self.match = Match()  # Match object
        self.decision = None  # 'permit' or 'deny'
    
    def __str__(self):
        result = '\t\tPID: ' + str(self.pid) + '\n'
        for key, val in self.match.attribute.items():
            result += '\t\t' + key + '=' + val + '\n'
        result += '\t\tDECISION: ' + self.decision + '\n'
        return result
    
    def __iter__(self):
        for k, v in self.match.attribute.items():
            yield k, v
    
    def __len__(self):
        return len(self.match.attribute)
    
    def to_dict(self):
        rdict = dict()
        rdict['id'] = self.id
        rdict['pid'] = self.pid
        rdict['pdefault'] = self.pdefault
        rdict['priority'] = self.priority
        rdict['decision'] = self.decision
        rmatch = dict()
        for key, val in self.match.attribute.items():
            rmatch[key] = val
        rdict['match'] = rmatch
        return rdict

class Match(object):
    def __init__(self):
        # each attribute name can only appear once
        # for AND logic, attribute name will not repeat anyway
        # for OR logic, use multiple Rules
        self.attribute = dict()

