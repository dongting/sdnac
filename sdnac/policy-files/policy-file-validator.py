import sys

if len(sys.argv) <= 1:
    print 'Usage: python policy_file_validator.py <policy_file>'
    sys.exit()

fname = sys.argv[1]

policies = []
policy = None
with open(fname, 'r') as f:
    for line in f:
        line = line.strip()
        if len(line) == 0:
            continue
        if line[0] == '#':
            continue
        if line[0] == '[':
            policy = dict()
            policy['id'] = None
            policy['name'] = None
            policy['default'] = None
            policy['rules'] = []
            policies.append(policy)
            
            title = line.lstrip('[').rstrip(']')
            for elt in title.split(','):
                key, val = elt.split('=')
                policy[key] = val
        else:
            if policy is None:
                continue
            rule = dict()
            rule['id'] = None
            rule['priority'] = None
            rule['match'] = dict()
            rule['decision'] = None
            
            for elt in line.split(','):
                try:
                    key, val = elt.split('=')
                    if key == 'decision' or key == 'priority' or key == 'id':
                        rule[key] = val
                    else:
                        rule['match'][key] = val
                except ValueError:
                    # presence match doesn't need '='
                    rule['match'][elt] = 'true'
            policy['rules'].append(rule)
    for p in policies:
        for r in p['rules']:
            print r

