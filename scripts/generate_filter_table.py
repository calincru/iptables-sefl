import random
import sys

# MPR = Matches Per Rule
# [A, B] the interval to randomly select from
MPR_A = 1
MPR_B = 4

GEN_ROOT_DIR = 'data/generated/'

MATCHES = {
    '-m mark --mark': [
        '0x1/0xffff',
    ],
    '-p tcp --dport': [
        '9999',
        '80',
        '22',
    ],
    '-i': [
        'eth0',
        'eth1',
    ],
    '-o': [
        'eth0',
        'eth1',
    ],
}


def main(args):
    """Generates a specified number rules in an iptables filter/FORWARD chain
    by randomly selecting the number of matches in a rule (uniformly between
    [a,b]), negate each one with a 50% probability, randomly selecting matches
    from the MATCHES dict and for each match, random select a value.
    """
    assert len(args) == 3

    num_chains = int(args[1])
    num_rules = int(args[2])

    for i in range(num_chains):
        with open(GEN_ROOT_DIR + '_gen{}'.format(i), 'w') as f:
            accept = random.random() < 0.5
            print('<<filter>>\n\t<FORWARD:' +
                    ('ACCEPT' if accept else 'DROP') + '>', file=f)

            for i in range(int(args[1])):
                rule = '\t\t'

                # Find the number of matches to randomly pick.
                num_matches = random.randint(MPR_A, MPR_B)
                # Find *which* matches to use.
                match_keys = random.sample(MATCHES.keys(), num_matches)

                for match in match_keys:
                    # Build a new match.
                    negate = random.random() < 0.5
                    if negate:
                        rule += ' !'
                    rule += ' ' + match + ' ' + random.choice(MATCHES[match])

                # Pick a target and add it to the rule.
                accept = random.random() < 0.5
                rule += ' -j ' + ('ACCEPT' if accept else 'DROP')

                # Dump the rule to output file.
                print(rule, file=f)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
