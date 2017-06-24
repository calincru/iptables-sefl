import os
import random
import sys

# MPR = Matches Per Rule
# [A, B] the interval to randomly select from
MPR_A = 1
MPR_B = 4

GEN_ROOT_DIR = 'data/generated/'

# We split them into TCP/UDP matches to avoid generating conflicting matches
# within the same rule.

TCP_MATCHES = {
    '--mark': ('-m mark', [
        '0x1/0xffff',
        '0x4000000/0xffff0000',
        '0x2/0xffff',
    ]),
    '-s': ('', [
        '192.168.1.0/24',
        '192.168.2.1',
        '1.1.1.1',
    ]),
    '-d': ('', [
        '8.8.8.8',
        '100.100.100.100',
        '2.2.2.2',
    ]),
    '--dport': ('', [
        '9999',
        '80',
        '22',
    ]),
    '--sport': ('', [
        '9999',
        '80',
        '22',
    ]),
    '-i': ('', [
        'eth0',
        'eth1',
    ]),
    '-o': ('', [
        'eth0',
        'eth1',
    ]),
    '--syn': ('', [
        # No options for --syn.
        ' ',
    ]),
    '--tcp-flags': ('', [
        'SYN,ACK,FIN SYN',
        'SYN,ACK ALL',
        'ALL NONE',
    ]),
}

UDP_MATCHES = {
    '--mark': ('-m mark', [
        '0x1/0xffff',
        '0x4000000/0xffff0000',
        '0x2/0xffff',
    ]),
    '-s': ('', [
        '192.168.1.0/24',
        '192.168.2.1',
        '1.1.1.1',
    ]),
    '-d': ('', [
        '8.8.8.8',
        '100.100.100.100',
        '2.2.2.2',
    ]),
    '--dport': ('', [
        '8081',
        '52',
        '1234',
    ]),
    '--sport': ('', [
        '8081',
        '52',
        '1234',
    ]),
    '-i': ('', [
        'eth0',
        'eth1',
    ]),
    '-o': ('', [
        'eth0',
        'eth1',
    ]),
}


def usage():
    print("Usage:\n\tpython generated_filter_table <num_chains> <num_rules>")
    sys.exit(1)


def main(args):
    """Generates a specified number rules in an iptables filter/FORWARD chain
    by randomly selecting the number of matches in a rule (uniformly between
    [a,b]), negate each one with a 50% probability, randomly selecting matches
    from the MATCHES dict and for each match, random select a value.
    """
    if len(args) != 3:
        usage()

    num_chains = int(args[1])
    num_rules = int(args[2])

    # Create a new dir for this number of rules, if it does not exist already.
    gen_dir = GEN_ROOT_DIR + str(num_rules)
    if not os.path.isdir(gen_dir):
        os.mkdir(gen_dir)

    for i in range(num_chains):
        with open(gen_dir + '/_gen{}'.format(i), 'w') as f:
            accept = random.random() < 0.5
            print('<<filter>>\n\t<FORWARD:' +
                    ('ACCEPT' if accept else 'DROP') + '>', file=f)

            for i in range(num_rules):
                # Find the number of matches to randomly pick.
                num_matches = random.randint(MPR_A, MPR_B)
                # Find *which* matches to use.
                from_tcp = random.random() < 0.5
                match_keys = random.sample(TCP_MATCHES.keys() if from_tcp else
                                            UDP_MATCHES.keys(), num_matches)

                # Construct the rule.
                rule = '\t\t' + ('-p tcp' if from_tcp else '-p udp')
                for match in match_keys:
                    # Load its needed module, if that is the case.
                    module, values = \
                            (TCP_MATCHES if from_tcp else UDP_MATCHES)[match]
                    rule += ' ' + module

                    # Maybe negate it.
                    negate = random.random() < 0.3
                    if negate:
                        rule += ' !'
                    rule += ' ' + match + ' ' + random.choice(values)

                # Pick a target and add it to the rule.
                accept = random.random() < 0.5
                rule += ' -j ' + ('ACCEPT' if accept else 'DROP')

                # Dump the rule to output file.
                print(rule, file=f)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
