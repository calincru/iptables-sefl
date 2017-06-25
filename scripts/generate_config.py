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

COMMON_MATCHES = {
    '--mark': ('-m mark', [
        '0x1/0xffff',
        '0x4000000/0xffff0000',
        '0x2/0xffff',
        '0x3/0xffff',
    ]),
    '--ctstate': ('-m conntrack', [
        'NEW',
        'ESTABLISHED',
        'DNAT',
        'SNAT',
    ]),
    '-s': ('', [
        '192.168.1.0/24',
        '192.168.2.1',
        '192.168.1.3',
        '1.1.1.1',
        '8.8.8.8',
    ]),
    '-d': ('', [
        '8.8.8.8',
        '100.100.100.100',
        '192.168.1.3',
        '1.1.1.1',
        '2.2.2.2',
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

TCP_MATCHES = {
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
}

TABLES = {
    'filter': (
        ['INPUT', 'FORWARD'],
        {
            'ACCEPT': [' '],
            'DROP': [' '],
        },
    ),
    'mangle': (
        # Ignoring INPUT/FORWARD/OUTPUT for now.
        ['PREROUTING', 'POSTROUTING'],
        {
            'MARK': [
                '--set-xmark 0x1/0xffff',
                '--set-xmark 0x2/0xffff',
                '--set-mark 0x3/0xffff',
                '--set-mark 0x4/0xffff',
            ],
            'CONNMARK': [
                '--save-mark --nfmask 0xffff000 --ctmask 0xffff0000',
                '--save-mark --nfmask 0x000ffff --ctmask 0x0000ffff',
                '--restore-mark --nfmask 0xffff000 --ctmask 0xffff0000',
                '--restore-mark --nfmask 0x000ffff --ctmask 0x0000ffff',
            ],
        },
    ),
    'nat': (
        ['PREROUTING', 'POSTROUTING'],
        {
            'SNAT': [
                '--to-source 203.0.113.103',
                '--to-source 8.8.8.8',
                '--to-source 203.0.113.0/24',
                '--to-source 1.1.1.1',
            ],
            'DNAT': [
                '--to-destination 192.168.1.0/24',
                '--to-destination 192.168.1.3',
                '--to-destination 192.168.1.2',
            ],
            'MASQUERADE': [
                ' ',
                '--to-ports 50000-55000',
                '--to-ports 10000-15000',
                '--to-ports 80-1000',
            ],
            'REDIRECT': [
                '--to-ports 9697-10000',
                '--to-ports 80-81',
            ],
        },
    ),
}


def usage():
    print("Usage:\n\tpython generated_filter_table <num_chains> <num_rules>")
    sys.exit(1)


def is_valid_match(match, table, chain):
    if match == '-i':
        if chain not in ['INPUT', 'FORWARD', 'PREROUTING']:
            return False
    if match == '-o':
        if chain not in ['OUTPUT', 'FORWARD', 'POSTROUTING']:
            return False
    return True


def is_valid_target(target, table, chain):
    if target == 'MARK':
        if chain != 'PREROUTING':
            return False;
    if target == 'SNAT':
        if chain != 'POSTROUTING':
            return False
    if target == 'DNAT':
        if chain not in ['PREROUTING', 'OUTPUT']:
            return False
    if target == 'REDIRECT':
        if chain not in ['PREROUTING', 'OUTPUT']:
            return False
    if target == 'MASQUERADE':
        if chain not in ['POSTROUTING']:
            return False
    return True


def generate_table(
        table_name,
        tcp_matches,
        udp_matches,
        num_rules,
        config_file):
    chains, targets = TABLES[table_name]

    print('<<{}>>'.format(table_name), file=config_file)
    for chain in chains:
        accept = random.random() < 0.5
        print('\t<{}:{}>'.format(chain, ('ACCEPT' if accept else 'DROP')),
              file=config_file)

        for i in range(num_rules):
            # Find the number of matches to randomly pick.
            num_matches = random.randint(MPR_A, MPR_B)
            # Find *which* matches to use.
            from_tcp = random.random() < 0.5
            matches = tcp_matches if from_tcp else udp_matches
            match_keys = random.sample(matches.keys(), num_matches)

            # Construct the rule.
            rule = '\t\t' + ('-p tcp' if from_tcp else '-p udp')
            for match in match_keys:
                if not is_valid_match(match, table_name, chain):
                    continue

                # Load its needed module, if that is the case.
                module, values = matches[match]
                rule += ' ' + module

                # Maybe negate it.
                negate = random.random() < 0.3
                if negate:
                    rule += ' !'
                rule += ' {} {}'.format(match, random.choice(values))

            # Pick a target and add it to the rule.
            while True:
                target = random.choice(list(targets.keys()))
                if is_valid_target(target, table_name, chain):
                    rule += ' -j {} {}'.format(target,
                                               random.choice(targets[target]))
                    break

            # Dump the rule to output file.
            print(rule, file=config_file)


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

    tcp_matches = {**COMMON_MATCHES, **TCP_MATCHES}
    udp_matches = {**COMMON_MATCHES, **UDP_MATCHES}

    for i in range(num_chains):
        with open(gen_dir + '/_gen{}'.format(i), 'w') as f:
            # Generate rules for each table.
            generate_table('filter', tcp_matches, udp_matches, num_rules, f)
            # generate_table('nat', tcp_matches, udp_matches, 2, f)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
