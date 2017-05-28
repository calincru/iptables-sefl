import sys


TABLE_NAMES = ['raw', 'mangle', 'nat', 'filter']


def main(args):
    index_of = lambda fn: \
        next((i for i, tn in enumerate(TABLE_NAMES) if tn in fn), None)
    table_files = sorted(args[1:], key=index_of)

    tables = {}
    for i, table_file in enumerate(table_files):
        curr_table = {}

        with open(table_file, mode='r') as f:
            for line in f:
                tokens = line.split()
                if tokens[0] == '-P':
                    curr_table[tokens[1]] = {
                            'default_policy': tokens[2],
                            'rules': []
                    }
                elif tokens[0] == '-N':
                    curr_table[tokens[1]] = {
                            'rules': []
                    }
                elif tokens[0] == '-A':
                    curr_table[tokens[1]]['rules'].append(' '.join(tokens[2:]))
                else:
                    raise Exception('Unknown iptables command!')
        tables[TABLE_NAMES[i]] = curr_table

    with open('iptables.out', mode='w') as f:
        for table_name, chains in tables.items():
            print('<<{}>>'.format(table_name), file=f)
            for chain_name, chain_data in chains.items():
                if 'default_policy' in chain_data:
                    print('<{}:{}>'.format(chain_name,
                                           chain_data['default_policy']),
                          file=f)
                else:
                    print('<{}>'.format(chain_name), file=f)
                for rule in chain_data['rules']:
                    print(rule, file=f)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
