import sys


TABLE_NAMES = ['raw', 'mangle', 'nat', 'filter']


def main(args):
    index_of = lambda fn: \
        next((i for i, tn in enumerate(TABLE_NAMES) if tn in fn), None)
    table_files = sorted(args[1:], key=index_of)

    tables = {}
    for i, table_file in enumerate(table_files):
        # TODO: Implement this.
        pass


if __name__ == '__main__':
    sys.exit(main(sys.argv))
