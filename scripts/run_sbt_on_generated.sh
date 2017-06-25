#!/bin/bash

GEN_ROOT_DIR="data/generated"

function usage {
  echo -e "Usage\n\t./scripts/run_sbt_on_generated.sh <num_rules>"
  exit 1
}

function run_tests {
  echo "" >/tmp/sbt-commands
  root_dir=$GEN_ROOT_DIR/$1
  for file in `ls $root_dir`; do
    echo -e "run --iptables $root_dir/$file " \
                "--routing_table data/empty-routing-table " \
                "--ips data/empty-ips " \
                "--input_port eth0 " \
                "$2" >> /tmp/sbt-commands
  done

  cat /tmp/sbt-commands \
    | sbt -J-Xmx3G \
    | grep "Symbolic execution time" \
    | awk -v num_rules="$1" '{sum += $5} END {print num_rules " rules: " sum/NR}'
}

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  usage
fi

run_tests "$1" "$2"
