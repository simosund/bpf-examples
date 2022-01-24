#!/bin/bash

KPPING_PATH="~/pping"
EPPING_PATH="~/bpf-examples/pping"

EPPING_EXTRA_ARGS="-f -r 0 -I xdp"
KPPING_EXTRA_ARGS=""

pping_version=${1:-"e_pping"}
host=${2:-"localhost"}
iface=${3:-"ens192"}
save_path=$4

if [[ $save_path != /* ]]; then
    save_path="~/${save_path}"
fi

if [[ $pping_version == "e_pping" ]]; then
    program_path=$EPPING_PATH
    extra_args=$EPPING_EXTRA_ARGS
elif [[ $pping_version == "k_pping" ]]; then
    program_path=$KPPING_PATH
    extra_args=$KPPING_EXTRA_ARGS
elif [[ $pping_version == "no_pping" ]]; then
    cmd="mkdir -p $save_path; touch ${save_path}/pping.out ${save_path}/pping.err"
elif [[ $pping_version == "kill" ]]; then
    cmd="sudo pkill -f "\""pping -i $iface"\"
else
    echo "Err: Unknown pping version: $pping_version"
    exit 1
fi

if [[ -z "$cmd" ]]; then
    cmd="mkdir -p $save_path; "
    cmd+="cd $program_path; "
    cmd+="sudo ./pping -i $iface $extra_args > ${save_path}/pping.out 2> ${save_path}/pping.err &"
fi

if [[ $host == "localhost" ]]; then
    eval $cmd
else
    ssh $host "$cmd"
fi
