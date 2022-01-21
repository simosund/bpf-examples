#!/bin/bash

host=${1:-"localhost"}
path=${2:-"."}
suffix=$3

if [[ $host == "localhost" ]]; then
    xz -T0 ${path}/pping.out ${path}/pping.err
else
    mkdir -p $path
    ssh $host "xz -T0 ${path}/pping.out ${path}/pping.err"
    scp -p ${host}:${path}/pping.*.xz ${path}/
    ssh $host "rm ${path}/pping.*.xz"
fi

if [[ -n $suffix ]]; then
    for pping_suffix in "out" "err"; do
        mv ${path}/pping.${pping_suffix}.xz ${path}/pping-${suffix}.${pping_suffix}.xz
    done
fi

