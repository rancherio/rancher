#!/bin/bash

which csv2md >/dev/null || echo "Install csv2md with `npm install -g csv2md`"
which jq >/dev/null || echo "Install jq"

for j in json/* ; do
    jq . $j >/dev/null
    if [ $? -ne 0 ] ; then
        echo "INVALID JSON IN FILE $j"
        exit 1
    fi
done

sed -i -e '/INSERT TABLE HERE/q' README.md
csv2md output.csv >> README.md
