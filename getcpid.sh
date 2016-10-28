# Licensed under the Apache License, Version 2.0 (the "License")
#
# This program gets all child PID/TID of a program (PID)
#
# Usage: ./getcpid.sh parent_pid
#
# Copyright 2016 Ali Khayam

function getcpid() {
    cpids=`pgrep -w -P $1 |xargs`
    for cpid in $cpids;
    do
        echo "$cpid"
        getcpid $cpid
    done
}
