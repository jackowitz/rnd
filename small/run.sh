#!/bin/bash
BINARY=small_42135

function start_rnd {
  if [[ $# -lt 2 ]]; then
    echo "Usage: ./run.sh start n k"
    exit
  fi
  n=$1
  k=$2
  go build -o $BINARY rnd_tcp/small
  for i in `seq 0 $(($n - 1))`; do
    #if [[ $i -eq 0 ]]; then
      ./$BINARY -n=$n -k=$n $i &> logs/server$i.log &
    #else
    #  ./$BINARY -n=$n -k=$n $i &> /dev/null &
    #fi
  done
  echo "Started $n servers."
}

function stop_rnd {
  echo -n "Stopping..."
  pkill $BINARY
  rm -f $BINARY
  echo "done."
}

if [[ $# -lt 1 ]]; then
  echo "Usage: ./run.sh [start | stop]"
  exit
fi
case $1 in
  start) shift; start_rnd $@
    ;;
  stop) stop_rnd
    ;;
  *) echo "Usage: ./run.sh [start | stop]"
    ;;
esac
