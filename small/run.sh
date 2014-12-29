#!/bin/bash
BINARY=small_42135
TEST=test_42135
go build -o $BINARY rnd/small
go build -o $TEST rnd/small_test
for n in `seq 2 10`; do
	for i in `seq 0 $((n - 1))`; do
		if [[ $i -eq 0 ]]; then
			./$BINARY -n=$n -k=$n $i &
		else
			./$BINARY -n=$n -k=$n $i &> /dev/null &
		fi
	done
	sleep 2 && ./$TEST &> /dev/null
	pkill $BINARY
done
rm $BINARY $TEST
