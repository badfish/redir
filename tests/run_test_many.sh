#!/bin/sh

TARGET=$(( $(date '+%s') + 15 ))

while [ $(date '+%s') -lt $TARGET ]; do
	./run_test_once.sh
done
