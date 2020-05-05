#!/bin/bash

TARGET=$(( SECONDS + 15 ))

while [ $SECONDS -lt $TARGET ]; do
	./run_test_once.sh
done
