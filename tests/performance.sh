#!/bin/bash

set -e

BASEDIR=$(readlink -f ${0%/*})
TEMPDIR=$(mktemp -d)

cd $TEMPDIR
touch foo
tar -cf foo.tar foo

timing() {
	FILENAME=$1

	n=0
	TARGET=$(( SECONDS + 15 ))
	while [ $SECONDS -lt $TARGET ]; do
		[ -f $FILENAME ] || true
		[ -f $FILENAME ] || true
		[ -f $FILENAME ] || true
		[ -f $FILENAME ] || true
		[ -f $FILENAME ] || true
		n=$(( n + 5 ))
	done
	echo $n
}

#avfs-on
[ -f /#avfs-on ] || true

timing foo
timing /.avfs/$TEMPDIR/foo
timing /.avfs/$TEMPDIR/foo.tar#/foo
timing foo.tar#/foo

#avfs-off
[ -f /#avfs-off ] || true

timing foo
timing /.avfs/$TEMPDIR/foo
timing /.avfs/$TEMPDIR/foo.tar#/foo
timing foo.tar#/foo

cd $BASEDIR
rm -rf $TEMPDIR
