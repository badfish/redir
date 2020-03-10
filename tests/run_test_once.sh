#!/bin/sh

set -e

BASEDIR=$(readlink -f ${0%/*})

#avfs-on
[ -f /#avfs-on ] || true

TEMPDIR=$(mktemp -d)

cd $TEMPDIR
mkdir test_dir
cp -r $BASEDIR/../module/* test_dir
ln -s redir.c test_dir/test_link
tar -cf test.tar test_dir/*

( cd test_dir; ls -l | grep -v '^total' ) > list1
( cd test.tar#/test_dir; ls -l | grep -v '^total' ) > list2

diff list1 list2

( cd test_dir; md5sum $(find . -type f | sort) ) > list1
( cd test.tar#/test_dir; md5sum $(find . -type f | sort) ) > list2

diff list1 list2

cd $BASEDIR
rm -rf $TEMPDIR
