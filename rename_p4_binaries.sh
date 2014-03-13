#!/bin/bash
# Script to rename Perforce binaries by their major and minor version numbers
# e.g. /depotdata/p4/common/bin/p4 -> p4.2013.3.740675
# This allows easy version upgrades/downgrades by just repointing the necessary symlinks
#
FILES=/depotdata/p4/common/bin/*
for f in $FILES
do
  if [[ -x "$f" ]]
  then 
    MAJOR_VERSION=$($f -V|grep "Rev."|cut -d'/' -f3|cut -d' ' -f1)
    MINOR_VERSION=$($f -V|grep "Rev."|cut -d'/' -f4|cut -d' ' -f1)
    mv --verbose $f $f.$MAJOR_VERSION.$MINOR_VERSION
  else
    echo "File '$f' is not executable"
  fi
done
