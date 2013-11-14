#!/bin/bash
FILES=/depotdata/p4/common/bin/*
for f in $FILES
do
  if [[ -x "$f" ]]
  then 
    VERSION=$($f -V|grep "Rev."|cut -d'/' -f4|cut -d' ' -f1)
    mv --verbose $f $f.$VERSION
  else
    echo "File '$f' is not executable"
  done
  fi
done
