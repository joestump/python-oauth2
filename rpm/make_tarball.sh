#!/bin/bash

package="python-oauth2"
lasttag="$( git describe --tags --abbrev=0 )"
version=$( echo $lasttag | awk -F- '{ print $1 }' )
prefix="${package}-${version}"

echo "Creating tarball for ${package} version ${version}"
cd ./$(git rev-parse --show-cdup)
echo "Appending prefix ${prefix}..."
git archive --format=tar --prefix=$prefix/ HEAD | gzip > ./$(git rev-parse --show-cdup)/rpm/${package}-${version}.tar.gz
echo "Wrote ${package}-${version}.tar.gz"
cd $OLDPWD
