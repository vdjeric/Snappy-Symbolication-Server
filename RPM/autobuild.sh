#!/usr/bin/env bash
# This script automatically builds copies over the systemd unit files, spec files and builds the rpm.

RPM_BUILD_DIR="$HOME/rpmbuild"

export UPSTREAM="https://github.com/mozilla/Snappy-Symbolication-Server"
commit_date=`curl -s https://api.github.com/repos/mozilla/Snappy-Symbolication-Server/commits?per_page=1 | grep -m 1 date | cut -d '"' -f 4`
export EPOCH=`date --date="${commit_date}" +%s`

cp ./SPECS/mozilla-snappy.spec $HOME/rpmbuild/SPECS/
cp ./SOURCES/mozilla-snappy.* $HOME/rpmbuild/SOURCES/

rpmbuild -ba $HOME/rpmbuild/SPECS/mozilla-snappy.spec
