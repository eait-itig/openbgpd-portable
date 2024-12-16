#!/usr/bin/env bash
#:
#: name = "build"
#: variety = "basic"
#: target = "omnios-r151046"
#: output_rules = [
#:	"/work/tarballs/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

mkdir -p /work/dist

#
banner packages
#

#
banner configure
#
export MAKE=gmake
export AR=gar
./update.sh || true
(cd openbsd &&
 git checkout -b release openbgpd-8.5 &&
 rm -fr .git)
./update.sh
mkdir m4
rm -fr autom4te.cache
autoreconf -fi
./configure \
  --prefix=/opt/openbgpd \
  --localstatedir=/var \
  --sysconfdir=/etc \
  --disable-bgplgd

sed 's/-fuse-linker-plugin)/-fuse-linker-plugin|-fstack-protector*)/' \
  ltmain.sh > ltmain.sh.fixed
mv -f ltmain.sh.fixed ltmain.sh

find . ! -perm -u=w -exec chmod u+w {} \;
cp scripts/config.* .

#
banner build
#
gmake -j2

#
banner install
#
pfexec gmake install -j2 DESTDIR=/work/dist
pfexec /usr/gnu/bin/install -D -g sys -o root \
  smf.xml /work/dist/lib/svc/manifest/network/bgp.xml

#
banner tarball
#
mkdir -p /work/tarballs
pushd /work/dist
tar -czvf /work/tarballs/openbgpd.tar.gz *
popd
