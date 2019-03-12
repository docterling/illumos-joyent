#!/usr/bin/ksh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright (c) 2019, Joyent, Inc.
#

set -e

result=0

progname=$(basename $0)

fail()
{
	echo "Failed: $*" 2>&1
	result=1
}

fail_non_c()
{
	cmd="$@"
	set +e
	out=$($CTFCONVERT $cmd 2>&1)

	if [[ $? -eq 0 ]]; then
		fail "$cmd succeeded but should have failed"
		set -e
		return;
	fi

	set -e

	if ! echo "$out" | \
	    grep "No C source to convert from" >/dev/null; then
		fail "$cmd: incorrect output $out"
		return;
	fi
}

no_ctf()
{
	for f in "$@"; do
		if elfdump -c -N .SUNW_ctf "$f" |
		    grep '.SUNW_ctf' >/dev/null; then
			fail "$f has CTF section"
			return
		fi
	done
}

cat <<EOF >file1.c
#include <stdio.h>
struct foo { int a; };
int main(void) { struct foo foo = { 4 }; printf("%d\n", foo.a); }
EOF

# NB: we just pretend to compile this as C++
cat <<EOF >file2.cc
struct bar { char *tar; };
void mycxxfunc(char *c) { c[0] = '9'; };
EOF

cat <<EOF >file3.s
.globl caller
.type caller,@function
caller:
	movl 4(%ebp), %eax
	ret
EOF

echo "$progname: ctfconvert should fail on a .cc-derived object"
$CC -c -o file2.o file2.cc
fail_non_c file2.o
$CC -c -o file2.o file2.cc
$CTFCONVERT -i file2.o

echo "$progname: ctfconvert shouldn't process .cc-derived DWARF"
$CC $DEBUGFLAGS -c -o file2.o file2.cc
$CTFCONVERT -i file2.o
no_ctf file2.o

echo "$progname: ctfconvert should fail on a .s-derived object"
as -o file4.o file4.s
fail_non_c file4.o
as -o file4.o file4.s
$CTFCONVERT -i file4.o
no_ctf file4.o

echo "result is $result"
exit $result
