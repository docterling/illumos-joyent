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

fail_no_debug()
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
	    grep "No debug info found to convert from" >/dev/null; then
		fail "$cmd: incorrect output $out"
		return;
	fi
}

has_ctf()
{
	for f in "$@"; do
		if ! elfdump -c -N .SUNW_ctf "$f" |
		    grep '.SUNW_ctf' >/dev/null; then
			fail "$f lacks CTF section"
			return
		fi
	done
}

cat <<EOF >file1.c
#include <stdio.h>
struct foo { int a; };
int main(void) { struct foo foo = { 4 }; printf("%d\n", foo.a); }
EOF

cat <<EOF >file2.c
#include <stdio.h>
char myfunc(int a) { printf("%d\n", a); }
EOF

# NB: we just pretend to compile this as C++
cat <<EOF >file3.cc
struct bar { char *tar; };
void mycxxfunc(char *c) { c[0] = '9'; };
EOF

cat <<EOF >file4.s
.globl caller
.type caller,@function
caller:
	movl 4(%ebp), %eax
	ret
EOF

echo "$progname: An empty file should fail conversion due to no DWARF"
echo >emptyfile.c

$CC -c -o emptyfile.o emptyfile.c
fail_no_debug emptyfile.o
$CC -c -o emptyfile.o emptyfile.c
$CTFCONVERT -m emptyfile.o

$CC $DEBUGFLAGS -c -o emptyfile.o emptyfile.c
fail_no_debug emptyfile.o
$CC $DEBUGFLAGS -c -o emptyfile.o emptyfile.c
$CTFCONVERT -m emptyfile.o

echo "$progname: A file missing DWARF should fail conversion"

$CC -c -o file1.o file1.c
fail_no_debug file1.o
$CC -c -o file1.o file1.c
$CTFCONVERT -m file1.o

echo "$progname: One C file missing DWARF should fail ctfconvert"

$CC -c -o file1.o file1.c
$CC $DEBUGFLAGS -c -o file2.o file2.c
ld -r -o files.o file2.o file1.o
# FIXME: known to fail right now
fail_no_debug files.o
ld -r -o files.o file2.o file1.o
$CTFCONVERT -m files.o
has_ctf files.o

echo "$progname: One .cc file missing DWARF should pass"

$CC $DEBUGFLAGS -c -o file1.o file1.c
$CC -c -o file2.o file2.c
$CC -c -o file3.o file3.cc
$CC -o mybin file1.o file2.o file3.o
$CTFCONVERT mybin
has_ctf mybin

echo "$progname: One .s file missing DWARF should pass"
$CC $DEBUGFLAGS -c -o file1.o file1.c
$CC -c -o file2.o file2.c
as -o file4.o file4.s
$CC -o mybin file1.o file2.o file4.o
$CTFCONVERT mybin
has_ctf mybin

echo "result is $result"
exit $result
