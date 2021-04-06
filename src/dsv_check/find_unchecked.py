# DSV: Disassembly Soundness Validation
# Copyright (C) <2021> <Xiaoxin An> <Virginia Tech>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import re

def find_unchecked(a):
    res = []
    a_n = a.split('\n')
    for i in a_n:
        i = i.strip()
        if i:
            if '\t' not in i:
                x = i
                res.append(x)
    return res

if __name__=='__main__':
    a = '''ls	28906
tee	7402
sleep	7078
runcon	5375
mv	36229
paste	6474
expr	29179
echo	5539
dd	19694
dirname	5654
mknod	7022
FALSE	4965
shred	14080
od	14225
md5sum	8915
stdbuf	
cksum	6386
cp	30012
tsort	7920
hostid	5418
dircolors	5608
dir	28906
date	17099
groups	6360
factor	16636
vdir	28906
touch	14986
pathchk	6123
whoami	5463
unexpand	7445
users	6092
df	21992
chmod	14887
rmdir	8230
join	10113
getlimits	7160
env	8105
[	10264
unlink	5504
uname	5652
ln	18841
tr	8997
split	9845
nohup	7358
shuf	13855
uptime	8375
comm	8626
chcon	12773
timeout	6389
basenc	7631
pinky	7019
printf	11414
nice	5788
expand	7373
mktemp	9206
wc	9968
fmt	7744
fold	6526
tty	4981
chroot	7584
pwd	6222
logname	5418
truncate	6430
stat	15345
kill	6308
pr	14900
tac	27009
yes	6156
make-prime-list	1167
rm	14956
mkdir	
cat	6875
id	8526
mkfifo	6713
b2sum	
chown	14455
TRUE	4970
sync	5758
numfmt	12126
who	10487
printenv	5188
base32	7258
realpath	11368
cut	8078
readlink	10410
seq	
tail	17006
nproc	6717
basename	5894
csplit	
head	8553
stty	10982
ginstall	32351
du	
link	5572
base64	7731
ptx	38123
nl	25960
uniq	8375
test	9159
chgrp	14333
sum	8562'''
    res = find_unchecked(a)
    print(res)

