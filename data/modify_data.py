import sys
import re
import os


regex = re.compile(r"run=(\d+), ff=(\d+), rip=(-?\d+), rsp=(-?\d+), window=(\d+), lpd=(\d+), offset=(\d+)$")
page_access = re.compile(r"(\d+)=(\d)")

datafname = os.path.splitext(sys.argv[1])[0] + "_1.csv"
dainfofname = os.path.splitext(sys.argv[1])[0] + "_2.csv"

data_mod = []
data_dainfo = []

data_ori = open(sys.argv[1]).readlines()
i = 0
while i < len(data_ori):
    m = regex.search(data_ori[i])
    if m is None:
        i += 1
        continue
    data_mod.append(m.groups())
    run = m.group(1)
    pfn = m.group(2)
    #print(m.groups())
    m = page_access.findall(data_ori[i+1])
    if len(m):
        for j in m:
            data_dainfo.append("{}, {}, {}\n".format(run, pfn, ", ".join(j)))
        i += 1

    i += 1

with open(datafname, "w") as f:
    f.write("run, t, rip, rsp, window, ldp, offset\n")
    for s in data_mod:
        print(", ".join(s), file=f)
print(f"written pagefaults to {datafname}")

with open(dainfofname, "w") as f:
    f.write("run, t, offset, da\n")
    for i in data_dainfo:
        f.write(i)
print(f"written dirty/access bits to {dainfofname}")
