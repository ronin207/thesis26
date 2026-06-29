import os, sys, subprocess, resource, time, threading
from datetime import datetime, timezone

tag="vkreject_w2"; rw="2"; cw="2"
SP1="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1"
BIN=SP1+"/target/release/plum_host"
DYLD=SP1+"/target/release/build/vc-pqc-c53acd15037f6a7e/out/build/libiop"
OUT="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/zkwrap_vkreject_run1_20260628/"+tag

env=dict(os.environ)
env["PATH"]=os.path.expanduser("~/.cargo/bin")+":"+env.get("PATH","")
env["DYLD_LIBRARY_PATH"]=DYLD
env["PLUM_SECURITY"]="80"; env["PLUM_HOST_MODE"]="prove"
env["PLUM_PROVE_ARM"]="syscall"; env["PLUM_ZK_WRAP"]="plonk"
env.pop("SHARD_SIZE",None)
env["SP1_WORKER_NUM_RECURSION_PROVER_WORKERS"]=rw
env["SP1_WORKER_NUM_CORE_WORKERS"]=cw
env["RUST_LOG"]="info,sp1_core_machine=info,sp1_prover=info,sp1_recursion_machine=info,sp1_recursion_circuit=info,sp1_recursion_gnark_ffi=info,p3_=warn"
env["SP1_PROVER"]="cpu"

def now(): return datetime.now(timezone.utc).strftime("%H:%M:%S")
t0=time.time()
def el(): return time.time()-t0
meta=open(OUT+".meta","w")
meta.write(f"TAG={tag} RW={rw} CW={cw} SHARD_SIZE=DEFAULT(1<<24) wrap=plonk arm=syscall lambda=80 SHAPE=REGENERATED(ExtAlu1072032/PrefixSum263424) vk_map=STALE(md5 931c0bba May17)\n")
meta.write(f"start_epoch={int(time.time())} start_utc={now()}\n"); meta.flush()

logf=open(OUT+".log","w")
# timestamped stage-boundary log: prefix each line with elapsed seconds + RSS-at-line
peak_kb=[0]; peak_ts=["-"]; cur_kb=[0]
def cur_rss():
    try:
        r=subprocess.run(["ps","-axo","pid,rss,comm"],capture_output=True,text=True)
        tot=0
        for ln in r.stdout.splitlines():
            if "plum_host" in ln and "ps -axo" not in ln:
                try: tot+=int(ln.split()[1])
                except: pass
        return tot
    except: return 0

p=subprocess.Popen([BIN],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,bufsize=1,text=True)
stop=False
def sampler():
    tsv=open(OUT+".rss.tsv","w"); tsv.write("epoch\tutc\telapsed_s\trss_kb\trss_gib\n")
    while not stop:
        tot=cur_rss(); cur_kb[0]=tot
        if tot>peak_kb[0]: peak_kb[0]=tot; peak_ts[0]=f"{el():.1f}s/{now()}"
        tsv.write(f"{int(time.time())}\t{now()}\t{el():.1f}\t{tot}\t{tot/1024/1024:.3f}\n"); tsv.flush()
        time.sleep(3)
    tsv.close()
th=threading.Thread(target=sampler); th.start()
# stage markers we care about
markers=["core","normalize","compress","reduce","compose","shrink","wrap","gnark","plonk","vk not allowed","shard","leaf"]
stages_seen={}
for line in p.stdout:
    e=el(); rk=cur_kb[0]
    logf.write(f"[{e:8.1f}s {rk/1024/1024:6.2f}GiB] {line}"); logf.flush()
    low=line.lower()
    for m in markers:
        if m in low and m not in stages_seen:
            stages_seen[m]=(e,rk)
rc=p.wait()
stop=True; th.join()
dt=time.time()-t0
ru=resource.getrusage(resource.RUSAGE_CHILDREN); mb=ru.ru_maxrss
meta.write(f"end_epoch={int(time.time())} end_utc={now()} rc={rc} wall_s={dt:.1f} wall_min={dt/60:.2f}\n")
meta.write(f"getrusage_maxrss_bytes={mb} GiB={mb/1024**3:.3f}\n")
meta.write(f"sampler_peak_kb={peak_kb[0]} GiB={peak_kb[0]/1024/1024:.3f} sampler_peak_at={peak_ts[0]}\n")
meta.write("first_seen_markers:\n")
for m,(e,rk) in stages_seen.items():
    meta.write(f"  {m}: first@{e:.1f}s rss={rk/1024/1024:.2f}GiB\n")
meta.flush(); meta.close()
print(f"DONE rc={rc} wall_min={dt/60:.2f} maxRSS_GiB={mb/1024**3:.3f} sampler_peak_GiB={peak_kb[0]/1024/1024:.3f} @ {peak_ts[0]}")
