import os, sys, subprocess, resource, time, threading
from datetime import datetime, timezone

tag = sys.argv[1] if len(sys.argv)>1 else "regen_w2"
rw  = sys.argv[2] if len(sys.argv)>2 else "2"
cw  = sys.argv[3] if len(sys.argv)>3 else "2"
SP1 = "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1"
BIN = SP1 + "/target/release/plum_host"
DYLD = SP1 + "/target/release/build/vc-pqc-c53acd15037f6a7e/out/build/libiop"
OUT = "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/docs/measurements/zkwrap_regen_shape_20260628/" + tag

env = dict(os.environ)
env["PATH"] = os.path.expanduser("~/.cargo/bin") + ":" + env.get("PATH","")
env["DYLD_LIBRARY_PATH"] = DYLD
env["PLUM_SECURITY"]="80"; env["PLUM_HOST_MODE"]="prove"
env["PLUM_PROVE_ARM"]="syscall"; env["PLUM_ZK_WRAP"]="plonk"
env.pop("SHARD_SIZE", None)  # default 1<<24
env["SP1_WORKER_NUM_RECURSION_PROVER_WORKERS"]=rw
env["SP1_WORKER_NUM_CORE_WORKERS"]=cw
# Raised RUST_LOG to capture phase transitions CORE->NORMALIZE->COMPRESS->SHRINK->WRAP->gnark
env["RUST_LOG"]="info,sp1_core_machine=info,sp1_prover=info,sp1_recursion_machine=info,sp1_recursion_circuit=info,sp1_recursion_gnark_ffi=info,p3_=warn"
env["SP1_PROVER"]="cpu"

def now(): return datetime.now(timezone.utc).strftime("%H:%M:%S")
meta=open(OUT+".meta","w")
meta.write(f"TAG={tag} RW={rw} CW={cw} SHARD_SIZE=DEFAULT(1<<24) wrap=plonk arm=syscall lambda=80 SHAPE=REGENERATED(ExtAlu1072032/PrefixSum263424)\n")
meta.write(f"start_epoch={int(time.time())} start_utc={now()}\n"); meta.flush()
logf=open(OUT+".log","w")
t0=time.time()
p=subprocess.Popen([BIN], env=env, stdout=logf, stderr=subprocess.STDOUT)
stop=False; peak_kb=[0]; peak_ts=["-"]
def sampler():
    tsv=open(OUT+".rss.tsv","w"); tsv.write("epoch\tutc\trss_kb\trss_gib\n")
    while not stop:
        try:
            r=subprocess.run(["ps","-axo","pid,rss,comm"],capture_output=True,text=True)
            tot=0
            for ln in r.stdout.splitlines():
                if "plum_host" in ln and "ps -axo" not in ln:
                    parts=ln.split()
                    try: tot+=int(parts[1])
                    except: pass
            if tot>peak_kb[0]: peak_kb[0]=tot; peak_ts[0]=now()
            tsv.write(f"{int(time.time())}\t{now()}\t{tot}\t{tot/1024/1024:.3f}\n"); tsv.flush()
        except Exception: pass
        time.sleep(3)
    tsv.close()
th=threading.Thread(target=sampler); th.start()
rc=p.wait()
stop=True; th.join()
dt=time.time()-t0
ru=resource.getrusage(resource.RUSAGE_CHILDREN)
mb=ru.ru_maxrss
meta.write(f"end_epoch={int(time.time())} end_utc={now()} rc={rc} wall_s={dt:.1f} wall_min={dt/60:.2f}\n")
meta.write(f"getrusage_maxrss_bytes={mb} GiB={mb/1024**3:.3f}\n")
meta.write(f"sampler_peak_kb={peak_kb[0]} GiB={peak_kb[0]/1024/1024:.3f} sampler_peak_at_utc={peak_ts[0]}\n")
meta.flush(); meta.close()
print(f"rc={rc} wall_min={dt/60:.2f} getrusage_maxrss_GiB={mb/1024**3:.3f} sampler_peak_GiB={peak_kb[0]/1024/1024:.3f} peak_at={peak_ts[0]}")
