import os, sys, subprocess, resource, time, threading, signal

tag, rw, cw = sys.argv[1], sys.argv[2], sys.argv[3]
SP1 = "/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1"
BIN = SP1 + "/target/release/plum_host"
DYLD = SP1 + "/target/release/build/vc-pqc-c53acd15037f6a7e/out/build/libiop"
OUT = "/private/tmp/claude-501/-Users-takumiotsuka-Library-Mobile-Documents-com-apple-CloudDocs-Desktop-Projects-research-thesis/928eeb87-6943-4173-9956-087ef72c8953/scratchpad/" + tag

env = dict(os.environ)
env["PATH"] = os.path.expanduser("~/.cargo/bin") + ":" + env.get("PATH","")
env["DYLD_LIBRARY_PATH"] = DYLD
env["PLUM_SECURITY"]="80"; env["PLUM_HOST_MODE"]="prove"
env["PLUM_PROVE_ARM"]="syscall"; env["PLUM_ZK_WRAP"]="plonk"
env["SHARD_SIZE"]="4194304"
env["SP1_WORKER_NUM_RECURSION_PROVER_WORKERS"]=rw
env["SP1_WORKER_NUM_CORE_WORKERS"]=cw
env["RUST_LOG"]="info"; env["SP1_PROVER"]="cpu"

meta=open(OUT+".meta","w")
meta.write(f"TAG={tag} RW={rw} CW={cw} SHARD_SIZE=4194304 wrap=plonk arm=syscall lambda=80\n")
meta.write(f"start_epoch={int(time.time())}\n"); meta.flush()

logf=open(OUT+".log","w")
t0=time.time()
p=subprocess.Popen([BIN], env=env, stdout=logf, stderr=subprocess.STDOUT)

stop=False
peak_kb=[0]
def sampler():
    tsv=open(OUT+".rss.tsv","w")
    while not stop:
        try:
            r=subprocess.run(["ps","-axo","pid,rss,comm"],capture_output=True,text=True)
            tot=0
            for ln in r.stdout.splitlines():
                if "plum_host" in ln and "ps -axo" not in ln:
                    parts=ln.split()
                    try: tot+=int(parts[1])
                    except: pass
            if tot>peak_kb[0]: peak_kb[0]=tot
            tsv.write(f"{int(time.time())}\t{tot}\n"); tsv.flush()
        except Exception: pass
        time.sleep(3)
    tsv.close()
th=threading.Thread(target=sampler); th.start()

rc=p.wait()
stop=True; th.join()
dt=time.time()-t0
ru=resource.getrusage(resource.RUSAGE_CHILDREN)
maxrss_bytes=ru.ru_maxrss  # bytes on macOS
meta.write(f"end_epoch={int(time.time())} rc={rc} wall_s={dt:.1f} wall_min={dt/60:.2f}\n")
meta.write(f"getrusage_maxrss_bytes={maxrss_bytes} GB={maxrss_bytes/1024**3:.3f}\n")
meta.write(f"sampler_peak_kb={peak_kb[0]} GB={peak_kb[0]/1024/1024:.3f}\n")
meta.flush(); meta.close()
print(f"rc={rc} wall_min={dt/60:.2f} getrusage_maxrss_GB={maxrss_bytes/1024**3:.3f} sampler_peak_GB={peak_kb[0]/1024/1024:.3f}")
