import os,sys,subprocess,resource,time
start,end=sys.argv[1],sys.argv[2]
chunk=sys.argv[3] if len(sys.argv)>3 else "4"
SP1="/Users/takumiotsuka/Library/Mobile Documents/com~apple~CloudDocs/Desktop/Projects/research/thesis/platforms/zkvms/sp1"
BIN=SP1+"/target/release/build_recursion_vks"
BUILD="/private/tmp/claude-501/vkmap_slope_build"
os.makedirs(BUILD,exist_ok=True)
env=dict(os.environ)
env["PATH"]=os.path.expanduser("~/.cargo/bin")+":"+env.get("PATH","")
env["RUST_LOG"]="warn"
n=int(end)-int(start)
t0=time.time()
p=subprocess.run([BIN,"--build-dir",BUILD,"--start",start,"--end",end,"--chunk-size",chunk],
                 env=env,capture_output=True,text=True)
dt=time.time()-t0
ru=resource.getrusage(resource.RUSAGE_CHILDREN)
gib=ru.ru_maxrss/1024**3
print(f"slice {start}..{end} n={n} chunk={chunk} rc={p.returncode} wall_s={dt:.2f} per_setup_s={dt/n:.4f} maxRSS_GiB={gib:.3f}")
