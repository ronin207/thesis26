"""Stand-in for tts_timed.py (Festival HTS voice cmu_us_slt_arctic_hts; espeak-ng with STANDIN=espeak) when the Kokoro model cannot be downloaded (Hugging Face blocked in the cloud
container). Writes the same .wav (48 kHz mono) + .json word timestamps that build.py expects, at the same
hashed paths, so `build.py timing` then runs without calling Kokoro. Word starts are measured, not estimated:
each start is the synthesized duration of the sentence prefix before that word (trailing silence trimmed).
On a machine with Kokoro, delete .build/tts_* and run `build.py timing` to replace this voice."""
import json, hashlib, os, re, subprocess, wave, sys
D = os.path.dirname(os.path.abspath(__file__)); B = os.path.join(D, ".build"); os.makedirs(B, exist_ok=True)
cfg = json.load(open(os.path.join(D, "project.json"))); narr = json.load(open(os.path.join(D, "narration.json")))
RATE, GAP = "160", 0.28
ENGINE = os.environ.get("STANDIN", "festival")
FEST = "(begin (voice_cmu_us_slt_arctic_hts) (Parameter.set 'Duration_Stretch 0.93))"

def synth(text, path):
    if ENGINE == "espeak":
        subprocess.run(["espeak-ng", "-v", "en-us", "-s", RATE, "-w", path, text], check=True)
    else:
        txt = path + ".txt"; open(txt, "w").write(text)
        subprocess.run(["text2wave", "-eval", FEST, txt, "-o", path], check=True, stderr=subprocess.DEVNULL)
    with wave.open(path) as w:
        import array
        a = array.array("h", w.readframes(w.getnframes())); sr = w.getframerate()
    i = len(a)
    while i > 0 and abs(a[i - 1]) < 300: i -= 1
    return i / sr, sr

def beat(b):
    h = hashlib.md5((b["text"] + cfg.get("voice", "af_heart") + str(cfg.get("speed", 1.05))).encode()).hexdigest()[:10]
    out = f"{B}/tts_{b['id']}_{h}.wav"
    if os.path.exists(out) and os.path.exists(out[:-4] + ".json"): return
    sents = re.split(r"(?<=[.?!])\s+", b["text"]); words, parts, off = [], [], 0.0
    for k, s in enumerate(sents):
        p = f"{B}/_{b['id']}_s{k}.wav"; full, sr = synth(s, p); toks = s.split()
        for j, t in enumerate(toks):
            st = 0.0 if j == 0 else synth(" ".join(toks[:j]), f"{B}/_{b['id']}_p.wav")[0]
            words.append({"w": t, "s": round(off + st, 3), "e": round(off + st, 3)})
        parts.append((p, full)); off += full + GAP
    # concatenate trimmed sentences with fixed gaps
    flt = "".join(f"[{i}]atrim=0:{d:.3f},apad=pad_dur={GAP}[a{i}];" for i, (_, d) in enumerate(parts)) + "".join(f"[a{i}]" for i in range(len(parts))) + f"concat=n={len(parts)}:v=0:a=1[o]"
    cmd = ["ffmpeg", "-y", "-loglevel", "error"] + sum([["-i", p] for p, _ in parts], []) + ["-filter_complex", flt, "-map", "[o]", "-ar", "48000", "-ac", "1", "-c:a", "pcm_s16le", out]
    subprocess.run(cmd, check=True)
    json.dump(words, open(out[:-4] + ".json", "w")); print("ok", b["id"], flush=True)


if __name__ == "__main__":
    from multiprocessing import Pool
    with Pool(min(16, os.cpu_count() or 4)) as p:
        p.map(beat, narr)
