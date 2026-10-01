# Thesis explainer video

Narrated explainer for *When Does a Precompile Pay?*, built with the
`explaining-research-as-video` skill (Manim + TTS). It runs about 6.8 min.

- `narration.json`: the script. `text` is what the voice speaks and `cap` is the subtitle spelling.
- `scenes.py`: one Manim scene per step of the argument, cued to sentence and word timestamps.
- `project.json`: the scene order. `style.py` holds the shared look.
- `tts_standin.py`: a stand-in voice (Festival HTS, offline; espeak-ng with STANDIN=espeak). It was used because Hugging Face, which hosts
  the Kokoro model, was blocked in the cloud container.

To rebuild with the Kokoro voice on a machine that can reach Hugging Face, run these from this directory:

    rm -f .build/tts_* timing.json
    python3 <skill>/scripts/build.py timing
    python3 <skill>/scripts/build.py check
    python3 <skill>/scripts/build.py render && python3 <skill>/scripts/build.py mux

The animation cues follow the new word timings automatically.
