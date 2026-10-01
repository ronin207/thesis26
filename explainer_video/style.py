"""Shared style + timing base for research-video scenes. Copy next to scenes.py and `from style import *`.
Visual contract: Latin Modern (Computer Modern) everywhere, charcoal background, off-white text, two semantic accents
(BLUE = holds / supported / kept, RED = fails / withdrawn / violated), thin rules instead of boxes, braces for grouping,
math italics for named entities. Change the palette here, once, if a project needs different semantics."""
from manim import *
import json, os, subprocess, manimpango

HERE = os.path.dirname(os.path.abspath(__file__))


def _find_lm():
    try:
        p = subprocess.check_output(["kpsewhich", "lmroman10-regular.otf"], text=True).strip()
        return os.path.dirname(p) if p else None
    except Exception:
        return None


_LM = _find_lm()
if _LM:
    for f in ("lmroman10-regular.otf", "lmroman10-italic.otf", "lmroman10-bold.otf", "lmmono10-regular.otf"):
        manimpango.register_font(os.path.join(_LM, f))
SERIF, MONO = ("Latin Modern Roman", "Latin Modern Mono") if _LM else ("Times New Roman", "Courier New")

BG, FG, MU, RULE = "#161616", "#E6E4DF", "#8C8A86", "#4A4A4A"
BLUE, RED = "#6A9BCB", "#DD5E4E"
config.background_color = BG

_TP = os.path.join(HERE, "timing.json")
T = json.load(open(_TP)) if os.path.exists(_TP) else {"_scenes": []}
SC = {s["name"]: s for s in T["_scenes"]}


# ---- typography (render at 2x and scale: sharper small text; 4x makes long lines wrap) ----
def tx(s, size=24, color=FG, slant=NORMAL):
    return Text(s, font=SERIF, font_size=size * 2, color=color, slant=slant).scale(0.5)


def note(s, size=20, color=MU):
    return tx(s, size, color)


def tt(s, size=20, color=FG):
    return Text(s, font=MONO, font_size=size * 2, color=color).scale(0.5)


def m(s, color=FG, scale=1.0):
    return MathTex(s, color=color).scale(scale)


def hrule(x0, x1, y, w=1.2, color=RULE):
    return Line([x0, y, 0], [x1, y, 0], stroke_width=w, color=color)


def strike(mob, color=RED, w=2.5):
    return Line(mob.get_left() + LEFT * 0.05, mob.get_right() + RIGHT * 0.05, color=color, stroke_width=w)


def dots(n, cols, r=0.1, gap=0.12, color=RULE):
    return VGroup(*[Dot(radius=r, color=color) for _ in range(n)]).arrange_in_grid(cols=cols, buff=gap)


def ctr(final, start, color=FG, s=1.0):
    """Counter laid out at its final width, right edge fixed, so it never grows into the label beside it.
    Call n.set_value(start) after arranging, then animate ChangeDecimalToValue(n, final) in its OWN play()."""
    n = Integer(final, color=color, edge_to_fix=RIGHT).scale(s)
    n.start = start
    return n


def table(x0, x1, y_head, headers, xs, caption=None):
    """Booktabs-style table: top rule, header row, mid rule. headers[i] is placed at xs[i] (first left-aligned)."""
    top, mid = hrule(x0, x1, y_head + 0.35), hrule(x0, x1, y_head - 0.3, 0.8)
    hs = VGroup(*[note(h, 19).move_to([x, y_head, 0], aligned_edge=LEFT if i == 0 else ORIGIN) for i, (h, x) in enumerate(zip(headers, xs))])
    g = VGroup(top, mid, hs)
    if caption:
        g.add(note(caption, 17).next_to(top, UP, buff=0.15).align_to(top, LEFT))
    return g


# ---- timing: every animation is cued to the narration ----
class Beat(Scene):
    """One scene = one step of the narrative spine, spanning narration beats first..last (project.json).
    self.c(beat, n, off): start of sentence n of a beat. self.w(beat, word, k, off): k-th occurrence of a spoken word.
    self.until(t): wait until scene-local time t. self.end(keep=[...]): fade everything except `keep`, pad to exact length.
    Scenes that continue the running example should end with end(keep=...) and the next scene should self.add() the
    same objects in the same state at t=0, so the cut is invisible."""
    NAME, SEC = "", ""

    def setup(self):
        if self.NAME not in SC:
            raise RuntimeError(f"{self.NAME} not in timing.json: run `build.py timing` after editing project.json")
        sc = SC[self.NAME]
        self.t0, self.D = sc["t0"], sc["t1"] - sc["t0"]
        self.sec = note(self.SEC, 17).to_corner(UL, buff=0.45) if self.SEC else None
        if self.sec:
            self.add(self.sec)

    def c(self, bid, n=0, off=0.0):
        s = T[bid]["sent"]
        return s[min(n, len(s) - 1)] - self.t0 + off

    def w(self, bid, word, k=0, off=0.0):
        hits = [x["t"] for x in T[bid]["words"] if x["w"].strip(".,?!").lower() == word.lower()]
        return (hits[min(k, len(hits) - 1)] if hits else T[bid]["sent"][0]) - self.t0 + off

    def until(self, t):
        dt = t - self.renderer.time
        if dt > 1 / 60:
            self.wait(dt)

    def fade(self, *mobs, rt=0.45):
        mobs = [x for x in mobs if x is not None]
        if mobs:
            self.play(*[FadeOut(x) for x in mobs], run_time=rt)

    def end(self, keep=None):
        if self.renderer.time > self.D - 0.6:
            print(f"OVERRUN {self.NAME}: {self.renderer.time:.2f} > {self.D - 0.6:.2f}")
        self.until(self.D - 0.6)
        keep = keep or []
        rest = [x for x in self.mobjects if x not in keep and (keep or x is not self.sec)]
        if rest:
            self.play(*[FadeOut(x) for x in rest], run_time=0.5)
        self.until(self.D)
