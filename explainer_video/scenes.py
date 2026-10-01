"""When Does a Precompile Pay? -- explainer for Otsuka, Master's thesis (Waseda, 2026).
Running example: one PLUM-80 verification on SP1 (1052 Griffin calls) and its removed-vs-added ledger.
Build: see the explaining-research-as-video skill, Quick reference."""
from style import *

BITS = 0.045          # scene units per bit, for the field-width bars


def bar(nbits, y, x0=-4.2, color=FG):
    ln = Line([x0, y, 0], [x0 + nbits * BITS, y, 0], color=color, stroke_width=3)
    ends = VGroup(*[Line([x, y - 0.12, 0], [x, y + 0.12, 0], color=color, stroke_width=2) for x in (x0, x0 + nbits * BITS)])
    return VGroup(ln, ends)


def limbs(y, x0=-4.2):
    """Ticks every 30 bits across the 199-bit bar, limb names below."""
    ticks = VGroup(*[Line([x0 + 30 * k * BITS, y - 0.18, 0], [x0 + 30 * k * BITS, y + 0.18, 0], color=RED, stroke_width=2) for k in range(1, 7)])
    names = VGroup(*[m(rf"a_{k}", MU, 0.6).move_to([x0 + (30 * k + 15) * BITS, y - 0.45, 0]) for k in range(7)])
    names[-1].move_to([x0 + (180 + 9.5) * BITS, y - 0.45, 0])
    return ticks, names


class Case(Beat):
    NAME, SEC = "Case", "a single multiplication"

    def construct(self):
        self.until(self.c("a1", 0))
        small = bar(31, 1.9)
        ls = m(r"\text{prover field } p_{\mathsf{vm}}:\ 31 \text{ bits}", FG, 0.7).next_to(small, UP, buff=0.2).align_to(small, LEFT)
        self.play(Create(small), FadeIn(ls), run_time=1.0)
        self.until(self.c("a1", 1))
        big = bar(199, 0.4)
        lb = m(r"\text{PLUM field } p:\ 199 \text{ bits}", FG, 0.7).next_to(big, UP, buff=0.2).align_to(big, LEFT)
        self.play(Create(big), FadeIn(lb), run_time=1.2)

        self.until(self.c("a2", 0))
        op = m(r"a \cdot b \bmod p", FG, 1.0).move_to([0, -1.4, 0])
        self.play(Write(op), run_time=0.8)
        self.until(self.c("a2", 1))
        one = VGroup(Dot(radius=0.12, color=BLUE), note("native prover: 1 step", 22, BLUE)).arrange(RIGHT, buff=0.25).move_to([-4.4, -2.75, 0])
        self.play(FadeIn(one), run_time=0.6)

        self.until(self.c("a3", 0))
        ticks, names = limbs(0.4)
        self.play(Create(ticks), FadeIn(names), run_time=1.0)
        ell = m(r"\ell = 7", RED, 0.8).next_to(big, RIGHT, buff=0.4)
        self.play(FadeIn(ell), run_time=0.4)
        self.until(self.c("a3", 1))
        grid = dots(49, 7, r=0.07, gap=0.1, color=RED).move_to([0.2, -2.75, 0])
        gl = note("schoolbook: 7 × 7 = 49 limb products", 22, RED).next_to(grid, RIGHT, buff=0.4)
        self.play(LaggedStart(*[FadeIn(d) for d in grid], lag_ratio=0.03), FadeIn(gl), run_time=1.6)
        self.end()


ARM_X = [-6.2, -0.6, 3.6]


def arm_table():
    return table(-6.4, 6.4, 1.2, ["arm", "guest cycles (execute)", "prove time"], ARM_X,
                 caption="PLUM verification, 80-bit level, SP1, 24 GB laptop")


def cell(s, i, y, color=FG, size=22):
    t = tx(s, size, color)
    return t.move_to([ARM_X[i], y, 0], aligned_edge=LEFT if i == 0 else ORIGIN)


class Obvious(Beat):
    NAME, SEC = "Obvious", "the obvious fix"

    def construct(self):
        self.until(self.c("b1", 0))
        eq = m(r"1\ \textit{Verify} \;=\; 1052 \times \textit{Griffin}", FG, 0.95).move_to([0, 2.9, 0])
        self.play(Write(eq), run_time=1.0)
        tab = arm_table()
        self.play(FadeIn(tab), run_time=0.6)
        Y = [0.35, -0.55, -1.45]

        self.until(self.c("b2", 0))
        r1 = VGroup(cell("software only", 0, Y[0]), cell("7.08 × 10⁹", 1, Y[0]))
        self.play(FadeIn(r1), run_time=0.6)
        self.until(self.w("b2", "memory", 0, -0.4))
        t1 = cell("out of memory, ≈ 1 m 45 s", 2, Y[0], RED)
        self.play(FadeIn(t1), run_time=0.5)

        self.until(self.c("b3", 2))
        r2 = cell("Griffin precompile", 0, Y[1])
        self.play(FadeIn(r2), run_time=0.5)
        self.until(self.c("b4", 0))
        c2 = cell("1.26 × 10⁸", 1, Y[1]); t2 = cell("14.25 min", 2, Y[1])
        self.play(FadeIn(c2), FadeIn(t2), run_time=0.6)
        self.until(self.c("b4", 2))
        self.play(t2.animate.set_color(BLUE), run_time=0.5)

        self.until(self.c("b5", 1))
        r3 = VGroup(cell("SHA-3 control (software hash)", 0, Y[2]), cell("1.11 × 10⁸", 1, Y[2]))
        self.play(FadeIn(r3), run_time=0.6)
        self.until(self.c("b6", 0))
        t3 = cell("13.05 min", 2, Y[2], BLUE)
        self.play(FadeIn(t3), run_time=0.5)
        self.until(self.c("b6", 1))
        self.play(t2.animate.set_color(RED), run_time=0.5)
        n3 = note("means of 3 runs each; slower in every run", 18).move_to([3.6, -2.0, 0])
        self.play(FadeIn(n3), run_time=0.4)

        self.until(self.c("b7", 1))
        hid = tx("the chip's own rows are proved, but not counted as cycles", 24, RED).move_to([0, -2.9, 0])
        self.play(FadeIn(hid), run_time=0.6)
        self.end()


class Rule(Beat):
    NAME, SEC = "Rule", "trace area"

    def construct(self):
        self.until(self.c("c1", 0))
        cells = dots(120, 24, r=0.045, gap=0.08, color=MU).move_to([0, 2.3, 0])
        self.play(LaggedStart(*[FadeIn(d) for d in cells], lag_ratio=0.01), run_time=1.2)
        self.until(self.c("c1", 1))
        ta = note("trace area = number of committed cells", 22, FG).next_to(cells, DOWN, buff=0.25)
        self.play(FadeIn(ta), run_time=0.5)

        self.until(self.c("c2", 0))
        self.play(FadeOut(cells), FadeOut(ta), run_time=0.4)
        T_ = MathTex(r"T_{\mathsf{prove}}", r"\approx", r"\kappa_{\mathsf{core}}\,A_{\mathsf{core}}", r"+", r"\sum_P \kappa_P\,A_P", color=FG).scale(0.95).move_to([0, 2.6, 0])
        self.play(Write(T_), run_time=1.0)
        self.until(self.c("c2", 1))
        u1 = Underline(T_[2], color=BLUE, buff=0.08)
        l1 = note("core area: removed", 18, BLUE).next_to(u1, DOWN, buff=0.12)
        self.play(Create(u1), FadeIn(l1), run_time=0.5)
        self.until(self.c("c2", 2))
        u2 = Underline(T_[4], color=RED, buff=0.08)
        l2 = note("chip area: added", 18, RED).next_to(u2, DOWN, buff=0.12)
        self.play(Create(u2), FadeIn(l2), run_time=0.5)

        self.until(self.c("c3", 0))
        ineq = MathTex(r"\Delta A_{\mathsf{core}}\,\kappa_{\mathsf{core}}", r"\;>\;", r"A_P\,\kappa_P", color=FG).scale(0.95).move_to([0.6, 0.75, 0])
        ineq[0].set_color(BLUE); ineq[2].set_color(RED)
        pl = note("pays exactly when", 20).next_to(ineq, LEFT, buff=0.35)
        self.play(FadeIn(pl), Write(ineq), run_time=1.0)

        hdr = VGroup(note("removed (core)", 19, BLUE).move_to([-1.6, -0.4, 0]), note("added (chip)", 19, RED).move_to([4.0, -0.4, 0]))
        rule = hrule(-6.4, 6.4, -0.7, 0.8)
        self.until(self.c("c4", 0))
        lab1 = note("vs. software only", 20, FG).move_to([-5.3, -1.3, 0])
        self.play(FadeIn(hdr), Create(rule), FadeIn(lab1), run_time=0.6)
        self.until(self.c("c4", 1))
        a1 = tx("≈ 6.6 × 10⁶ cycles / call", 20).move_to([-1.6, -1.3, 0])
        self.play(FadeIn(a1), run_time=0.5)
        self.until(self.c("c4", 2))
        b1 = tx("14 × 3819 ≈ 5.3 × 10⁴ cells / call", 20).move_to([4.0, -1.3, 0])
        self.play(FadeIn(b1), run_time=0.5)
        self.until(self.c("c4", 3))
        g1 = m(">", BLUE, 0.9).move_to([0.95, -1.3, 0]); v1 = note("pays", 20, BLUE).next_to(lab1, DOWN, buff=0.1)
        self.play(FadeIn(g1), FadeIn(v1), run_time=0.5)

        self.until(self.c("c5", 0))
        lab2 = note("vs. SHA-3 control", 20, FG).move_to([-5.3, -2.4, 0])
        self.play(FadeIn(lab2), run_time=0.4)
        self.until(self.c("c5", 1))
        a2 = tx("−13 % (more cycles)", 20, RED).move_to([-1.6, -2.4, 0])
        self.play(FadeIn(a2), run_time=0.5)
        self.until(self.c("c5", 2))
        b2 = tx("+ 5.6 × 10⁷ cells", 20, RED).move_to([4.0, -2.4, 0])
        self.play(FadeIn(b2), run_time=0.5)

        self.until(self.c("c6", 0))
        g2 = m("<", RED, 0.9).move_to([0.95, -2.4, 0]); v2 = note("loses, for any κ ≥ 0", 18, RED).next_to(lab2, DOWN, buff=0.1)
        self.play(FadeIn(g2), FadeIn(v2), run_time=0.5)
        self.until(self.c("c6", 1))
        one = note("one inequality, two operating points", 20, FG).move_to([0, -3.4, 0])
        self.play(FadeIn(one), run_time=0.5)
        self.end()


class Cycles(Beat):
    NAME, SEC = "Cycles", "why not count cycles"

    def construct(self):
        self.until(self.c("d1", 2))
        sym = m(r"a^{(p-1)/t} \bmod p", FG, 1.0).move_to([0, 2.5, 0])
        sl = note("power-residue symbol", 20).next_to(sym, DOWN, buff=0.15)
        self.play(Write(sym), FadeIn(sl), run_time=0.9)
        X = [-6.2, -0.8, 1.8]
        tab = table(-6.4, 3.2, 0.7, ["", "dedicated chip", "guest loop"], X)
        self.play(FadeIn(tab), run_time=0.4)

        self.until(self.c("d2", 0))
        r1 = VGroup(note("guest cycles", 22, FG).move_to([X[0], -0.2, 0], aligned_edge=LEFT), tx("365", 24).move_to([X[1], -0.2, 0]))
        self.play(FadeIn(r1), run_time=0.5)
        self.until(self.c("d2", 1))
        l1 = tx("6549", 24).move_to([X[2], -0.2, 0])
        self.play(FadeIn(l1), run_time=0.4)
        self.until(self.c("d2", 2))
        v1 = note("chip looks 17.9× cheaper", 20, BLUE).next_to(l1, RIGHT, buff=0.6)
        self.play(r1[1].animate.set_color(BLUE), FadeIn(v1), run_time=0.5)

        self.until(self.c("d3", 0))
        r2 = VGroup(note("multiplication columns", 22, FG).move_to([X[0], -1.1, 0], aligned_edge=LEFT), tx("382", 24).move_to([X[1], -1.1, 0]))
        self.play(FadeIn(r2), run_time=0.5)
        self.until(self.c("d3", 1))
        l2 = tx("261", 24).move_to([X[2], -1.1, 0])
        self.play(FadeIn(l2), run_time=0.4)
        self.until(self.c("d3", 2))
        v2 = note("chip adds area", 20, RED).next_to(l2, RIGHT, buff=0.6)
        self.play(r2[1].animate.set_color(RED), FadeIn(v2), run_time=0.5)

        self.until(self.c("d4", 0))
        self.play(Create(strike(v1)), v1.animate.set_opacity(0.5), run_time=0.5)
        self.until(self.c("d4", 1))
        concl = tx("state the rule in trace area, not in cycles", 26, BLUE).move_to([0, -2.6, 0])
        self.play(FadeIn(concl), run_time=0.6)
        self.end()


def band_axes():
    ax = Axes(x_range=[1, 8.4, 1], y_range=[0, 66, 16], x_length=6.2, y_length=4.2, tips=False,
              axis_config={"color": RULE, "stroke_width": 1.5, "include_ticks": True}).move_to([-2.6, -0.4, 0])
    xl = m(r"\ell", MU, 0.7).next_to(ax.x_axis, RIGHT, buff=0.15)
    yl = note("native mults per big-field mult", 17).next_to(ax.y_axis, UP, buff=0.15).align_to(ax.y_axis, LEFT)
    xt = VGroup(*[m(str(k), MU, 0.5).next_to(ax.c2p(k, 0), DOWN, buff=0.12) for k in (1, 2, 4, 7, 8)])
    lo = ax.plot(lambda x: x, x_range=[1, 8], color=FG, stroke_width=2)
    hi = ax.plot(lambda x: x * x, x_range=[1, 8], color=FG, stroke_width=2)
    llo = m(r"\ell", FG, 0.6).next_to(ax.c2p(8, 8), RIGHT, buff=0.1).shift(DOWN * 0.12)
    lhi = m(r"\ell^2", FG, 0.6).next_to(ax.c2p(8, 64), RIGHT, buff=0.1)
    return ax, VGroup(ax, xl, yl, xt), VGroup(lo, hi, llo, lhi)


class Prediction(Beat):
    NAME, SEC = "Prediction", "the prediction"

    def construct(self):
        self.until(self.c("e1", 1))
        big = bar(199, 2.9, x0=-4.5)
        ticks, _ = limbs(2.9, x0=-4.5)
        src = note("emulation: big numbers split into limbs", 20).next_to(big, DOWN, buff=0.3).align_to(big, LEFT)
        self.play(Create(big), Create(ticks), FadeIn(src), run_time=1.0)

        self.until(self.c("e2", 0))
        self.play(FadeOut(big), FadeOut(ticks), FadeOut(src), run_time=0.4)
        ax, frame, band = band_axes()
        self.play(FadeIn(frame), run_time=0.5)
        self.play(Create(band[0]), Create(band[1]), FadeIn(band[2]), FadeIn(band[3]), run_time=1.2)
        self.until(self.c("e2", 1))
        p1 = Dot(ax.c2p(1, 1), radius=0.08, color=RED)
        n1 = note("ℓ = 1: nothing to remove", 18, RED).move_to(ax.c2p(1.25, 52), aligned_edge=LEFT)
        n1l = Line(n1.get_bottom() + DOWN * 0.05 + LEFT * 0.6, p1.get_top() + UP * 0.05, color=RED, stroke_width=1.2)
        n1 = VGroup(n1, n1l)
        self.play(FadeIn(p1), FadeIn(n1), run_time=0.5)

        self.until(self.c("e3", 1))
        s1 = m(r"\text{pays} \;\Rightarrow\; \text{mismatched}", BLUE, 0.8).move_to([4.2, 0.8, 0])
        self.play(Write(s1), run_time=0.7)
        self.until(self.c("e3", 2))
        s2 = m(r"\text{mismatched} \;\not\Rightarrow\; \text{pays}", RED, 0.8).move_to([4.2, -0.2, 0])
        self.play(Write(s2), run_time=0.7)
        self.end(keep=[frame, band, p1])


class Tests(Beat):
    NAME, SEC = "Tests", "the tests"

    def construct(self):
        ax, frame, band = band_axes()
        p1 = Dot(ax.c2p(1, 1), radius=0.08, color=RED)
        self.add(frame, band, p1)                      # same state as the end of Prediction
        self.until(self.c("f1", 0))
        em = note("execute mode, SP1", 18).move_to([4.2, 2.6, 0])
        self.play(FadeIn(em), run_time=0.4)

        self.until(self.c("f2", 0))
        q1 = tx("ℓ = 1:      19 cycles / mult", 22).move_to([4.2, 1.6, 0])
        self.play(FadeIn(q1), run_time=0.5)
        self.until(self.c("f2", 1))
        q7 = tx("ℓ = 7:  3121 cycles / mult", 22).move_to([4.2, 0.9, 0])
        self.play(FadeIn(q7), run_time=0.5)
        self.until(self.c("f2", 2))
        q = tx("164×", 30, BLUE).move_to([4.2, 0.0, 0])
        self.play(FadeIn(q), run_time=0.5)

        self.until(self.c("f3", 0))
        fit = ax.plot(lambda x: x ** 1.30, x_range=[1, 8], color=BLUE, stroke_width=3)
        self.play(Create(fit), run_time=1.2)
        self.until(self.c("f3", 1))
        fl = m(r"\propto \ell^{1.30}\ \ (\ell = 2,4,7,8)", BLUE, 0.6).next_to(ax.c2p(8, 8 ** 1.3), RIGHT, buff=0.15).shift(UP * 0.2)
        self.play(FadeIn(fl), run_time=0.5)

        self.until(self.c("f4", 0))
        self.play(*[FadeOut(x) for x in (frame, band, p1, fit, fl, em, q1, q7, q)], run_time=0.5)
        X = [-6.2, -2.0, 0.6, 3.6]
        tab = table(-6.4, 6.4, 2.2, ["chip", "mismatched", "already served", "verdict"], X, caption="three precompiles over the same 199-bit field")
        self.play(FadeIn(tab), run_time=0.5)

        def row(y, name, mis, srv, verdict, col):
            return VGroup(tx(name, 22).move_to([X[0], y, 0], aligned_edge=LEFT), tx(mis, 22).move_to([X[1], y, 0]),
                          tx(srv, 22).move_to([X[2], y, 0]), tx(verdict, 22, col).move_to([X[3] + 0.8, y, 0]))
        self.until(self.c("f4", 1))
        r1 = row(1.3, "Griffin", "yes", "no", "pays (56.4× fewer cycles)", BLUE)
        self.play(FadeIn(r1[:3]), run_time=0.5)
        self.until(self.c("f4", 2))
        self.play(FadeIn(r1[3]), run_time=0.5)
        self.until(self.c("f5", 0))
        r2 = row(0.4, "field multiplication", "yes", "", "", FG)
        self.play(FadeIn(r2[:2]), run_time=0.5)
        self.until(self.c("f5", 1))
        r2b = VGroup(tx("yes (256-bit mul)", 22).move_to([X[2], 0.4, 0]), tx("does not pay", 22, RED).move_to([X[3] + 0.8, 0.4, 0]))
        self.play(FadeIn(r2b), run_time=0.5)
        self.until(self.c("f6", 0))
        r3 = row(-0.5, "power residue", "yes", "yes", "open", MU)
        self.play(FadeIn(r3), run_time=0.5)
        self.until(self.c("f6", 1))
        fz = note("fused chip: control overhead paid 1 time, not 261", 20).move_to([0, -1.4, 0])
        self.play(FadeIn(fz), run_time=0.5)
        self.until(self.c("f6", 2))
        sp = note("deciding experiment specified, not run", 20, MU).next_to(fz, DOWN, buff=0.15)
        self.play(FadeIn(sp), run_time=0.4)

        self.until(self.c("f7", 1))
        fc = tx("open: matched field (ℓ = 1), full proof — forecast: does not pay", 22, FG).move_to([0, -3.0, 0])
        self.play(FadeIn(fc), run_time=0.6)
        self.end()


class Consequence(Beat):
    NAME, SEC = "Consequence", "what this buys"

    def construct(self):
        self.until(self.c("g1", 0))
        f = tx("PLUM verification, 80-bit level:  14.25 min  (finite)", 26, BLUE).move_to([0, 2.6, 0])
        self.play(FadeIn(f), run_time=0.6)
        self.until(self.c("g1", 1))
        qn = note("anonymous credential?", 22, FG).next_to(f, DOWN, buff=0.4)
        self.play(FadeIn(qn), run_time=0.4)
        self.until(self.c("g1", 2))
        ny = tx("not yet", 24, RED).next_to(qn, RIGHT, buff=0.3)
        self.play(FadeIn(ny), run_time=0.4)

        self.until(self.c("g2", 0))
        l1 = tx("affordable proof: STARK  —  not zero-knowledge", 24, RED).move_to([0, 0.6, 0])
        self.play(FadeIn(l1), run_time=0.5)
        self.until(self.c("g2", 1))
        l2 = tx("zero-knowledge wraps: Groth16, PLONK  —  pairing-based", 24, FG).move_to([0, -0.1, 0])
        self.play(FadeIn(l2), run_time=0.5)
        self.until(self.c("g2", 2))
        self.play(l2.animate.set_color(RED), run_time=0.4)
        l2b = note("not post-quantum", 20, RED).next_to(l2, DOWN, buff=0.1)
        self.play(FadeIn(l2b), run_time=0.4)

        self.until(self.c("g3", 0))
        self.play(*[FadeOut(x) for x in (l1, l2, l2b)], run_time=0.4)
        l3 = tx("wrap fails at recursive compression", 24, RED).move_to([0, 0.6, 0])
        self.play(FadeIn(l3), run_time=0.5)
        self.until(self.c("g3", 1))
        l3b = note("the Griffin chip overflows the fixed recursion shapes", 20).next_to(l3, DOWN, buff=0.15)
        self.play(FadeIn(l3b), run_time=0.5)
        self.until(self.c("g3", 2))
        l3c = note("one-time regeneration, not a memory limit", 20, FG).next_to(l3b, DOWN, buff=0.15)
        self.play(FadeIn(l3c), run_time=0.5)

        self.until(self.c("g4", 0))
        self.play(*[FadeOut(x) for x in (l3, l3b, l3c)], run_time=0.4)
        c0 = tx("predicate change", 24).move_to([0, 0.6, 0])
        self.play(FadeIn(c0), run_time=0.4)
        self.until(self.c("g4", 1))
        c1 = tx("static circuit recompile ≈ 0.3 s", 24, FG).move_to([0, -0.2, 0])
        self.play(FadeIn(c1), run_time=0.5)
        self.until(self.c("g4", 2))
        c2 = tx("difference: re-audit footprint, not time", 24, BLUE).move_to([0, -1.0, 0])
        self.play(FadeIn(c2), run_time=0.5)
        self.end()


class Scope(Beat):
    NAME, SEC = "Scope", "scope"

    def construct(self):
        def item(s, y, col=FG):
            return tx(s, 24, col).move_to([-6.0, y, 0], aligned_edge=LEFT)
        self.until(self.c("h1", 0))
        i1 = item("all prove times at the 80-bit level, not a deployment level", 2.7)
        self.play(FadeIn(i1), run_time=0.5)
        self.until(self.c("h1", 1))
        i2 = item("means of 3 runs, one 24 GB laptop", 2.0)
        self.play(FadeIn(i2), run_time=0.5)
        self.until(self.c("h2", 0))
        i3 = item("positive results assume Griffin-AIR constraint soundness (open)", 1.3, MU)
        self.play(FadeIn(i3), run_time=0.5)
        self.until(self.c("h2", 2))
        i4 = item("negative results hold without it", 0.6)
        self.play(FadeIn(i4), run_time=0.5)

        self.until(self.c("h3", 1))
        ineq = MathTex(r"\Delta A_{\mathsf{core}}\,\kappa_{\mathsf{core}}", r"\;>\;", r"A_P\,\kappa_P", color=FG).scale(1.0).move_to([0, -0.6, 0])
        ineq[0].set_color(BLUE); ineq[2].set_color(RED)
        self.play(Write(ineq), run_time=0.9)

        self.until(self.c("h4", 1))
        op = note("open: matched-field proof  ·  fused power-residue chip  ·  post-quantum zero-knowledge wrap", 18, MU).move_to([0, -1.7, 0])
        self.play(FadeIn(op), run_time=0.5)
        self.until(self.c("h4", 2))
        self.play(*[FadeOut(x) for x in (i1, i2, i3, i4, ineq, op)], run_time=0.5)
        t1 = tx("When Does a Precompile Pay?", 36).move_to([0, 0.9, 0])
        t2 = note("A Cost Criterion for Compiling Low-Constraint Post-Quantum Signatures into General-Purpose zkVMs", 18, FG).next_to(t1, DOWN, buff=0.3)
        t3 = note("Takumi Otsuka  ·  Master's thesis, Waseda University, 2026  ·  advisor: Prof. Kazue Sako", 18).next_to(t2, DOWN, buff=0.45)
        self.play(FadeIn(t1), FadeIn(t2), FadeIn(t3), run_time=0.8)
        self.until(self.D)
