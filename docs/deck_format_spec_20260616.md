# Deck format spec (lock for the Thesis-A rebuild) — 2026-06-16

Captured from the live deck so a ground-up rebuild stays visually identical. Every new or
restructured slide must obey this. Source: 修論進捗報告20260616_大塚.pptx.

## Canvas
- Slide size: 13.33 x 7.5 in (16:9).
- Content slides use the layout named **"Default"** (custom). Title slide uses "タイトルスライド".

## Title bar (every content slide)
- Placeholder "Title 1": left 0.37 in, top 0.39 in, width ~12.6 in, height ~0.79 in.
- Font: theme major-latin, **26 pt**, color = theme **accent1 (#0099CC, cyan)**.
- The cyan vertical accent bar at the far left is part of the layout; do not redraw it.
- Title text = a functional section name (Background, Evaluation, Contributions, ...),
  punch only in the body tagline. No aphorisms, no questions as titles.

## Body
- Body placeholder: left 0.37 in, top ~1.55 in, width ~12.6 in.
- Body font: theme major-latin (renders Arial Nova family), **16 pt**, color **#202020** (near-black).
- Bullets: char "•", bullet color **accent2 (#FF0066, magenta)**, hanging indent (marL 342900, indent -342900).
- Numbered lists: buAutoNum arabicPeriod, number in **accent2 magenta**, +mj-lt font.
- Sub-bullets: marL ~571000, indent -285750, "•", body sz ~12.5 pt.
- Secondary / footnote text boxes: **Arial Nova, 11 pt, color #3A3838 (dk1)**.

## Footer (every content slide, bottom)
- "Waseda University Sako Laboratory" text box at left ~8.99 in, top 6.95 in.
- "Page N" text box at left ~12.02 in, top 6.95 in.
- The Waseda logo sits to their left (part of the layout area).

## Color palette (theme)
- accent1 #0099CC (cyan) — titles, section headers.
- accent2 #FF0066 (magenta) — bullets, list numbers, emphasis marks.
- dk1 #3A3838 — body / footnote text.
- accent text in S5 Venn glosses uses the same blue as the circle.

## Charts (native, not images)
- COLUMN_CLUSTERED, one series "Prove time (min)", data labels outside-end, number format "0.#",
  category labels ~10 pt, value axis ~9 pt, no legend, title ~11 pt. Lower-is-better noted in the title.

## Discipline carried on every slide (do not dilute)
- lambda=80 disclosed as observability ceiling wherever a headline number appears.
- Aurora = Loquat-Fp127 proxy caveat rides with every ~22 min / 3.76 min figure.
- No em-dashes; no "e.g./i.e./etc."; every term defined at/before first use.
- Numbers only from the verified ground-truth set.
