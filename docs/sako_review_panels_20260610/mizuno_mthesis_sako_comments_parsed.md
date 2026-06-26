# Sako review-panel comments — mthesis_mizuno (Overleaf, captured 2026-06-10)
# Comments dated 2026-01-17; replies by Mizuno 2026-01-23. Verbatim.

**SAKO:** 書き下す

  reply: done

**SAKO:** 具体的に？

  reply: 具体化してみました

**SAKO:** これは発行元の情報？公開鍵を使っていることとの因果関係を説明できていない

  reply: 公開鍵から発行元がわかり，その情報から属性情報が推測されるという風に書いてみました

**SAKO:** どんな課題？

  reply: 現在標準化が進んでいたり，使われている署名方式の多くが群構造維持署名でないということを明記しました

**SAKO:** referenceがいるのでは

  reply: done

**SAKO:** reference

  reply: done

**SAKO:** この段落の説明は、はじめにに書くには細かすぎ、なのに説明なさすぎ、です。この説明は後にゆずって、全体の方針が書いてあるのがよいと思います。

  reply: はじめにに示すべき背景と全体の方針のために必要な最低限の情報だと思うのですが，いかがでしょうか

**SAKO:** これの説明が必要

  reply: 「公開鍵を認証局などに登録する際に秘密鍵の所持証明も提出するという仮定である」という枕詞を付けたほか，Registered Key Modelに語彙を変更しました

**SAKO:** 提示プロトコルとは

  reply: 証明生成アルゴリズムに変えました

**SAKO:** これがstructure-preserving?

  reply: structure-preserving signature (日本語だと群構造維持署名)は具体的な署名方式ではなく、「グループ署名」のように複数の署名方式の総称を指す言葉です． / 具体的な署名方式の一... / show more

**SAKO:** ポリシーとは

  reply: このコメント時点で25行目にポリシーの説明を加えました / keyboard_arrow_down / 2-preliminaries.tex / 25

**SAKO:** 大文字は群で、小文字は群の要素とする方がわかりやすいのでは

  reply: done

**SAKO:** 群の生成元

  reply: done

**SAKO:** そうなの？reference?

  reply: 標準モデルとはShoupがGGMを定義した際に，GGMで設けた制限を設けない（何の制限も設けない）モデルなので，GGMで「群の具体的な表現（ビット列の構造）は隠蔽されており」と対比させていましたが，そ... / show more

**SAKO:** アブストででてきたCertified Key Modelとの違いは？なんのモデル？（GGMとは違うモデルなのでは）

  reply: 説明の都合上2章の最後に持っていき，名前もRegistered Key Modelにしています．

  reply: というのも，Certified Key Settings / Modelとしている論文よりもKnowledge of the Secret KeyやRegistered Key Modelという名称を... / show more

**SAKO:** システムとは？

  reply: Issuer-Hiding ACシステムと明記しました

**SAKO:** はじめてでてきた

  reply: 後ろに持っていくことで初出で亡くなりました

**SAKO:** ふたつの違いは？

  reply: 他のところでも書きましたが，論文によって同じものの言い方が違ったり，同じ用語で微妙に指しているものが違ったりします． / 今回はRegistered Key Modelに統一する予定です

**SAKO:** この表現だと、定義1が[11]そのもののように思った。

  reply: 修正しました

**SAKO:** BellareとNevenと表現したり、Bellare らと表現したりしないで、統一させて

  reply: done

**SAKO:** 何の定義？

  reply: この節を修正する中で削除しました

**SAKO:** reference

  reply: Extrabilityについて別途説明を記述しました

**SAKO:** そういいきっていいの？証明かreferenceが必要では

  reply: 等価であるとは言い切れなさそうだったので「同様」としました．元論文では "Both proofs reduce to the same computational assumptions used i... / show more

**SAKO:** correctnessもかいて

  reply: done

**SAKO:** referenceと正当性条件

  reply: Correctnessを加えました．コミットメント付きデジタル署名については今回のために定義したという認識ですが，似たような文献がないか調査します

**SAKO:** 有効の意味は？

  reply: 下のCorrectnessでいかがでしょうか

**SAKO:** 意味がわからない。「用いる」ではなく「検討する」？そして、その理由は？

  reply: 理由を追加しました

**SAKO:** why?

**SAKO:** Bonehが提案したのはグループ署名では

  reply: 補足しました

**SAKO:** 署名アルゴリズムとするならここはメッセージでは

  reply: 少なくとも2章はメッセージに統一しました

**SAKO:** メッセージでしょ

  reply: 少なくとも2章はメッセージに統一しました

**SAKO:** 「次に定義する」といれる

  reply: done

**SAKO:** 定義と同じ文字列にして

**SAKO:** 他のところもチェックして

  reply: 2章に関してはSUFに統一しています

**SAKO:** これはなに？

  reply: すでに上で説明しています

**SAKO:** これは別のセクションがよいのでは

**SAKO:** 3.2との違いがわからなくなった

  reply: BobolzらによるIssuer-Hiding ACでなくIssuer-Hiding ACの概要を示すことにし，3.1をIssuer-Hiding ACではなくBobolzらが示した一般的構成について... / show more

**SAKO:** シンタックス？本来かくべきは定義のセキュリティ要件かと。

  reply: セキュリティ要件を先に書こうかと思いましたが，あらかじめシンタックスを書いておかないとpolが説明なしで出てきてしまうためこの順にしました / keyboard_arrow_down / 7-conclusion.tex / 3

**SAKO:** 勝るものは？

  reply: 「その結果，計算モデルでは提案手法のみが / % Standard Model / 標準モデル... / show more

**SAKO:** そうなの？

  reply: 「総じて」という言い方があっているかはわかりませんが，計算モデルは提案方式だけ標準モデルで他はGGMであるためより優れていると言えると思いますし，計算コストもKatzらよりはポリシー生成が早く，他の方... / show more

**SAKO:** つかいまわせるとは？

  reply: 今後の課題の方に移しましたが，別のポリシー作成で使えるか否かのことを指しています / keyboard_arrow_down / main.tex / 10

**SAKO:** 証明者が唐突で何をする人なのかわからない

  reply: ユーザという言葉に変えました

**SAKO:** なんの証明検証かわからない

  reply: クレデンシャルの検証と変えました

**SAKO:** どういう状況なのか、具体的でなく、わからない。

  reply: 現在の書き振りでいかがでしょうか

**SAKO:** 発行元の公開鍵が必要なことと、発行元の情報との関係がとんでいるの、わかりますか。発行元の公開鍵から発行元の情報がわかるということを暗に仮定していませんか。「相手の電話番号が必要となるため、相手の情報が... / show more

  reply: うまく飛んでいた部分を埋めてみました． / いかがでしょうか

**SAKO:** どういう場合がすぐにはわからないので、例があるといいかも

  reply: 例を入れてみました． / 概要なのでさらっと書いてみましたが，もう少し丁寧に例を入れた方が良いでしょうか

**SAKO:** 計算モデルが強力とは？

**SAKO:** なぜそれが問題？

  reply: 計算能力に制限をかけた計算モデルであると書き換えたほか，問題というのは言い過ぎなので標準モデルにできればなお良い程度に書き直しました

**SAKO:** これがなにかわからない

  reply: 「公開鍵の認証局への登録時に対応する秘密鍵を所持していることの証明も示す」という枕詞を付けました

**SAKO:** なにの提案方法かが不明確

  reply: BBS署名を利用したIssuer-Hiding ACを構成したので，それを提案手法と指すと読めるように変えてみました

**SAKO:** なにかわからない

  reply: 初めの方にIssuer-Hiding ACについて軽く説明し，その際にポリシーについても説明を加えました

  reply: またポリシー作成，証明生成，証明検証についても何を指しているのかわかるようにIssuer-Hidign ACの説明時に「〜（ポリシー作成）」のようにし，分かりやすくしてみました

**SAKO:** 唯一とは？

  reply: 比較した4方式の中で唯一と明記しました

**SAKO:** 提案方式　とか提案という言葉をどこかにいれた方がよいのでは / description / Current file / list / Overview / chevron_right / arrow_right_alt / arrow_left_alt / Recompile / expand_more / description / 1 / download / keyboard_arrow_up / keyboard_arrow_down / / 55 / remove / add / 104% / 令和 / 7 / 年度 修士論文 / Issuer-Hiding Veriﬁable Credentials / の実 / 現の検討 / Consideration of Issuer-Hiding Veriﬁable Credentials / 水野 / 重弦 / 早稲田大学 / 基幹理工学研究科 / 情報理工・情報通信専攻 / 5124F101-4 / 提出日 / : / 令和 / 8 / 年 / 1 / 月 / 26 / 日 / 研究指導名 / : / 暗号プロトコル研究 / 指導教員 / : / 佐古 和恵 教授 / 概要 / World Wide Web Consortium (W3C) / が標準化を進める / Veriﬁable Credentials (VC) / は，ユーザが / 必要な属性のみを選択的に開示する「選択的開示」が可能な属性情報の証明書である．ただし， / 証明書の検証のために / VC / の発行元の公開鍵を参照する際，その鍵に紐づく発行元自体も特定 / される．発行元の情報がユーザの属性情報となる場合，検証者に属性を推測される可能性があ / る．例えば，早稲田大学の学生に対して学生証が / VC / として発行されていた場合，発行元が「早 / 稲田大学」であるということがわかると，学生が早稲田大学の学生であるということがわかっ / てしまう．そこで， / VC / でも用いることが一部検討されている / Anonymous Credentials / （ / AC / ）に / おいて，発行元の公開鍵を秘匿したまま証明書の検証を可能にする / Issuer-Hiding AC / が提案さ / れている． / Issuer-Hiding AC / では，証明書の検証を行う検証者が受け入れ可能な発行元の公開 / 鍵をポリシーに記載（ポリシー作成）し，ユーザはこのポリシー内に実際の証明書の発行元が含 / まれていることを証明する（証明生成）ことで，検証者が発行元を匿名にされたまま証明書の検 / 証（証明検証）をすることを可能とする．しかし，既存の / Issuer-Hiding AC / では，標準化され / ていない群構造維持署名方式を前提としていたり，計算コストやデータサイズが大きいなどの / 問題がある．また，計算能力に制限をかけた計算モデルである / Generic Group Model / を仮定に / おいており，計算能力に制限をかけない標準モデルのもとで安全性が証明することができれば， / なお良い．そこで本稿では標準化が進んでいる / BBS / 署名を利用し，公開鍵の認証局への登録 / 時に対応する秘密鍵を所持していることの証明も示す / Registered Key Model / を仮定することで / 標準モデルの下でも / Issuer-Hiding AC / を構成できることを示した．また，既存の / Issuer-Hiding / AC / の / 3 / 方式と提案した / Issuer-Hiding AC / の方式を計算モデル，計算コストやデータサイズの / 面で比較・評価した．その結果，提案方式は既存方式と比較してポリシー作成時の計算コスト / が最も低く，証明生成や証明検証の処理速度も高速であることを確認した．また，提案方式は / 比較した / 4 / 方式の中で唯一，計算モデルが標準モデルであることから，セキュリティ面でも優 / れていると考えられる．さらに，本稿では / Issuer-Hiding AC / を用いた / Veriﬁable Credentials / を / 構成するために， / VC / と / Issuer-Hiding VP / のデータフォーマットを提案した． / Dimensions / close / Close / Search Dimensions to find research papers.

