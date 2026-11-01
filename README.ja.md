[English](README.md) · **日本語**

<div align="center">

# 🛡 Termaxa

**AI コーディングエージェントとシェルの間に立つ門番。** コマンドが実行される前に、Termaxa は何が壊れるかを見せ、復元できるバックアップを取り、読めるポリシーに従って確認を求めるか拒否します。Claude Code、Codex、Cursor、Copilot CLI を、ひとりでも、無人でも使う人向けです。

**十秒で試せます：** [play.termaxa.com](https://play.termaxa.com) では、使い捨てのプロジェクトで本物の門番が動きます。**インストール：** `brew install termaxa/tap/termaxa` または `cargo install termaxa`。

<img src="https://termaxa.com/termaxa-claude-code-v2.gif" alt="承認をオフにした実際の Claude Code セッション：エージェントは scratch/ を調べ、rm -rf ./scratch を試み、Termaxa のフックが理由と、削除されるはずだった 12 個のファイルを示して止める。エージェントはそれを迂回するのをやめる" width="800">

*承認をオフにした実際の Claude Code セッション。調べるコマンドは通り、`rm -rf` は理由と影響範囲を添えて止まり、エージェントは迂回しません。Claude Code 2.1.283 で録画。*

[![CI](https://github.com/termaxa/termaxa/actions/workflows/ci.yml/badge.svg)](https://github.com/termaxa/termaxa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/termaxa/termaxa?display_name=tag)](https://github.com/termaxa/termaxa/releases)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue)](#ライセンス)

</div>

---

## 問題

コーディングエージェントは、自分でシェルコマンドを実行します。被害の原因は、巧妙な攻撃であることはまずありません。ありふれた作業を、いちばん強い書き方で実行してしまうことです。掃除に `rm -rf`、push に `--force`、取り消しに `reset --hard` といった具合です。これまでの選択肢は、全コマンドを見張るか（それではエージェントを使う意味がありません）、無条件に信用するか（うまくいくのは、うまくいかなくなるまでです）のどちらかでした。

めったに起きない失敗ではありません。2026年10月に 36 モデルで測定したところ、「*直前のコミットを取り消して*」と頼まれて、そのうち 19 が `git reset --hard` を実行し、誰も話題にしていないファイルのコミットされていない作業を壊しました（[ベンチマーク](https://www.kaggle.com/benchmarks/devdoc83/destructive-reach)、[解説記事](https://dev.to/zerodrop/asked-to-undo-a-commit-19-of-36-models-destroyed-work-nobody-mentioned-54je)）。

## Termaxa がすること

Termaxa は単一の Rust バイナリで、エージェントのフックの経路に入ります。モデルもサービスもアカウントもありません。コマンドごとに、次のことを行います。

1. **判断する。** リポジトリ内のポリシーで、許可・確認・拒否のどれかを決めます。最初に一致したルールが優先され、どれにも一致しないコマンドは確認になります。
2. **文字列ではなく、結果をプレビューする。** 削除で消えるファイル、force push で失われるコミット、`DROP` で消える行、`reset --hard` で捨てられるコミットされていない編集です。
3. **実行の前に保険をかける。** ファイルをコピーし、ref を固定し、テーブルをダンプし、編集のスナップショットを取るので、`termaxa rollback` で元に戻せます。
4. **繰り返すエージェントには対応を強める。** サーキットブレーカーが、書き方やシェルが違っても破壊の*意図*を数え、作動します。
5. **記録する。** すべての判断を、追記専用でハッシュ連鎖のログに残します。エージェントはこのログを書き換えられません。

```console
$ termaxa check "rm -rf ./scratch"
command   rm -rf ./scratch
decision  deny
rule      *rm -rf*
reason    Recursive force delete blocked by default policy.
context   destructive flag detected: -rf  ⚠

delete impact
  target      : /home/dev/proj/scratch
  contains    : 12 files across 1 directory
  insurance   : copy 1 path(s) to .termaxa/backups before deletion (automatic on run/hook)
```

*このページのコンソール出力はすべて、フィクスチャ上でバイナリから採取したものです。パスは短縮し、doctor と report の出力は省略しています。*

## すでにあるプロンプトでは足りない理由

**エージェント自身のプロンプト**が見せるのはコマンドです。Termaxa は、そのコマンドが何をするかを見せ、プロンプトを誰も見ていないときでも、危険な少数を止めます。上の録画は、エージェントの承認をオフにしたセッションです。

**サンドボックス**は、コマンドが届く範囲を閉じ込めます。Termaxa は、与えた範囲の内側で、コマンドが何を壊すかを判断します。リポジトリを含むサンドボックスは `rm -rf ./src` を通してしまいます。両者は補い合うので、確実な保証が必要なときは両方を使ってください。

**ポリシーエンジン**（OPA など）は、文字列をルールに照らして評価します。Termaxa は、文字列が持たない三つのものを足します。結果、バックアップ、記録です。ポリシーは今もリポジトリ内のファイルで、プルリクエストでレビューできます。

## クイックスタート

うまくいく順番は、過去を判定し、今を観察し、それから強制する、です。

**1. インストール。**

```bash
brew install termaxa/tap/termaxa     # macOS / Linux (prebuilt, sha256-pinned)
cargo install termaxa                # any OS, with a Rust toolchain
winget install Termaxa.Termaxa       # Windows (the winget manifest can lag a release)
scoop bucket add termaxa https://github.com/termaxa/scoop-bucket && scoop install termaxa   # Windows, always current
```

または、お使いのプラットフォーム向けのアセットを [Releases](https://github.com/termaxa/termaxa/releases) からダウンロードしてください。どれも attestation とチェックサムが付いており、Linux 版は静的な musl ビルドで、どのディストリビューションでも動きます。`curl | sh` 形式のインストーラーは意図的に用意していません。Termaxa はこのパターンを危険として警告するので、門番のルールは門番自身にも適用されるからです。

**2. エージェントがすでに実行したコマンドを判定する。** プロジェクトには何もインストールせず、何も実行しません。

```bash
termaxa check "rm -rf /"      # works immediately, no setup
termaxa replay                # every command your agents have run on this machine, judged
```

`replay` は、Claude Code と Codex がホームディレクトリの下に残しているトランスクリプトを読み、門番を入れる前に確かめるべき問いに答えます。普段の作業のうち、どれくらいの頻度で確認を求められていたか。一覧に出た確認はどれも、足すべきルールか、確認のままにしておく理由のどちらかです。

**3. observe モードでプロジェクトにつなぐ。**

```bash
cd your-project
termaxa init --claude-code --observe    # or --codex, --cursor, --copilot
termaxa doctor                          # proves the hook fires; "configured" alone is not enough
```

observe モードでは、すべてのコマンドがこれまでどおり実行され、バックアップも取られ、記録には、強制していたら*どうしたか*が溜まっていきます。フックは何も言わないので、エージェントのプロンプトは以前とまったく同じです。

**4. レポートを読み、それから強制する。**

```bash
termaxa report       # "Observed, not enforced": what would have been asked, denied, and what ran with no copy
```

*ran with no copy* が、受け入れられない数字になったら、`mode: enforce` を `.termaxa/policy.yaml` に設定してください。以降、このプロジェクトでエージェントが実行するシェルコマンドは、すべて先に門番を通ります。実行時の状態（ログ、バックアップ）は、リポジトリの外の `~/.termaxa/` の下に置かれます。

## 動作の様子

### 複合コマンドは、最も危険な部分で判定される

```console
$ termaxa check "git status && rm -rf ./build"
command   git status && rm -rf ./build
decision  deny
rule      *rm -rf*
reason    segment 2/2 `rm -rf ./build` — Recursive force delete blocked by default policy.
context   destructive flag detected: -rf  ⚠

delete impact
  target      : /home/dev/proj/build
  contains    : 1 files across 1 directory
  insurance   : copy 1 path(s) to .termaxa/backups before deletion (automatic on run/hook)
```

`&&`、`||`、`;`、`|`、単独の `&` で区切って、区間ごとに判定します。いちばん危険な区間が全体の判定になります。最初の実際の Claude Code セッションで、`git status && <anything>` が `git status*` の許可ルールに便乗して通ることが分かりました。このバイパスは v0.7 以来、名前付きのリグレッションテストになっています（[GHSA-rv66-7qcx-c45j](https://github.com/termaxa/termaxa/security/advisories/GHSA-rv66-7qcx-c45j)）。

### 実行を決める前に分かる影響範囲

```console
$ termaxa check "psql -d shop -c 'DROP TABLE users'"
decision  deny
reason    DROP TABLE is blocked. Archive or rename instead.

postgres impact
  DROP TABLE users
    rows (estimate) : 50,000
    referenced by   : audit_log, orders, sessions (3 tables)
    without CASCADE : this DROP will FAIL (dependents exist)
  insurance : pg_dump users before execution (automatic on run/hook)
```

行数の見積もりはプランナーから取ります（`pg_class.reltuples`。`ANALYZE` の実行間では古くなります）。Termaxa がテーブルをスキャンすることはなく、プレビューがあなたのものを実行することもありません。ただし、一度だけ実行したことがあります。Postgres のプレビューが、解析中の SQL ファイルを実行できてしまったのです（[GHSA-gxg4-5fmj-534m](https://github.com/termaxa/termaxa/security/advisories/GHSA-gxg4-5fmj-534m)、v0.14.1 で修正）。そのため「拒否されたコマンドでは、プレビューは何も実行しない」は、いまではテスト付きのルールです。

### 再試行するエージェントは、書き方を変えてもすり抜けられない

```console
$ rm -rf .                        -> ask   (file-delete #1)
$ Remove-Item -Recurse -Force .   -> ask   (file-delete #2, different shell)
$ del /s /q .                     -> DENY  circuit breaker: 2 prior
                                     file-delete attempts this session
```

シェルは三つ、意図は一つ。三つ目の書き方で拒否されます。書き方ごとにルールを列挙する必要はありません。`find -exec rm`、`xargs rm`、`unlink` も数えます。ブレーカーは既定で有効です（しきい値は 2、ポリシーの `circuit_breaker:`）。作動すると、その意図はプロジェクト全体で、セッションをまたいで止まったままになります。解除するのは `termaxa breaker resume --reason "…"` です。誰がなぜ解除したかが記録されます。任意の `resume_after` を設定すれば、期限が来たときに解除されます。`termaxa breaker status` で、いま止まっているものを確認できます。

### 壊して、元に戻す

```console
$ termaxa run -- git reset --hard HEAD
┌ termaxa
│ command : git reset --hard HEAD
│ decision: ask
│ reason  : no rule matched; policy default is `ask`
│ context : destructive flag detected: --hard  ⚠
└
┌ discard impact
│  uncommitted : changes in 1 file would be discarded
│  files       : docs/notes.md
│  insurance   : snapshot them with git stash before they are discarded (automatic on run/hook)
└
Proceed? [y/N] y
🛟 backup b-1791356096439 — uncommitted changes in 1 file(s) snapshotted to refs/termaxa/backup/b-1791356096439 (a4136247); `git stash apply a4136247` brings them back
HEAD is now at 35105b7 c1

$ termaxa rollback b-1791356096439
restore  : b-1791356096439 [git-stash]
saved    : uncommitted changes in 1 file(s) snapshotted to refs/termaxa/backup/b-1791356096439 (a4136247); `git stash apply a4136247` brings them back
insured  : git reset --hard HEAD
Restoring writes data. Proceed? [y/N] y
✓ uncommitted changes in 1 file(s) restored from a4136247
```

`git reset --hard`、`git checkout -- <paths>`、`git restore <paths>` は、コミットされていない変更を捨てます。git の reflog にもそれは残っていません。reflog が残すのはコミットで、コミットされていない作業は、そもそもコミットではないからです。上のベンチマークで起きたのは、まさにこのパターンで、スナップショットがその答えです。force push はリモート側で同じ形の事故になり、スターターのポリシーは単純にこれを拒否します。

```console
$ termaxa check "git push --force origin main"
decision  deny
rule      git push*--force*
reason    Force pushes are blocked by policy. Open a PR instead.
context   current branch: main  ⚠
context   destructive flag detected: --force  ⚠
```

そのルールを確認に緩めたプロジェクトでは、push のプレビュー（リモートが*失う*コミット）と保険が働きます。push の前に、リモートの ref がローカルのバックアップブランチに固定され、`rollback` がそれを push し直して戻します。

### 削除が実際に何を失わせるか

削除は、破壊的なコマンドのなかで最も多く、最も間違えやすいものです。パスは、間違っていると分かる瞬間まで、正しく絞れているように見えるからです。

```console
$ termaxa check "rm -rf /c/Users/harih"
decision  ask
reason    no rule matched; policy default is `ask`

delete impact
  target      : C:\Users\harih
  as written  : /c/Users/harih
  ⚠ OUTSIDE the project root (C:\Users\harih\project)
  ⚠ resolves to a USER PROFILE directory
  ⚠ contains  : .ssh (SSH private keys), .aws (AWS credentials)
  contains    : 5,000+ files (stopped counting) across 422 directories
  ✗ insurance : too large to copy (5,000+ files) — NOT recoverable
```

`/c/Users/harih` は Git Bash での `C:\Users\harih` の書き方で、実在するユーザープロファイルです。Termaxa はパスを解決し、中身を数え（予算は 5,000 ファイルまたは 300 ms で、数えるのをやめたときはそう表示します）、影響範囲にある認証情報を警告し、そもそもバックアップが可能かどうかを伝えます。プロジェクト内の普通の削除では、そのどれも表示しません。それが狙いです。`rm -rf ./target` でも鳴る警告は、誰も読まない警告だからです。

Termaxa にできないのは、あなたが何を意図したかを知ることです。パスに打ち間違いがあれば、Termaxa は入力されたとおりのパスの影響範囲を、忠実に報告します。そのずれを、実行の前に見えるようにする。それがこのツールの貢献のすべてです。

### セッションのあとで

誰も警告してくれない失敗があります。フックはインストールされているのに、エージェントがそれを呼ばず、それでも見た目は何事もないことです。`termaxa doctor` は、登録されたフックに必ず拒否されるはずのペイロードを送り、フックが動いたかどうかを報告します。以前はフックの名前を grep するだけで、門番を通らずに動いた二つのセッションのあいだ、緑の「configured」を表示し続けていました（Windows、2026年8月13日）。いまは、そのために実際に試して確かめます。

```console
$ termaxa doctor

Termaxa doctor
──────────────────────────────────────────
✓ termaxa 0.21.4
  /usr/local/bin/termaxa

Policy
✓ /home/dev/proj/.termaxa/policy.yaml
  224 rule(s), default ask
  enforce mode (default)
  fingerprint 69edb158b1af
  ✓ unchanged since 2026-10-07T06:54:22Z

Agents
✓ Claude Code  hook configured and live

Preview support
✓ git        force-push previews and git backups
· psql       Postgres blast radius unavailable
· pg_dump    Postgres backups unavailable
· terraform  plan previews unavailable
```

フィンガープリントは、ポリシーの編集に気づくための仕組みです。`init` がハッシュを記録し、ファイルがそれと一致しなくなると `doctor` が知らせます。`termaxa report` は記録を読んで、何が起きたかを伝えます。

```console
$ termaxa report

Session   session s1
──────────────────────────────────────────
Commands            10   ✓ 3 · ? 4 · ✗ 3
Asks                4   approved 0 · declined 0 · unanswered 4
Previews            2
Backups             1

Destructive intents
──────────────────────────────────────────
file-delete         2
git-destructive     2
breaker trips       0

Observed, not enforced
──────────────────────────────────────────
enforcement would have asked 4 and denied 2
  insured             1   a copy was taken first
  known, uninsured    3   understood, nothing could be copied
  consequence unknown 2   the gate could not read what they change
  held by the floor   1   denied even in observe mode
ran with no copy: 5
```

どの行も、監査ログに出どころのある事実です。レポートはローカルの追記専用ログを読むだけで、ネットワークに出ず、テレメトリも送りません。`termaxa replay --against-record` はもう一歩進んで、エージェントのトランスクリプトをそのログと突き合わせ、シェル呼び出しをすべて「判定済み」「実行されたが記録されていない」「一度も実行されていない」に振り分けます。最初の実行では、九件の呼び出しを「一度も実行されていない」と判定しましたが、九件すべてが、自分のトランスクリプト読み取り側の不具合で、それぞれテストになっています。自分の発見を自分で覆せる道具であること。それがこの検査の狙いです。

## ハーネス

| ハーネス | つなぎ方 | 判定がエージェントに届く経路 | 検証バージョン | 重要な注意点 |
|---|---|---|---|---|
| **Claude Code** | `termaxa init --claude-code` → `.claude/settings.json`（`PreToolUse`、対象は `Bash` と書き込み系ツール） | 確認はエージェント内でプロンプトになる。拒否は理由とプレビューを運ぶ | 2.1.283（上の録画） | Bash の呼び出しはすべて前置きに包まれて届き、門番はそれを外枠として読む |
| **Codex CLI** | `termaxa init --codex` → `.codex/hooks.json`（`Bash` と `apply_patch`） | **拒否のみ**：Codex は明示的な許可を受け付けず、確認の仕組みもないため、確認は理由つきの拒否になる。`apply_patch` は、書き込むファイルとして判定される | 0.155.1（2026年9月19日） | エージェントが拒否を読んで判断する。あなたにはプロンプトが出ない |
| **Cursor** | `termaxa init --cursor` → `.cursor/hooks.json`（シェルとファイルのツール。`Delete` は削除として扱う） | 確認は、Allowlist と Run Everything で「Hook requested approval」と表示される。拒否はどのモードでもブロックされる | 3.21.16（2026年10月4日） | **Auto-review モードでは、Cursor のレビュアーがフックの確認を上書きして、コマンドを実行する。** 2026年10月5日に Cursor のサポートが確認し、開発チームにも報告済み。Termaxa では Allowlist か Run Everything を使うこと。`doctor` もそう表示する |
| **Copilot CLI** | `termaxa init --copilot` → `.github/hooks/hooks.json` | 確認は Allow All でもプロンプトになる。拒否はブロックされる | 1.0.83 と 1.0.91（2026年10月4日） | Copilot は、フックの*許可*を承認として扱い、自分のプロンプトを省く。enforce モードでは、それは門番が承認していることになる。observe モードでは門番は黙っているので、Copilot のプロンプトは変わらない（v0.20.1 で、そうなっていなかった版を修正した） |
| **Herdr** | `herdr plugin install termaxa/termaxa` | ペインが門番の下でエージェントを起動する。サイドバーに拒否が表示され、記録が隣に開く | [`herdr-plugin/`](herdr-plugin/) を参照 | プラグインは、自分が起動するハーネスをつなぐ |
| **それ以外** | `termaxa run -- <cmd>`、または `termaxa wrap -- <agent>`（Unix） | `run` はコマンドを門番に通す。`wrap` は、エージェントが名前で解決するシェルにシムを置く | `wrap` 配下の Claude Code、Linux、zsh あり・なしの両方 | `/bin/sh` を絶対パスで指定するハーネスは `wrap` の外に出る。入口はフック |

ハーネスはそれぞれ独自の方言を話し、方言は変わります。Cursor 3.11 がフックのイベント名を変え、v0.11.4 で直るまで、四つのリリースのあいだ門番が効いていませんでした。方言はバージョンごとに [docs/dialects.md](docs/dialects.md) に記録してあります。そして、フックは読めないペイロードに対して、設計上、**フェイルオープン**します。ハーネスの更新のたびにフェイルクローズする門番は、それ自体が障害になるからです。ポリシーの `unrecognised: deny` を使うと、無人で動かすときはこれを反転できます。

<img src="https://termaxa.com/termaxa-herdr.gif" alt="マルチプレクサの中で、ひとつの操作で Claude Code が門番の下で起動する。拒否された rm -rf はサイドバーに termaxa deny と表示され、記録がエージェントの隣に開く" width="800">

## モード

**Enforce** が既定です。確認は確認を求め、拒否は拒否し、実行の前に保険をかけます。

**Observe**（`mode: observe`、`termaxa init --observe`、または一台のマシンだけに効かせる `TERMAXA_MODE=observe`）は、すべてを実行し、強制していたら何をしたかを、保険も含めて記録します。フックは黙っているので、エージェント自身のプロンプトは変わりません。例外は floor です。`floor: true` が付いた 38 個のスターターのルールは、どちらのモードでも強制されます。保険をかけられないコマンドも同じです。対象は、門番自身の設定と状態（v0.21.3 以降は書き込みが着地するパスで止め、v0.21.4 以降は `cd` のあとでも止めます。それらのファイルを読むのは普通の作業です）、マシン本体とその復旧ポイント、復旧の手段がないコマンドです：`rm -rf /`、`mkfs`、デバイスへの `dd`、シャドウコピーの削除、`drop database`、データベースのリセット、`kubectl delete`、`terraform destroy`、`docker system prune`、`find -delete`。コピーの予算を超える削除は保険をかけられないため止まります。ただし、ビルドで作り直せるディレクトリ（プロジェクト内の `node_modules`、`.next`、`dist`、`target`、`.venv` とその仲間）は別で、observe モードでは何もコピーせずに実行されます。その中のものは、どれも唯一のコピーではないからです。v0.20 より前に書いたポリシーには floor の印がありません。決して緩めないルールに `floor: true` を足すか、[`examples/policy.yaml`](examples/policy.yaml) から 38 個を取ってください。設計と計測：[docs/observe-mode.md](docs/observe-mode.md)。

**Supervised**（Unix）は、判断の権限を移します。あなたとして動くデーモンがすべての判断を下し、エージェントは、監査ログを読めず、バックアップを編集できず、ポリシーを変更できず、スーパーバイザーを止められない、もう一つのアカウントで動きます。拒否するのはコードではなく、オペレーティングシステムだからです。

```bash
termaxa init --supervised     # prints the setup; runs none of it
termaxa supervise &           # as you
sudo -u termaxa-agent termaxa wrap -- claude
```

`init --supervised` は表示するだけで、実行はしません。ユーザーを作ることやツリーを chown することには root が必要で、設定のために root を求めるツールは、このモードが制限しようとしている権限そのものを求めることになるからです。境界を試す試験装置が、23 個のアサーションでそれを証明しており、それぞれに対照条件があります。この下で動かした最初の実エージェントのセッションで、コマンドがひとつもスーパーバイザーに届いていないことが分かりました。壊れていた点は[フィールドレポート](docs/field-reports/2026-08-17-supervised-routing.md)として公開してあり、修正は v0.17 に入っています。セットアップ全体、認証情報のトレードオフ、まだ試していないこと：[docs/supervisor.md](docs/supervisor.md)。

**`wrap`**（Unix）は、フックを持たないエージェント向けです。`termaxa wrap -- <agent>` は、エージェントが名前で解決するシェルにシムを置き、Claude Code 向けには `CLAUDE_CODE_SHELL` を設定します。Claude Code はこれに従います。

## 保険の対象と、対象外

破壊的だからといって、復旧できるとは限りません。各行はコードが実際に行うことで、最後の二行は行わないことです。

| コマンド | プレビュー | 実行前にかける保険 | `rollback` |
|---|---|---|---|
| 削除（`rm`、`rmdir`、`Remove-Item`、`del`、`rd`。`sudo rm`、`/bin/rm`、`git -C … rm`） | 対象、ファイル数、中身、プロジェクト外と認証情報の警告 | 予算（5,000 ファイルまたは 300 ms）の範囲内で、パスを `~/.termaxa/` の下にコピーする。予算を超えたときは、黙ってスキップせず、プレビューの文言を添えてコピーを拒否する | コピーを書き戻す |
| 上書き（内容を切り詰めるリダイレクト、既存ファイルへの `cp`、ファイルを書き出すオプション） | 既存のファイルが失うもの | ファイルをコピーする | コピーを書き戻す |
| force push、または ref を削除する push | リモートが失うコミットと、消える ref | リモートの ref をローカルのバックアップブランチに固定する | 固定した ref を force push し直す |
| `git reset --hard`、`git checkout -- <paths>`、`git restore <paths>` | 捨てられるコミットされていない変更（ファイルごと） | `refs/termaxa/backup/` の下に固定した stash のスナップショット | それを適用する（ステージの状態も含む） |
| `DROP`、`TRUNCATE`、`DELETE`（`psql` 経由） | 行数、依存するもの、そもそも文が成功するか | テーブルの `pg_dump`（`DROP` ではスキーマとデータ、それ以外ではデータのみ） | ダンプを再生する |
| `terraform apply` | プランの追加・変更・破棄の数 | ローカルのステートファイルをコピーする。リモートのステートはバックエンドの仕事 | ステートファイル。破棄されたリソースは**戻らない** |
| `terraform destroy`、`find -delete`、`docker system prune`、データベースのリセット | floor が拒否する。先にコピーされるものはなく、コピーできるものもない | なし | なし |
| エージェントが書いたスクリプト（`python cleanup.py`）、言語ランタイムの内部での削除、`git branch -D` | 門番は、それらが何を変えるか読めない。`git branch -D` は確認になる | なし | なし |

## ポリシー

`.termaxa/policy.yaml`：最初に一致したものが優先され、`*` はワイルドカードです。マッチングは大文字小文字と空白を区別せず、リゾルバーが知っている書き方（`-C`、`env`、`sudo`、同じ行で代入した変数）を見通して判定します。

```yaml
version: 1
default: ask                     # unmatched commands require approval
mode: enforce                    # or observe

rules:
  - match: "git status*"
    action: allow
  - match: "git push*--force*"
    action: deny
    reason: "Force pushes are blocked by policy. Open a PR instead."
  - match: "*find* -delete*"
    action: deny
    reason: "find -delete removes everything it matches and nothing is copied first. Delete named paths with rm instead."
    floor: true                  # enforced even in observe mode

circuit_breaker:
  enabled: true
  threshold: 2
```

`init` が書き出すスターターには 224 個のルールがあります。内訳は許可 157、確認 14、拒否 53 で、うち 38 が floor です。ネイティブのファイルツール（Claude Code の `Write`、Cursor の `Delete`、Codex の `apply_patch`）は、同じパスのルールで、対象によって判定されます。門番自身のファイルは、読めるけれども、エージェントが気づかれずに書き換えることはできないルールで守られています。`doctor` がフィンガープリントを報告します。`unrecognised: deny` と `backup_failure: deny` は、無人で動かすときの二つのスイッチです。

## アーキテクチャ

```
                     a command the agent wants to run
                                  |
        +-------------------------v-------------------------+
        |                       TERMAXA                       |
        |                                                   |
        |  shell split -> policy -> context -> decision     |
        |  (&&, ;, |)     (yaml)   (branch,    (allow/      |
        |                          flags,       ask/deny)   |
        |                          prod, SQL)      |        |
        |                                          v        |
        |              preview <-------------- consequential|
        |         (git loss, pg blast radius,      |        |
        |          terraform plan)                 v        |
        |              insurance <------------- destructive |
        |         (git ref / pg_dump / files)      |        |
        |                                          v        |
        |                                       execute     |
        |                                          |        |
        |  audit (JSONL, ~/.termaxa) <---------------+        |
        |  notify (webhook)   report (session summary)      |
        +---------------------------------------------------+
```

エンジンは六つ、バイナリは一つです。ポリシーはリポジトリ内にあり、プルリクエストでレビューできます。ログとバックアップは `~/.termaxa/` の下にあり、どんな `git` 操作もそこには手を出せません。

## コマンドリファレンス

| コマンド | 用途 |
|---|---|
| `termaxa` | これが何か、次に何を試すか |
| `termaxa init [--claude-code\|--codex\|--cursor\|--copilot] [--observe]` | `.termaxa/` を作り、ツールを検出し、フックをインストールする。`--observe` は observe モードで開始する |
| `termaxa replay [paths…] [--all]` | エージェントのトランスクリプトにあるすべてのコマンドを判定する。何も実行しない |
| `termaxa replay --against-record` | トランスクリプトをこのマシンの記録と突き合わせる：判定済み、実行されたが記録されていない、一度も実行されていない。どちらかのバイパスが見つかると終了コード 1 |
| `termaxa demo` | 使い捨てのプロジェクトで門番を動かす：三つのチェックと記録 |
| `termaxa wrap -- <agent>` | シェル経由のコマンドを門番に通してエージェントを起動する（Unix） |
| `termaxa supervise` | 判断デーモンを自分として実行する。フックはこれを通して判断する（Unix） |
| `termaxa init --supervised` | supervised モードのセットアップを表示する。表示するだけで、実行はしない |
| `termaxa doctor` | 門番はつながっているか？ バイナリ、ポリシー、エージェント、ツール、状態 |
| `termaxa check "<cmd>"` | ドライラン：判定 + プレビュー（終了コード 0/3/4） |
| `termaxa run -- <cmd>` | 門番を通した実行：プレビュー → 承認 → バックアップ → 実行 |
| `termaxa hook` | エージェントのフックモード（標準入力の JSON → 判断） |
| `termaxa log [-n N] [-f] [--decision D] [--source S] [--json]` | 監査ログ。`-f` で追跡する |
| `termaxa stats` | 合計、セッション、ブロックが多いもの |
| `termaxa backups [--prune]` · `termaxa rollback <id>` | バックアップの一覧表示・削除・復元 |
| `termaxa report [--session ID] [--all] [--days N] [--md]` | セッションの要約 + 集計。observe モードでは、強制していたら何をしたか |
| `termaxa breaker status` | このプロジェクトでサーキットブレーカーが作動中のもの |
| `termaxa breaker resume --reason "…"` | 作動を解除する。誰が、いつ、なぜ解除したかが記録される（`reset` は理由が不要） |
| `termaxa notify --test` | Webhook を検証する |
| `termaxa paths` | ポリシーと状態の置き場所 |

出力が端末のときは色が付き、そうでないときは付きません。`NO_COLOR`、`TERMAXA_NO_COLOR`、`CLICOLOR_FORCE` に従います。

## 正直な制限事項

Termaxa は 1.0 より前の版です。実際に動き、テストされていますが、魔法ではありません。

- **フックは助言するだけで、強制はしません。** エージェントは協調的です。拒否を尊重して代替案を出すので、門番が成り立っています。完全自動モードのエージェントは、拒否された操作を別のコマンドやシェルで再試行するかもしれません。ブレーカーはそのコストを上げますが、フックは連携の接点であって、強制の境界ではありません。Supervised モードが動かすのは誰が判断するかであって、境界がどこにあるかではありません。確実な保証が必要なら、Termaxa を OS レベルのサンドボックスと組み合わせてください。
- **協調的な仕組みであり、サンドボックスではありません。** Termaxa が管理するのは、フック、`termaxa run`、またはラップされたシェルを通るコマンドです。フックのない素のシェルアクセスは、封じ込められません。
- **ネイティブのツールは、対象だけで判定されます。** `Write` で `.env` に書き込むと拒否されます。中身が何かを削除するスクリプトである `Write` は、ただの書き込みです。そのあとエージェントが実行するものは、実行されるときに判定されます。
- **門番は、認識できないペイロードに対して、設計上、フェイルオープンします。** 気づく手段は `doctor` と生存確認のプローブです。`unrecognised: deny` は、止まったエージェントのほうが、門番を通らないエージェントより安くつく場面で使うスイッチです。
- **シェルの解析はよくできていますが、完璧ではありません。** 複合コマンド、`-c` 文字列、`eval`、同じ行の変数、git・kubectl・terraform・tofu・docker のグローバルオプションは、実際に実行されるものとして読みます。パスで指定されたプログラムも、拒否ルールに対しては名前で読みます。`$(…)` は、中身をポリシーが許可するのでない限り、警告の対象になります。サブシェルや深い引用符は保守的に判定します。呼び出し元の環境から組み立てられるパス（`rm -rf ~/x/$SID`）は、推測せず、*未解決*として扱います。
- **プレビューはベストエフォートです。** データベースに接続できなければ、静的な解析だけになります。Terraform のプレビューは `terraform plan` を呼び出します。
- **バックアップには限界があります。** スクリプトや言語ランタイムを通した削除には、保険がかかりません。グロブの対象（`rm -rf build/*`）は、展開された内容でプレビューされますが、保険はかかりません。シェルが展開するのは、門番が見たあとだからです。予算を超える対象は、黙って保険なしにされるのではなく、拒否されます。ただし、ビルドで作り直せるディレクトリ（プロジェクト内の `node_modules`、`.next`、`dist`、`target`、`.venv`）は例外で、コピーから外され、そのことが表示されます。リンクはリンクとしてコピーし、その先のツリーまでは決して辿りません。辿ることが、ディレクトリジャンクション経由で稼働中の 48,218 ファイルを削除した 2026年9月20日の事故の仕組みだからです。
- **フォーマットはまだ変わるかもしれません。** リリースを固定してください。
- **Windows PowerShell 5.1 は、リダイレクトした Unicode を壊します。** `termaxa report > out.txt` は UTF-16 で書き出し、罫線の文字を文字化けさせます。PowerShell 7 を使うか、`termaxa report --md | Out-File -Encoding utf8 report.md` を使ってください。

実際の利用で見つかったバグは、どう見つかったか、どこで直したかとともに、すべて [docs/found-in-the-wild.md](docs/found-in-the-wild.md) にあります。現時点で 48 件です。脅威モデルと公開済みのアドバイザリは [SECURITY.md](SECURITY.md) にあります。

## コントリビュート

Rust 2021、本番コードは約 19,100 行、テストは約 20,000 行、Linux 上のテストは 599 件、CI は Linux、macOS、Windows で動きます。`cargo fmt`、`cargo clippy -- -D warnings`、`cargo test` が関門で、門番のルールは門番自身にも適用されます。ここでは意見より計測が勝ちます。判定を変える変更には、それを示すフィクスチャを付けてください。

## セキュリティ

バイパスを見つけましたか？ 報告の方法とその後の流れは [SECURITY.md](SECURITY.md) にあります。そこにある判定ルールがバグと呼ぶバイパスは、自分たちで見つけたものも、誰かが報告したものも、すべて、露出していた期間を UTC で添えたアドバイザリとして公開されます。それ以外は、制限として文書化されています。

## ライセンス

MIT または Apache-2.0。どちらでも、お好きな方を選べます。
