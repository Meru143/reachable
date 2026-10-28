# Everything on screen is real output: npm audit, and the reachable CLI packed from this repository, run against
# demo/cli-fixture (src/index.ts calls _.template, lodash 4.17.20 installed) with an empty advisory cache. Nothing is
# trimmed or staged, so the output follows OSV's current advisories.
#
# Render from docs/assets/render-staging, after `npm ci` in demo/cli-fixture and, at the repository root (npm pack
# does not create the folder), `mkdir -p docs/assets/render-staging/out && npm pack --pack-destination docs/assets/render-staging/out`:
#   vhs reachable-demo.tape
#   ffmpeg -i out/reachable-demo.mp4 -vf "fps=12,scale=900:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" out/reachable-demo.gif
# On Windows, run vhs from PowerShell, so that its bash is WSL's (ttyd shows nothing from Git Bash); WSL needs node and
# npm. The CLI and the fixture are copied into WSL's own file system first: read through /mnt/c, a scan takes 15 s.
Output out/reachable-demo.mp4

Set FontSize 15
Set Width 1000
Set Height 860
Set Theme "Dracula"
Set Padding 20
Set Framerate 15
Set Shell bash

# WSL's bash takes a few seconds to start, and does not pass on PATH or PS1.
Hide
Sleep 8s
Type `export PS1='\[\e[38;2;90;86;224m\]> \[\e[0m\]' REACHABLE_CACHE_DIR="$(mktemp -d)" DEMO="$(mktemp -d)"` Enter
Type `npm install --silent --no-audit --no-fund --prefix "$DEMO/cli" ./out/merupatel-reachable-*.tgz && cp -r demo/cli-fixture "$DEMO/app" && cd "$DEMO/app" && reachable() { "$DEMO/cli/node_modules/.bin/reachable" "$@"; }` Enter
Wait@300s
Type "clear" Enter
Sleep 1s
Show

Type "# reachable: cut npm audit noise" Sleep 300ms Enter
Sleep 800ms

Type "npm audit --audit-level=high" Sleep 300ms Enter
Wait@60s
Sleep 4s

Type "clear" Sleep 250ms Enter
Sleep 400ms

Type "reachable scan" Sleep 300ms Enter
Wait@120s
Sleep 7s

Type "clear" Sleep 250ms Enter
Sleep 400ms

Type "reachable trace lodash" Sleep 300ms Enter
Wait@60s
Sleep 2.5s
