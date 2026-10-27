# Render from docs/assets/render-staging: vhs reachable-demo.tape, then the GIF with
# ffmpeg -i out/reachable-demo.mp4 -vf "fps=12,scale=900:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" out/reachable-demo.gif
# demo/cli-fixture/bin stands in for node and npm and prints the staged output (real output, trimmed).
Output out/reachable-demo.mp4

Set FontSize 15
Set Width 1000
Set Height 560
Set Theme "Dracula"
Set Padding 20
Set Shell bash

# The shell vhs starts may not pass on PATH or PS1 (WSL's bash on Windows does not).
Hide
Type `export PATH="$PWD/demo/cli-fixture/bin:$PATH" PS1='\[\e[38;2;90;86;224m\]> \[\e[0m\]'` Enter
Type "clear" Enter
Sleep 500ms
Show

Type "# reachable: cut npm audit noise" Sleep 300ms Enter
Sleep 800ms

Type "cd demo/cli-fixture" Sleep 300ms Enter
Sleep 500ms

Type "npm audit --audit-level=high" Sleep 300ms Enter
Sleep 2.2s

Type "clear" Sleep 250ms Enter
Sleep 400ms

Type "node ../../dist/cli/index.js scan --format table --dry-run" Sleep 300ms Enter
Sleep 2.5s

Type "node ../../dist/cli/index.js trace lodash" Sleep 300ms Enter
Sleep 2s
