# Recording for docs/demo.gif -- regenerate with:  vhs docs/tape/demo.tape
#
# The gif is a build artefact of this file. Re-record it rather than editing the
# gif, so what the README shows always matches what the tool actually prints.

Output docs/demo.gif
Output docs/demo.mp4

Set Shell        zsh
Set FontFamily   "Menlo"
Set FontSize     14
Set Width        1200
Set Height       840
Set Padding      20
Set Margin       0
Set MarginFill   "#000000"
Set BorderRadius 10
Set WindowBar    Colorful
Set LineHeight   1.25
Set CursorBlink  true
Set Theme        { "name": "Termius Pro", "background": "#000000", "foreground": "#ffffff", "cursor": "#9aedfe", "cursorAccent": "#000000", "selection": "#2e3349", "black": "#000000", "red": "#ff5c57", "green": "#5af78e", "yellow": "#f3f99d", "blue": "#57c7ff", "magenta": "#ff6ac1", "cyan": "#9aedfe", "white": "#f1f1f0", "brightBlack": "#686868", "brightRed": "#ff5c57", "brightGreen": "#5af78e", "brightYellow": "#f3f99d", "brightBlue": "#57c7ff", "brightMagenta": "#ff6ac1", "brightCyan": "#9aedfe", "brightWhite": "#f1f1f0" }

Set TypingSpeed  28ms
Set PlaybackSpeed 1.0

# Put the local build on PATH and identify the assessment context.
Hide
Type "export PATH=$PWD/.venv/bin:$PATH; export PS1='%F{cyan}security@workstation%f %F{magenta}~/mcpbait%f %# '; mkdir -p .demo; find .demo -mindepth 1 -delete; clear"  Enter
Sleep 1s
Show

Sleep 800ms
Type "mcpbait doctor --dir .demo"
Sleep 300ms
Enter
Sleep 4s

Type "clear"
Enter
Sleep 500ms
Type "mcpbait demo --dir .demo"
Sleep 500ms
Enter

# The reference assessment is real and deterministic; pause for the evidence story.
Sleep 8s

Type "clear"
Enter
Sleep 500ms
Type "mcpbait status --dir .demo"
Sleep 300ms
Enter
Sleep 4s

Type "mcpbait report --dir .demo --json .demo/assessment.json >/dev/null"
Sleep 300ms
Enter
Sleep 2s
Type "find .demo -maxdepth 2 -type f | sort"
Enter
Sleep 6s

Hide
Type "find .demo -mindepth 1 -delete; rmdir .demo; clear"
Enter
