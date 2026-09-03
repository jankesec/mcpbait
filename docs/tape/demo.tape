# Recording for docs/demo.gif -- regenerate with:  vhs docs/tape/demo.tape
#
# The gif is a build artefact of this file. Re-record it rather than editing the
# gif, so what the README shows always matches what the tool actually prints.

Output docs/demo.gif

Set Shell        zsh
Set FontFamily   "Menlo"
Set FontSize     14
Set Width        1320
Set Height       900
Set Padding      22
Set Margin       14
Set MarginFill   "#0b0f14"
Set BorderRadius 10
Set Theme        { "background": "#0b0f14", "foreground": "#d7dee7", "cursor": "#00ff66", "selection": "#1d2733", "black": "#0b0f14", "red": "#ff5f6b", "green": "#00ff66", "yellow": "#ffc857", "blue": "#5aa9ff", "magenta": "#c792ea", "cyan": "#4dd0e1", "white": "#d7dee7", "brightBlack": "#5b6773", "brightRed": "#ff8892", "brightGreen": "#5cffa0", "brightYellow": "#ffd98a", "brightBlue": "#8cc4ff", "brightMagenta": "#ddb6ff", "brightCyan": "#89e6f0", "brightWhite": "#ffffff" }

Set TypingSpeed  55ms
Set PlaybackSpeed 1.0

# Put the local build on PATH and give the prompt a clean, neutral face.
Hide
Type "export PATH=$PWD/.venv/bin:$PATH; export PS1='%F{green}❯%f '; clear"  Enter
Sleep 1s
Show

Sleep 800ms
Type "mcpbait demo"
Sleep 500ms
Enter

# The run itself is fast; the pause is so a reader can actually read the verdicts.
Sleep 9s
