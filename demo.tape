# VHS tape for mcpbait demo recording
# Produces high-resolution, branded GIF and MP4

Output docs/demo.gif
Output docs/demo.mp4

Set Shell "zsh"
Set FontSize 14
Set Width 1200
Set Height 860
Set WindowBar Colorful
Set WindowBarSize 36
Set Theme "TokyoNight"
Set Padding 18
Set TypingSpeed 45ms

# Prepare environment quietly
Hide
Type "alias mcpbait='./tools/demo_fixture.sh'"
Enter
Type "clear"
Enter
Show

Sleep 600ms

# Type the red-teaming audit command against Cursor / Claude
Type "mcpbait audit --client cursor"
Sleep 500ms
Enter

# Wait for 3-phase adversary emulation and scorecard
Sleep 8.5s

# Pause on the final scorecard and report summary
Sleep 4.5s
