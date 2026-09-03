# VHS tape for mcpbait demo recording
# Produces high-resolution, branded GIF and MP4

Output docs/demo.gif
Output docs/demo.mp4

Set Shell "zsh"
Set FontSize 14
Set Width 1100
Set Height 720
Set WindowBar Colorful
Set WindowBarSize 36
Set Theme "TokyoNight"
Set Padding 16
Set TypingSpeed 40ms

# Show the fastest way to run mcpbait
Type "uvx mcpbait demo"
Sleep 400ms
Enter

# Wait for the kill chain execution and verdict table to print
Sleep 3.5s

# Pause to let viewer read resilience score
Sleep 4s
