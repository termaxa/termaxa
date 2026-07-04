# The money demo: destroy a commit, then bring it back.
Output demos/3-rollback.gif
Set FontSize 20
Set Width 1100
Set Height 520
Set Theme "Dracula"
Type "termaxa run -- git push --force origin main"
Sleep 500ms
Enter
Sleep 2s
Type "y"
Enter
Sleep 2s
Type "termaxa rollback $(termaxa backups | head -1 | awk '{print $1}')"
Sleep 500ms
Enter
Sleep 1s
Type "y"
Enter
Sleep 3s
