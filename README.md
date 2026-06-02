Best way to understand its beauty is by simply trying it -
```bash
brew tap Sujas-Aggarwal/tap
brew install my
```

Keep memories safe and secure (with Touch ID protection for sensitive topics), and yes, pretty much one of my faviorite creations.

Edit:
To Ensure that your system doesn't save the history of commands starting with "my", add this to your ~/.zshrc - 
by 
```bash
nano ~/.zshrc
```
then adding - 
```bash
zshaddhistory() {
    [[ $1 == my* ]] && return 1
    return 0
}
```
and refreshing your configurations - 
```bash
source ~/.zshrc
```
