#Bashrc file by Leo.C.Wu
# aliases
alias ll='ls -lGh'
alias grep='grep -in --color=auto'
alias tree='tree -upsh'
alias cp='cp -r'
alias scp='scp -r'
alias vi='vim'

# promotion set to: <username>@laworks[<basedir>]:$
PS1='\u@laworks[\W]:$'

if [ -f /Library/Developer/CommandLineTools/usr/share/git-core/git-completion.bash ]; then
    if [ ! -f /usr/local/etc/bash_completion.d/git-completion.bash ]; then
        cd  /usr/local/etc/bash_completion.d/;
        ln -s /Library/Developer/CommandLineTools/usr/share/git-core/git-completion.bash git-completion.bash
        cd -
    fi
fi

# host specific settings
if [ -f /usr/local/etc/bash_completion ]; then
    source /usr/local/etc/bash_completion
fi
