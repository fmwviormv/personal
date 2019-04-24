#!/bin/sh

xsetroot -solid black
#xpmroot /usr/xenocara/app/xlockmore/pixmaps/tunnel4.xpm
setxkbmap us colemak
xset b off

userresources=$HOME/.Xresources
usermodmap=$HOME/.Xmodmap
sysresources=/etc/X11/xinit/.Xresources
sysmodmap=/etc/X11/xinit/.Xmodmap

# merge in defaults and keymaps

if [ -f $sysresources ]; then
    xrdb -merge $sysresources
fi

if [ -f $sysmodmap ]; then
    xmodmap $sysmodmap
fi

if [ -f "$userresources" ]; then
    xrdb -merge "$userresources"
fi

if [ -f "$usermodmap" ]; then
    xmodmap "$usermodmap"
fi

if [ -z "$SSH_AGENT_PID" ];
then
	eval `ssh-agent -s`
	ssh-add < /dev/null
fi

cwm

if [ "$SSH_AGENT_PID" ]; then
	ssh-add -D < /dev/null
	eval `ssh-agent -s -k`
fi
