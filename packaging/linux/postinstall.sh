#!/bin/sh
# Keep an unmanaged file named dmg intact, including a dangling symlink.
bin=/usr/local/bin
if [ -e "$bin/dmg" ] || [ -L "$bin/dmg" ]; then
    [ "$(readlink "$bin/dmg")" = stepsecurity-dev-machine-guard ] || echo "Keeping existing $bin/dmg" >&2
else
    ln -sT stepsecurity-dev-machine-guard "$bin/dmg" ||
        echo "dmg is unavailable at $bin/dmg; use stepsecurity-dev-machine-guard findings" >&2
fi
