#!/bin/sh
# RPM passes 1 on upgrade; Debian calls postrm upgrade during replacement.
case "${1:-}" in 0|remove|purge)
    if [ "$(readlink /usr/local/bin/dmg)" = stepsecurity-dev-machine-guard ]; then
        unlink /usr/local/bin/dmg
    fi ;;
esac
