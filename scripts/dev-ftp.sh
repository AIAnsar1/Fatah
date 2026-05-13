#!/usr/bin/env bash
# Spin up a throwaway FTP server on localhost:2121 with one known
# credential pair, so you can dogfood `fatah run` end-to-end:
#
#   ./scripts/dev-ftp.sh up                              # start
#   fatah run -t ftp://127.0.0.1:2121 -l user -P /tmp/pw.lst
#   ./scripts/dev-ftp.sh down                            # stop
set -euo pipefail

CONTAINER=fatah-dev-ftp
IMAGE=delfer/alpine-ftp-server
USER=user
PASS=correcthorsebatterystaple

case "${1:-up}" in
  up)
    docker run -d --rm --name "$CONTAINER" \
      -p 2121:21 \
      -p 21000-21010:21000-21010 \
      -e USERS="$USER|$PASS" \
      "$IMAGE" >/dev/null
    echo "==> ftp running on localhost:2121 ($USER / $PASS)"
    ;;
  down)
    docker stop "$CONTAINER" >/dev/null 2>&1 || true
    echo "==> stopped"
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
