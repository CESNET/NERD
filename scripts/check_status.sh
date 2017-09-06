#!/bin/sh

check_service () {
  status="$(systemctl is-active ${1}.service)"
  if [ $status == "active" ]; then
    echo $1 $(tput setaf 2)$status$(tput sgr0)
  else
    echo $1 $(tput setaf 1)$status$(tput sgr0)
  fi
}

check_process () {
  if pgrep -f $1 > /dev/null; then
    echo $1 $(tput setaf 2)running$(tput sgr0)
  else
    echo $1 $(tput setaf 2)not running$(tput sgr0)
  fi
}

check_service postgresql-9.6
check_service mongod
check_service named
check_service httpd
check_service postfix
check_service munin-node
check_process warden_filer
check_process nerdd
