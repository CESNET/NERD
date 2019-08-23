#!/bin/sh

ret_code=0

check_service () {
  status="$(systemctl is-active ${1}.service)"
  if [ $status == "active" ]; then
    echo $1 $(tput setaf 2)$status$(tput sgr0)
  else
    echo $1 $(tput setaf 1)$status$(tput sgr0)
    ret_code=1
  fi
}

check_process () {
  if pgrep -f $1 > /dev/null; then
    echo $1 $(tput setaf 2)running$(tput sgr0)
  else
    echo $1 $(tput setaf 1)not running$(tput sgr0)
    ret_code=1
  fi
}

check_service postgresql-11
check_service mongod
check_service redis
check_service rabbitmq-server
check_service named
check_service httpd
check_service postfix
check_service munin-node
#check_process warden_filer.py
#check_process blacklists2redis.py
#check_process shodan_requester.py
#check_process nerdd.py
check_service nerd-supervisor

exit $ret_code

