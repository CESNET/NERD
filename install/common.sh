# To be run at the beginning of all installation scripts

# disable "fastestmirror plugin, which in fact slows down yum"
alias yum="yum --disableplugin=fastestmirror"

# Set up functions for colored output, but not during Vagrant provisioning, as it doesn't work well there
if ! [ -e /vagrant_provisioning ]
then
# print section headers in blue color
echob () {
  tput setaf 4 # light blue
  tput bold
  echo "$@"
  tput sgr0
}

# print important notes in yellow color
echoy () {
  tput setaf 3 # yellow
  tput bold
  echo "$@"
  tput sgr0
}

# print warnings and errors in red color
echor () {
  tput setaf 1 # red
  tput bold
  echo "$@"
  tput sgr0
}

else
# run during warden provisioning, don't use colors
alias echob=echo
alias echoy=echo
alias echor=echo
fi