#!/bin/sh
# Configure Apache to serve NERDweb
# Pass base location without trailing slash (e.g. "/nerd" or "/") as parameter
# (default is "/")
# Add "-d" parameter to install in debug mode

echo "=============== Configure Apache ==============="

# (in case base_loc is server root, httpd needs "/", while nerd needs "")
base_loc_httpd="/"
base_loc_nerd=""
debug=0

while getopts "d" opt; do
    case "$opt" in
        d)
            debug=1
            ;;
        *)
            echo "Unknown parameter"
            exit 1
            ;;
    esac
done
shift $((OPTIND-1))

# If base_loc is set and not root directory (which is default and treated specially)
if [ -n "$1" -a "$1" != "/" ] ; then
  base_loc_httpd=$1
  base_loc_nerd=$1
fi

echo "Base location: $base_loc_httpd"
if [ "$debug" = 1 ] ; then
  echo "WARNING: SETTING UP DEBUG MODE!"
fi

echo "** Installing Apache and WSGI **"
yum install -y httpd httpd-devel mod_wsgi
pip3 install mod_wsgi

# Replace the stock mod_wsgi.so with the one from Python36
rm -f /usr/lib64/httpd/modules/mod_wsgi.so
path="$(pip3 show mod_wsgi 2>/dev/null | sed -n '/Location: / s/Location: //p')"
if [ -z "$path" ] ; then
  echo "ERROR: Can't find the path to mod_wsgi python package, can't create symlink to it. Apache won't start." >&2
else
  ln -s "$path"/mod_wsgi/server/mod_wsgi-py36.*.so /usr/lib64/httpd/modules/mod_wsgi.so
fi

echo "** Setting up configuration files **"
if [ "$debug" = 1 ] ; then
  cp /tmp/nerd_install/httpd/nerd-debug.conf /etc/httpd/conf.d/nerd.conf
else
  cp /tmp/nerd_install/httpd/nerd.conf /etc/httpd/conf.d/nerd.conf
fi
# Set up base loc in both apache conf and NERD conf
sed -i -E "s|^Define\s+NERDBaseLoc\s+.*$|Define NERDBaseLoc $base_loc_httpd|" /etc/httpd/conf.d/nerd.conf
sed -i -E "s|^base_url:.*$|base_url: \"$base_loc_nerd\"|" /etc/nerd/nerdweb.yml

# Set up random "secret" number for Flask
secret=$(head -c 24 /dev/urandom | base64)
sed -i -E "s|^secret_key: \"!!! CHANGE THIS !!!\"|secret_key: \"$secret\"|" /etc/nerd/nerdweb.yml

# (not needed, default is to allow everything)
#echo "** Setting up firewall **"
#iptables -I INPUT 1 -p TCP --dport 80 -j ACCEPT
#iptables -I INPUT 1 -p TCP --dport 5000 -j ACCEPT
#iptables-save > /etc/sysconfig/iptables

echo "** Starting Apache **"
systemctl enable httpd
systemctl restart httpd
