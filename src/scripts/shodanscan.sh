shodan search $1 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
