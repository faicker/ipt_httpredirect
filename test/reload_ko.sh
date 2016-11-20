iptables -D FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -j HTTPREDIRECT --httpredirect-url "http://www.baidu.com"
rmmod xt_HTTPREDIRECT
insmod ../kernel/xt_HTTPREDIRECT.ko
iptables -A FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -j HTTPREDIRECT --httpredirect-url "http://www.baidu.com"
