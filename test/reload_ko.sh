iptables -D FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -j HTTPREDIRECT --httpredirect-url "http://192.168.56.1:8080/1.html"
rmmod xt_HTTPREDIRECT
insmod ../kernel/xt_HTTPREDIRECT.ko
iptables -A FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -j HTTPREDIRECT --httpredirect-url "http://192.168.56.1:8080/1.html"
