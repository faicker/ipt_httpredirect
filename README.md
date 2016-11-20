iptables http-redirect module
=============================
Redirect clients to a specific URL with the HTTP 302 response. Inspired by the REJECT module.


1. To compile the userpace so,
cd userspace;make libxt_HTTPREDIRECT.so
cp libxt_HTTPREDIRECT.so /lib64/xtables/

2. To compile the kernel module,
cd kernel;make

3. iptables rule example,
iptables -A FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -j HTTPREDIRECT --httpredirect-url "http://www.baidu.com"

4. Support kernel 2.6.32. It depends on conntrack module.
5. Test on CentOS 6.5 x86_64.
