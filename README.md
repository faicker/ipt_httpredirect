iptables http redirect module
=============================
Redirect clients to a specific URL with the HTTP 302 response and terminate the connection between the client and the server.  
Inspired by the REJECT module.  
It can be deployed on the gateway before the web server.  
The difference with REDIRECT is that HTTPREDIRECT terminates the established connection when url is matched.

1. first install kernel-devel, iptables-devel and etc.
2. To compile the userpace so,
```bash
cd userspace;make libxt_HTTPREDIRECT.so
cp libxt_HTTPREDIRECT.so /lib64/xtables/
```
3. To compile the kernel module,
```bash
cd kernel;make
insmod xt_HTTPREDIRECT.ko
```
4. iptables rule example,
```bash
iptables -A FORWARD -d 192.168.57.70/32 -p tcp --dport 80 -m state --state ESTABLISHED -m connbytes --connbytes 2:5 --connbytes-mode packets --connbytes-dir original -m string --string "HTTP/1." --algo kmp --from 40 --to 100 -j HTTPREDIRECT --httpredirect-url "http://www.abc.com"
```
5. It depends on conntrack module and the url length should be less than 64 Bytes.
6. Test on CentOS 6.5 with kernel version 2.6.32-431.23.3.el6.x86_64.
