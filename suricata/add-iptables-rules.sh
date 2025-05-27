iptables -I INPUT -i lo -p tcp --dport 8000 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -I OUTPUT -o lo -p tcp --sport 8000 -j NFQUEUE --queue-num 0 --queue-bypass