FROM jasonish/suricata:latest

COPY config/suricata.yaml /etc/suricata/config/suricata.yaml
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x ./entrypoint.sh
RUN mkdir -p /var/log/suricata

ENTRYPOINT ["./entrypoint.sh"]
