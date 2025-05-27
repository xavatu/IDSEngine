docker run -d \
  --rm \
  --name suricata-http-pass-through \
  --network host \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_NICE \
  --cap-add=SYS_RESOURCE \
  -v ./config:/etc/suricata/config \
  -v ./rules:/etc/suricata/rules \
  -v ./logs:/var/log/suricata \
  suricata-http-pass-through