FROM kalilinux/kali-rolling
RUN apt update && apt install -y iproute2 net-tools iputils-ping python3 tcpdump arp-scan nmap
CMD ["/bin/bash"]
