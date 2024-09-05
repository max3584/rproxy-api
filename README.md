# TCP/UDP ReverseProxy
+ Rust TCP/UDP ReverseProxy

# Usage:
```shell
# -- clone repository --
git clone https://github.com/max3584/TCP-UDP-rproxy.git

# -- reverse proxy build
cd TCP-UDP-rproxy

./forward -loglevel 2 \
          -debug false \
          -logfile ./proxy.log \
          -api_addr 127.0.0.1 \
          -api_port 8080 \
          -control_tcp_addr 127.0.0.2 \
          -control_udp_addr 127.0.0.3
```

## reverse proxy setup
<div>APIでTCP/UDPのデータReverseProxyを追加することができます。</div>
<div>例：</div>

```bash
nc 127.0.0.1 8080
# UP TCP Reverse Proxy 
{"property":"UP","listen_addr":"192.168.1.1","listen_port":8888,"remote_addr":"192.168.1.2","remote_port":8080,"protocol":"TCP"}

# STOP TCP Reverse Proxy
nc 127.0.0.2 8888
{"property": "STOP"}

# TCP ReverseProxy Update remote address
nc 127.0.0.2 8888
{"property": "STOP", "parameter": "192.168.1.3:8081"}
```

<div>このような形であれば何でも反応するようになっています。</div>