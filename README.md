# fusis agent

TODO

## basic workflow pseudocode

```
[[ -z $(grep fusis.out /etc/iproute2/rt_tables) ]] && (echo 200 fusis.out | tee -a /etc/iproute2/rt_tables)
ip rule add fwmark 9 table fusis.out
ip route add default via <fusis_ip> table fusis.out
iptables -t mangle -N FUSIS
iptables -t mangle -F FUSIS
iptables -t mangle -D PREROUTING -j FUSIS
iptables -t mangle -I PREROUTING -j FUSIS

containers = `docker ps`
for c in containers:
    if c.ENVS.ROUTER == 'fusis':
        iptables -t mangle -A FUSIS -s <c.ip> -j MARK --set-mark 9
```
