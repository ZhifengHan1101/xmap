# Building and installing `xmap-rtt` side by side with the production xmap

Nothing here touches `/usr/local/bin/xmap` or the cron jobs.

## Build

Dependencies: cmake, gcc, flex, byacc (or bison's yacc), gengetopt, libgmp-dev,
libjson-c-dev, libpcap-dev, libunistring-dev, libjudy-dev (Debian/Ubuntu names).

```
git clone <fork> xmap && cd xmap && git checkout feature/icmp-echo-time
mkdir build && cd build && cmake .. && make -j"$(nproc)"
./src/xmap --version
```

Re-run `cmake ..` after committing: the commit in the metadata is read at
configure time.

## Install to a separate prefix

```
sudo install -d /opt/xmap-rtt/bin
sudo install -m 0755 src/xmap /opt/xmap-rtt/bin/xmap-rtt
```

The binary reads the same `/etc/xmap/xmap.conf` and `blocklist.conf` as the
production one; nothing else is installed.

## sudoers (do not apply automatically)

The production scripts call `sudo -n xmap ...`. For `xmap-rtt` add a line next
to the existing one (use `visudo -f /etc/sudoers.d/xmap-rtt`):

```
<scan-user> ALL=(root) NOPASSWD: /opt/xmap-rtt/bin/xmap-rtt
```

## Rollback

```
sudo rm -rf /opt/xmap-rtt
sudo rm -f /etc/sudoers.d/xmap-rtt   # if the sudoers file was added
```

Scripts switched to `xmap-rtt -M icmp_echo_time` go back by restoring
`xmap -M icmp_echo` and their previous `-f` / `RESP_FIELDS`; the production
binary was never modified.
