# rinetd epoll
rinetd version 1.13 use epoll instead of select,support setuid after bind, support ipv6, support auto choose event mode(epoll/select).
 
This version tested on debian 10 and debian 11.
 
- [x] epoll support
- [x] IPv6 support
- [x] setuid after bind
- [ ] UDP support

## Configuration

choose `events` in rinetd.conf
```bash
events auto
#events epoll
#events select
```
if you don't choose events mode, it will auto choose `auto`

set linux user after bind, if not have root access, this config is not work
```bash
#user nobody
user www-data
```
user will change to `www-data` after bind

set forwarding rules in rinetd.conf
```bash
# bindadress       bindport     connectaddress  connectport  
127.0.0.1          80          192.168.1.12     80
2001:fada:327::1   3389        192.168.1.12     3389
192.168.1.10       4000        127.0.0.1        3000
fd00:1a29:1e12::1  22          192.168.1.12      22
::1                5555        10.0.0.6         1234       
```

forwarding http(s) example
```bash
::           80        127.0.0.1     8080
::           443       127.0.0.1     8443
```

forwarding cowrie ssh example.

cowrie bind in 127.0.0.1:2222
```bash
::           22        127.0.0.1     2222
```

`::` mean bind all ip address include ipv4&ipv6. 

if you want only bind ipv4 address, please use `0.0.0.0`

```bash
0.0.0.0           22        127.0.0.1     2222
```

## build
gcc version must be 8.3.0 or later

use `make` to build binary
```bash
make
```

`make static` will build static binary
```bash
make static
```

`make install` will install rinetd in system.
```bash
make && make install
```

## Development
update 1.13, fixd connection break in x64.

none

### 警告,该代码可能存在问题,可以使用这个版本https://github.com/notcomsed/reforward

#### Warning: this code may have some problem , please use this version https://github.com/notcomsed/reforward

--------------

源代码来自这个版本https://github.com/boutell/rinetd 0.62

更新: 已修复1.12,epoll模式在debian 10x64 下会自动断开连接,请用1.13版本.
