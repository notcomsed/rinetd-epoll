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

源代码来自这个版本https://github.com/boutell/rinetd 0.62

更新: 已修复,epoll模式在debian 10x64 下会自动断开连接,请用1.13版本.

rinetd一直没有epoll模式,本来不想写的,于是在网上找,找到了这个https://github.com/rogerwangzy/rinetdplus
,用ae实现的,
编译后测试,在iperf下多连接大流量测试第一次连接正常,后面几次就连不上了.strcae -p pid显示fd被占用,应该是忘了关闭socksfd,打开代码一看,断开连接后关闭了的啊(可能我是debian 11 gcc 10.2.1,可能gcc太新了),
奈何我技术不行,修不了ae的bug, 只好用纯epoll写一个,

ipv6是顺便改的,其实很容易,现在的库里面的bind()函数自动支持ipv6,把AF_INET,PF_INET改成AF_INET6,PF_INET6就行了,根本没有难度,支持udp也是挺容易的,就是 把SOCK_STREAM改为SOCK_DGRAM, 但是我不需要,就没有写.

软件测试了几天,也挺稳定的,没有出现问题
只要在我的服务器上没有出现bug,我就不会修.

Windows,和udp的支持去使用这个版本https://github.com/samhocevar/rinetd
