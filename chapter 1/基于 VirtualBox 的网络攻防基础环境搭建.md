# 基于 VirtualBox 的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

## 实验环境

以下是本次实验需要使用的网络节点说明和主要软件举例：

- VirtualBox 虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2109.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验要求

- 虚拟硬盘配置成多重加载，效果如下图所示；

![img](https://c4pr1c3.github.io/cuc-ns/chap0x01/attach/chap0x01/media/vb-multi-attach.png)

- 搭建满足如下拓扑图所示的虚拟机网络拓扑；

![img](https://c4pr1c3.github.io/cuc-ns/chap0x01/attach/chap0x01/media/vb-exp-layout.png)

> 根据实验宿主机的性能条件，可以适度精简靶机数量

- 完成以下网络连通性测试；
  - [ ] 靶机可以直接访问攻击者主机
  - [ ] 攻击者主机无法直接访问靶机
  - [ ] 网关可以直接访问攻击者主机和靶机
  - [ ] 靶机的所有对外上下行流量必须经过网关
  - [ ] 所有节点均可以访问互联网





### 实验步骤：

1.配置一块安装了kali的.vdi硬盘多重加载，并在virtualbox中新建三台虚拟机，分别设置为victim、gateway、attacker。

2.给三台虚拟机添加网卡。

配置成功截图：

![3](C:\Users\Administrator\Desktop\3.PNG)

gateway：

![4](C:\Users\Administrator\Desktop\4.PNG)

attacker：

![5](C:\Users\Administrator\Desktop\5.PNG)

开启Gateway ipv4转发功能，添加Gateway防火墙NAT规则，设置网关转发局域网192.168.1.0/24中的数据包。

通过指令

echo 1 >PROC/SYS/NET/IPV4/IP_forward

配置路由规则：

![7](C:\Users\Administrator\Desktop\7.PNG)



靶机可以直接访问攻击者主机：

![靶机到攻击者](C:\Users\Administrator\Desktop\靶机到攻击者.PNG)

攻击者主机无法直接访问靶机：

![网关到靶机](C:\Users\Administrator\Desktop\网关到靶机.PNG)

网关到攻击者：



![网关到攻击者](C:\Users\Administrator\Desktop\网关到攻击者.PNG)



靶机的所有对外上下行流量必须经过网关：

靶机的网关ip被设置为gateway eth0的ip，靶机本身不能上网，靶机只能经由gateway对外访问。



所有节点均可以访问互联网：

victim可以通过gateway上网。

gateway自身具有NAT网卡，可通过主机网络上网。

attacker自身具有NAT网卡，可以通过主机网络上网。





查阅的资料：

https://www.jianshu.com/p/024a43e917ae

http://ipset.netfilter.org/iptables.man.html

https://blog.csdn.net/jackcily/article/details/82807757

