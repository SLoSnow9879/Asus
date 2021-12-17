# 漏洞类型
未授权远程任意命令执行 

# 漏洞描述
在web服务对应二进制文件httpd中，攻击者可在未登陆验证的情况下，通过控制timestap参数进行缓冲区溢出触发漏洞达到远程任意命令执行的效果

# 影响范围
AC68U FirmwareVersion < 3.0.0.4.385.20633 
</br>
RT-AC5300 FirmwareVersion
</br>
. . . . . .
</br>
此漏洞影响多个路由器型号，具体型号暂未统计，官方2020年8-9月份修复的RCE漏洞（如下图）似乎就是这个
</br>
![image](https://user-images.githubusercontent.com/45091804/146535975-97051c7f-a65e-465a-8ed6-bc15ae5f6e6c.png)

# 漏洞触发流程
**本次数据基于固件版本AC68U 3.0.0.4.384.45713**
</br>
CName、mac、interval、timestap参数内容均为可控
</br>
### 流程1. 构造timestap、mac参数满足条件通过判断条件
 ①系统时间+3600-atol(timestap参数)<20 （timestap参数:通过一次空包返回内容来计算时间戳（注意需要根据设备系统设置时区计算）
 ![image](https://user-images.githubusercontent.com/45091804/146538461-c4dcb76e-d911-42c3-8c2d-ba7e1309f06f.png)
 </br>
 ②sub_11840函数为nvram_get，初始MULTIFILTER_MAC值为空，str("",mac)，所以mac必须为空
  </br>
  
 ![image](https://user-images.githubusercontent.com/45091804/146538587-02d5ce10-1572-4c4b-b148-9dbfcf84840d.png)

### 流程2. 绕过atol函构造timestap参数
atol(1639469133aaaaaaa.....)返回内容为1639469133,所以只需要在计算好的时间戳后面填充即可，通过strcat函数触发漏洞
![image](https://user-images.githubusercontent.com/45091804/146538789-fe6e5a14-2b47-4c13-8bf5-a202dbe2f7ed.png)

# 漏洞利用
1. timestap参数第一次尝试填充4740 * a,查看栈中数据，还有40个字节需要填充，也就是时间戳 + 4880* a + p32(addr)
![image](https://user-images.githubusercontent.com/45091804/146540066-b3f23900-0969-4edd-9deb-8dc8632abae9.png)

2.调试中发现会提前崩溃，逐步跟踪，发现崩溃点位于json_object_put函数，此函数参数会从栈上取数据（原数据值为0），而栈被覆盖了后取的数据导致提前崩溃
![image](https://user-images.githubusercontent.com/45091804/146541130-4c897ae3-6172-48d9-a902-0534d2f83480.png)

3.libjson-c.so.2.0.2查看json_object_put函数原型，a1就是栈上取的参数，也就是只有当满足条件a1=0 或 *(a1+12)-- != 1 才能保持正常返回。由于是strcat函数导致溢出，栈中数据出现00会截断。注意下图左边汇编代码，LDR是取内容，--后比较完后会通过STR指令将内容写回原地址，所以在覆盖返回地址前，理论上构造参数：时间戳 + 4840* a +p32(addr) +32*a +p32(addrToSystem) addr必须满足条件：可读、可写、无00
![image](https://user-images.githubusercontent.com/45091804/146541761-919669df-f73b-4917-8484-256c3f8ca10c.png)
4. 寻找合适地址
- 查看区段信息，未发现所需地址
- 查看lib库，开启了PIE，无法利用 （碰撞libc地址，因为概率太低不进行尝试了）
![image](https://user-images.githubusercontent.com/45091804/146541939-f0c53a5c-232e-4d2a-ae04-8dfb25d81d58.png)
5. 然而json_object_put函数内部有个函数指针调用，而a1的值是可控的，也就是不用覆盖到返回地址也可以劫持PC
![image](https://user-images.githubusercontent.com/45091804/146554377-df982dfb-d21a-4a3b-a0a6-f9ac650e5244.png)

6. 观察bss段数据 发现CName、mac、interval、timestap内容都存在bss段，且bss段可读可写。
构造结构如下图，且运行到json_object_put函数内，准备跳转前，发现R10的内容保存的是CName参数内容。
<sup> 


  
  
     #cmd：需要执行的命令
     #timeStapStr：计算好的时间戳
     #addr：interval参数内容首地址，需要根据cmd命令的长度进行调整
    'CName': cmd，
    'mac': '',
    'interval': 'a'*12+p32(1)+'a'*16+p32(0x0000EFA8),
    'timestap': timeStapStr +'a'*4740+p32(addr) 



</sup>

![image](https://user-images.githubusercontent.com/45091804/146554630-170a7eb3-5f7b-437b-8e44-6ad19c19f2cb.png)
