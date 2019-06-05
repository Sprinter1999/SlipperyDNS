# SlipperyDNS
░█▀▀░█░░░█░░█▀█░█▀█░█▀▀░█▀█░█░█░█▀▄░█▀█░█▀▀░   
░▀▀█░█░░░█░░█▀▀░█▀▀░█▀▀░█▀▀░░█░░█░█░█░█░▀▀█░   
░▀▀▀░▀▀▀░▀░░▀░░░▀░░░▀▀▀░▀░▀░░▀░░▀▀░░▀░▀░▀▀▀░   
### A "Slippery" DNS Local Proxy Solution, contributed by Xuefen & [Kumson](https://github.com/Kumson "Kumson").  

## Function：
读入“域名-IP地址”对照表，当客户端查询域名对应的IP地址时，用域名检索该对照表，三种检索结果：  
  **1.** 检索结果为IP地址0.0.0.0，则向客户端返回“域名不存在”的报错消息（不良网站拦截功能）  
  **2.** 检索结果为普通IP地址，则向客户返回这个地址（服务器功能）   
  **3.** 表中未检到该域名，则向因特网DNS服务器发出查询，并将结果返给客户端（中继功能）   
  **4.** 丝滑地支持多台计算机同时联机查询   
  **5.** 及时地更新本地资源记录   
  **6.** 完美支持多资源报和IPV6的支持
  **7.** 超时机制
