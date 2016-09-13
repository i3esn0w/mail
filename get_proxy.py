#encoding:utf8

import urllib2
import re
import socks,socket


content=r'''	<td><a href='(.+?)' title='View this Proxy details'>(.+?)
<!--
<img src='(.+?)' border='0' hspace='0' vspace='0' width='140' height='14' alt='View this Proxy details'/>
-->
</a></td>
	<td><a href='/proxy-1080-Socks4--ssl.htm' title='Select proxies with port number 1080'>(.+?)</a></td>'''
p=re.compile(content)


list_ip=[]
checked_list=[]

def get_proxy():
    proxy_url1='http://www.xroxy.com/proxylist.php?port=&type=Socks4&ssl=&country=&latency=&reliability=&sort=country&desc=true&pnum=%s'
    header={
        "user-agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36",
    }
    for i in range(1,2):
        proxy_url=proxy_url1%str(i)
        print proxy_url
        req=urllib2.Request(proxy_url,headers=header)
        response=urllib2.urlopen(req)
        data=response.read()
        #print data
        matchs=p.findall(data)
        
        for j in matchs:
            
            ip=j[1]+":"+j[3]
            list_ip.append(ip)
            print ip
def checkip(ipinfo):
    host_port=ipinfo.split(":")
    host=host_port[0].strip()
    port=host_port[1].strip()
    try:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, host, int(port))
        socket.socket = socks.socksocket
        self.sock = socket.create_connection(('www.baidu.com', 80), 10)
        print host+':'+port
        checked_list.append(host+':'+port)
    except:
        pass
    
    
if __name__=="__main__":
    get_proxy()
    for ip in list_ip:
        checkip(ip)
    for check in checked_list:
        print check
        

