import csv

allComputersInSubnet = {}
# we have to do that before activating the sniffer because it resolve computer name by 
# sending dns request 
def getAllComputersInSubnet():
        # to get the start of the subnet
        gws=netifaces.gateways()
        routerIP=gws['default'].values()[0][0]
        routerIP = str(routerIP).split('.')
        routerIP.insert(1,'.')
        routerIP.insert(3,'.')
        routerIP.pop(5)
        routerIP = ''.join(routerIP)
        for i in range(0,255):
                try:
                        elem = socket.gethostbyaddr(routerIP + '.' + str(i))
                        allComputersInSubnet[routerIP + '.' +str(i)] = elem[0]
                except:
                        pass
        print allComputersInSubnet

