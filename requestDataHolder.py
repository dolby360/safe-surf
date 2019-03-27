import os 
import csv

class reqDataHolder():
    def __init__(self):
        self.hour = None
        self.day_in_week = None
        self.day_in_month = None
        self.month = None
        self.year = None
        self.minutes = None
        self.seconde = None
        self.id = None
        self.MAC = None
        self.ip_src = None
        self.udp_src_port = None
        self.ip_dst = None
        self.udp_dst_port = None
        self.queryName = None
        self.computerName = None

        #check if dir exist if not create it
        def check_dir():
            try:
                with open('history.csv', 'rb') as csvfile:
                    pass
            except:
                with open('history.csv', 'wb') as csvfile:
                    pass
        check_dir()

    def __repr__(self):
        return self.queryName
    def __str__(self):
        return self.queryName

    def getDate(self):
        return  str(self.day_in_month) + '/' + str(self.month) + '/' +  str(self.year)
    
    def getTime(self):
        return str(self.hour) + ':' + str(self.minutes)

    def reportToCsvFile(self):
        line = [self.computerName,self.queryName,self.ip_src,self.MAC,self.getDate(),self.getTime()]
        with open('history.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow(line)
