from multiprocessing import Process, Queue
from firebase import firebase
import socket 
import time
from time import gmtime, strftime


class blackListAnalyze():
    def __init__(self):
        self.blackList = TheBlackList()
        self._firebase = firebase.FirebaseApplication('https://safewifi-a7dc0.firebaseio.com', None)
        self.get_black_list_IPs()

    def analyze_IP(self,q): 
        print 'Ready'
        while True:
            popped = q.get() 
            self.check_if_this_web_in_black_list_or_suspected(popped)

    def check_if_this_web_in_black_list_or_suspected(self,popped):
        def check_if_bad(dns):
            lisData = self.blackList.getListOfAllBlackLists()
            for i in range(0, len(lisData)):
                lis = list(map(lambda x:x.lower(),lisData[i]))
                for j in lis:
                    # print 'j = ' + str(j) + ' popped = ' + str(popped)
                    if j in popped.queryName:
                        print 'Alert! the site: ' + popped.queryName + ' suspecte as ' + str( self.blackList.getType(i) ) + 'site'
                        popped.reportToCsvFile()
        #TODO: I may need to do this with binary search.
        check_if_bad(popped)

    def get_data(self,data_type):
        def make_any_item_in_list_string(lis):
            stList = list(map(str,lis))
            return list(map(lambda x:x.lower(),stList))

        def get_list_from_data_base(data):
            if data == 'chatting':
                return self._firebase.get('/Black_List_Web_Site/Chatting',None)
            elif data == 'porn':
                return self._firebase.get('/Black_List_Web_Site/Porn',None)
            elif data == 'gambling':
                return self._firebase.get('/Black_List_Web_Site/Gambling',None)

        return make_any_item_in_list_string( get_list_from_data_base( data_type ) )

    def get_black_list_IPs(self):
        try:
            raise Exception("ss")
            # self.blackList.Chatting =  self.get_data('chatting')
            # self.blackList.Porn = self.get_data('porn')
            # self.blackList.Gambling = self.get_data('gambling')
        except:
            self.blackList.Chatting = [ "Tinder", "Omegle", "Chatroulette", "7 Cups", "Airtime", "BongaCams", "CAM4", "Chat-Avenue", "Discord", "Chaturbate", "Flirt4free", "Gitter", "Google Hangouts", "HipChat", "LiveJasmin", "Meebo Rooms", "MyFreeCams", "Megacams", "Rounds", "Streamup", "Talkomatic", "Tinychat", "TokBox", "Userplane", "Woo Media", "Xfire" ]
            self.blackList.Porn = [ "PlayBoy", "PornPlanner", "MyPornBible", "Badjojo", "FindTubes", "LasMejoresWebsPorno", "PornMD", "Nudevista", "AdultVideoFinder", "IPornTV", "xVideos", "PornHub", "amster", "XNXX", "YouPorn", "YouJizz", "HClips", "Porn", "TnaFlix", "Tube8", "Spankbang", "DrTuber", "VPorn", "Spankwire", "KeezMovies", "Nuvid", "SunPorno", "PornHD", "Porn300", "SexVid", "ZbPorn", "XXXBunker", "Mofosex", "Xbabe", "PornDroids", "TubSexer", "BeFuck", "MasseurPorn", "Hdmovz", "PornRox", "PornMaki", "Pornid", "Inxporn", "Slutload", "ProPorn", "FakePorn", "Pornhost", "HandjobHub", "TubeV", "Vpornvideos", "DansMovies", "Fapdu", "Porn7", "Rude", "24Porn", "FreudBox", "PornHeed", "Orgasm", "PornRabbit", "MadThumbs", "Fux", "Eroxia", "DeviantClip", "Xxvids", "H2porn", "TopFreePornVideos", "ApeTube", "MetaPorn", "ElephantTube", "Long", "PornerBros" ]
            self.blackList.Gambling = [ "jackpotparadise", "vegasparadise", "betatcasino", "casino", "partycasino", "slottyvegas", "dunder", "betway", "royalpanda" ]
class TheBlackList():
    def __init__(self):
        self.Gambling = []
        self.Porn = []
        self.Chatting = []
        
    def getListOfAllBlackLists(self):
        return [self.Gambling, self.Porn, self.Chatting]
    def getType(slef,index):
        if index == 0:
            return 'gambling'
        elif index == 1:
            return 'porn'
        elif index == 2:
            return 'chatting'