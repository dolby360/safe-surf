
class reqDataHolder():
    def __init__(self):
        self.hour = None
        self.day_in_week = None
        self.day_in_month = None
        self.month = None
        self.year = None
        self.hour = None
        self.minute = None
        self.seconde = None
        self.id = None
        self.MAC = None
        self.ip_src = None
        self.udp_src_port = None
        self.ip_dst = None
        self.udp_dst_port = None
        self.queryName = None
    def __repr__(self):
        return self.queryName
    def __str__(self):
        return self.queryName
