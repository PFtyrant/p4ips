from pymongo import MongoClient
from bson.objectid import ObjectId
import json
import threading
import enum
import sys
import os
import fcntl
import time
import re

class FieldType(enum.Enum):
    src_IP = 0
    dst_IP = 1
    src_port = 2
    dst_port = 3
    protocol = 4
    predicted_time = 5
    label = 6
    ingress_ts1 = 7
    ingress_ts2 = 8

class DbManager:
    USERNAME = 'root'
    PASSWORD = 'root'
    HOST = '192.168.13.71'
    PORT = '27017'


    def __init__(self):
        self.client = MongoClient("mongodb://" + self.USERNAME + ":"
                        + self.PASSWORD + "@" + self.HOST + ":" + self.PORT + "/")
        self.djangoDB = self.client["django"]
        self.idsCollection = self.djangoDB["IDS"]

    def insert_entry(self, entry_str):
        entry = entry_str.split(" ")
        entry = {"src_IP": entry[FieldType.src_IP.value], "dst_IP": entry[FieldType.dst_IP.value], 
                    "src_port": entry[FieldType.src_port.value], "dst_port": entry[FieldType.dst_port.value],
                    "protocol": entry[FieldType.protocol.value], "predicted_time": entry[FieldType.predicted_time.value],
                    "label": entry[FieldType.label.value], "ingress_ts1": entry[FieldType.ingress_ts1.value], "ingress_ts2": entry[FieldType.ingress_ts2.value]}
        self.idsCollection.insert_one(entry)


if __name__ == "__main__":
    dbManager = DbManager()
    print("---------- Mongodb --------")

    while True:
        try:    
            entry = input()
            entry = re.sub(u"\u0000", "", entry)
            # time.sleep(2) 
            # entry = "10.1.1.198 10.0.1.22 68 67 17 814342 1"
            # print("entry:", entry)  
            dbManager.insert_entry(entry)
        except KeyboardInterrupt:
            print("ctrl+C occured")
            break

    print("---------- Mongodb end --------")    