# -*- coding: utf-8 -*-
"""
Created on Thu Feb 29 16:48:01 2024

@author: USER
"""

class User:
    def __init__(self, name, phoneNumber, ideaKey=None, myPublicHellman=None, myPrivateHellman=None, SenderPublicHellman=None,
                 privateSignKey=None, myPublicSignKey=None, senderPublicSignKey=None, mySign=None, senderSign=None):
        self.name = name
        self.phoneNumber = phoneNumber
        self.ideaKey = ideaKey
        self.myPublicHellman = myPublicHellman
        self.myPrivateHellman = myPrivateHellman
        self.SenderPublicHellman = SenderPublicHellman
        self.privateSignKey = privateSignKey
        self.myPublicSignKey = myPublicSignKey
        self.senderPublicSignKey = senderPublicSignKey
        self.mySign = mySign
        self.senderSign = senderSign






