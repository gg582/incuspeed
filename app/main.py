from kivy.app import App
import os
import subprocess
from kivy.uix.popup import Popup
import time
import ast
import requests
from kivy.uix.gridlayout import GridLayout
import json
import asyncio
from kivy.uix.textinput import TextInput
from functools import partial
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout


class LVirCli_Client(GridLayout):

    def __init__(self, **kwargs):
        super(LVirCli_Client, self).__init__(**kwargs)
        self.padding=0
        self.t=None
        self.name = "LVirt"
        self.username_s =""
        self.password_s =""
        self.layout = BoxLayout(spacing=10, orientation = 'vertical',padding=10)
        self.rows = 2
        self.cols = 2
        self.res = ""
        self.add_widget(self.layout)
        self.i = -1
        self.tag = []
        self.btnarr = []
        self.seltagArr = []
        self.sel = 0
        self.threshold = 16
        self.username   = TextInput(text="USERNAME",size_hint=(.7,.7))
        self.layout.add_widget( self.username)
        self.password   = TextInput(hint_text="LVirCli-Deploy",text="PASSWORD",password=True,size_hint=(.7,.7),)
        self.layout.add_widget( self.password)
        self.btn_start = Button(text="Create Container",size_hint=(.7,.7))
        self.btn_start.bind(on_press=self.onCreatePress)
        self.btn_onb = Button(text="Start Container",size_hint=(.7,.7))
        self.btn_onb.bind(on_press=self.onStart)
        self.btn_offb = Button(text="Stop Container",size_hint=(.7,.7))
        self.layout.add_widget(self.btn_start)
        self.btn_offb.bind(on_press=self.onStop)
        self.btn_delete = Button(text="Delete Container",size_hint=(.7,.7))
        self.layout.add_widget(self.btn_onb)
        self.layout.add_widget(self.btn_offb)
        self.layout.add_widget(self.btn_delete)
        self.lock = False
        self.btn_sync = Button(text="Sync Data",size_hint=(.7,.7))
        self.btn_sync.bind(on_press=self.syncOnclick)
        self.layout.add_widget(self.btn_sync)
        self.r = Button(text="Register",size_hint=(.7,.7))
        self.r.bind(on_press=self.register)
        self.layout.add_widget(self.r)
    def syncOnclick(self,instance):
        password = self.password.text
        username = self.username.text
        response = json.loads(requests.post('http://dev.yoonjin2.kr:32000/request',json={"username":username,"password":str(base64.b64encode(bytes(password)))}, timeout = 1).text)

        if len(self.btnarr) != 0:
            for i in self.btnarr:
                self.layout.remove_widget(i)
        self.tag = response
        if len(response) != 0:
            for resp in self.tag:
                self.i+=1
                resp = json.loads(resp,strict=False)
                print(resp)
                self.seltagArr.append(resp.get("tag"))
                print(resp.get("tag"))
                self.tmp = globals()['self.btn{}'.format(self.i)]=Button(text="Select This VM"+":"+"(Port:" +resp.get("serverport")+")"+ " Now",size_hint=(.7,.7))
                self.ids["tag"]=self.seltagArr[self.i]
                self.tmp.bind(on_press = self.onSelectPress)
                self.btnarr.append(self.tmp)
                self.layout.add_widget(self.tmp)
                self.btn_delete.bind(on_press=self.onDeletePress)

    def onCreatePress(self,instance):
        try:
            self.spinLock=True
            self.password_s = self.password.text
            self.username_s = self.username.text
            subprocess.Popen(["/usr/bin/python3", os.getcwd()+"/app/mod.py", self.username_s,str(base64.b64encode(bytes(self.password_s])))
            self.i+=1
        except Exception as ex:
            print(ex)
            print("not registered")
            self.i-=1
        self.spinLock = False
            
    def register(self,instance):
            username = self.username.text
            password = self.password.text
            r = requests.get ('http://dev.yoonjin2.kr:32000/register', auth = (username,str(base64.b64encode(bytes(password))))
    def onDeletePress(self,instance):
        if self.lock:
            return
        if self.i==-1:
            return
        try:
            self.lock = True
            self.deleteStopStartTask('delete')
            wid = self.btnarr[self.sel]
            wid.parent.remove_widget(wid)
            self.tag.remove(self.tag[self.sel])
            self.i-=1
            self.sel-=1
            self.lock = False
        except Exception as ex:
            print(ex)
            self.lock = False
    def onSelectPress(self,instance):
            i = self.seltagArr.index(self.ids["tag"])
            self.sel = i
    def onStart(self,instance):
        self.deleteStopStartTask('start')

    def onStop(self,instance):
        self.deleteStopStartTask('stop')
    def deleteStopStartTask(self,st):
        r = requests.post('http://dev.yoonjin2.kr:32000/'+st, data=self.seltagArr[self.sel])
class LVirCli_App(App):
    def build(self):
        return LVirCli_Client()

LVirCli_App().build()
LVirCli_App().run()

