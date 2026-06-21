#!/usr/bin/env python3
"""WeChat key extraction - 64-bit safe + robust process enumeration.
  - CreateToolhelp32Snapshot.restype = c_void_p (prevent 64-bit handle truncation)
  - All Win32 API calls have explicit argtypes/restype for 64-bit safety
  - EnumProcesses fallback when ToolHelp32 snapshot fails
  - Process name matching: WeChat.exe, WeChatAppEx.exe, Weixin.exe
"""
import ctypes,ctypes.wintypes,json,os,sys
from pathlib import Path
T=2;M=260;P=0x1F0FFF
k=ctypes.WinDLL("kernel32",use_last_error=True)
k.CreateToolhelp32Snapshot.restype=ctypes.c_void_p
k.OpenProcess.restype=ctypes.c_void_p
k.OpenProcess.argtypes=[ctypes.wintypes.DWORD,ctypes.wintypes.BOOL,ctypes.wintypes.DWORD]
k.VirtualQueryEx.restype=ctypes.c_size_t
k.VirtualQueryEx.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t]
k.ReadProcessMemory.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p]
p=ctypes.WinDLL("psapi",use_last_error=True)
p.GetMappedFileNameW.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.wintypes.DWORD]
p.EnumProcesses.argtypes=[ctypes.c_void_p,ctypes.wintypes.DWORD,ctypes.c_void_p]
v=ctypes.WinDLL("version",use_last_error=True)
class E(ctypes.Structure):
 _fields_=[("a",ctypes.wintypes.DWORD),("b",ctypes.wintypes.DWORD),("c",ctypes.wintypes.DWORD),("d",ctypes.POINTER(ctypes.wintypes.ULONG)),("e",ctypes.wintypes.DWORD),("f",ctypes.wintypes.DWORD),("g",ctypes.wintypes.DWORD),("h",ctypes.wintypes.LONG),("i",ctypes.wintypes.DWORD),("j",ctypes.c_char*M)]
class B(ctypes.Structure):
 _fields_=[("a",ctypes.wintypes.LPVOID),("b",ctypes.wintypes.LPVOID),("c",ctypes.wintypes.DWORD),("d",ctypes.c_size_t),("e",ctypes.wintypes.DWORD),("f",ctypes.wintypes.DWORD),("g",ctypes.wintypes.DWORD)]
class F(ctypes.Structure):
 _fields_=[("a",ctypes.wintypes.DWORD),("b",ctypes.wintypes.DWORD),("c",ctypes.wintypes.DWORD),("d",ctypes.wintypes.DWORD),("e",ctypes.wintypes.DWORD),("f",ctypes.wintypes.DWORD)]
W={"3.2.1.154": [328121948, 328122328, 328123056, 328121976, 328123020], "3.3.0.115": [31323364, 31323744, 31324472, 31323392, 31324436], "3.3.0.84": [31315212, 31315592, 31316320, 31315240, 31316284], "3.3.0.93": [31323364, 31323744, 31324472, 31323392, 31324436], "3.3.5.34": [30603028, 30603408, 30604120, 30603056, 30604100], "3.3.5.42": [30603012, 30603392, 30604120, 30603040, 30604084], "3.3.5.46": [30578372, 30578752, 30579480, 30578400, 30579444], "3.4.0.37": [31608116, 31608496, 31609224, 31608144, 31609188], "3.4.0.38": [31604044, 31604424, 31605152, 31604072, 31605116], "3.4.0.50": [31688500, 31688880, 31689608, 31688528, 31689572], "3.4.0.54": [31700852, 31701248, 31700920, 31700880, 31701924], "3.4.5.27": [32133788, 32134168, 32134896, 32133816, 32134860], "3.4.5.45": [32147012, 32147392, 32147064, 32147040, 32148084], "3.5.0.20": [35494484, 35494864, 35494536, 35494512, 35495556], "3.5.0.29": [35507980, 35508360, 35508032, 35508008, 35509052], "3.5.0.33": [35512140, 35512520, 35512192, 35512168, 35513212], "3.5.0.39": [35516236, 35516616, 35516288, 35516264, 35517308], "3.5.0.42": [35512140, 35512520, 35512192, 35512168, 35513212], "3.5.0.44": [35510836, 35511216, 35510896, 35510864, 35511908], "3.5.0.46": [35506740, 35507120, 35506800, 35506768, 35507812], "3.6.0.18": [35842996, 35843376, 35843048, 35843024, 35844068], "3.6.5.7": [35864356, 35864736, 35864408, 35864384, 35865428], "3.6.5.16": [35909428, 35909808, 35909480, 35909456, 35910500], "3.7.0.26": [37105908, 37106288, 37105960, 37105936, 37106980], "3.7.0.29": [37105908, 37106288, 37105960, 37105936, 37106980], "3.7.0.30": [37118196, 37118576, 37118248, 37118224, 37119268], "3.7.5.11": [37883280, 37884088, 37883136, 37883008, 37884052], "3.7.5.23": [37895736, 37896544, 37895592, 37883008, 37896508], "3.7.5.27": [37895736, 37896544, 37895592, 37895464, 37896508], "3.7.5.31": [37903928, 37904736, 37903784, 37903656, 37904700], "3.7.6.24": [38978840, 38979648, 38978696, 38978604, 38979612], "3.7.6.29": [38986376, 38987184, 38986232, 38986104, 38987148], "3.7.6.44": [39016520, 39017328, 39016376, 38986104, 39017292], "3.8.0.31": [46064088, 46064912, 46063944, 38986104, 46064876], "3.8.0.33": [46059992, 46060816, 46059848, 38986104, 46060780], "3.8.0.41": [46064024, 46064848, 46063880, 38986104, 46064812], "3.8.1.26": [46409448, 46410272, 46409304, 38986104, 46410236], "3.9.0.28": [48418376, 48419280, 48418232, 38986104, 48419244], "3.9.2.23": [50320784, 50321712, 50320640, 38986104, 50321676], "3.9.2.26": [50329040, 50329968, 50328896, 38986104, 50329932], "3.9.5.81": [61650872, 61652208, 61650680, 0, 61652144], "3.9.5.91": [61654904, 61656240, 61654712, 38986104, 61656176], "3.9.6.19": [61997688, 61997464, 61997496, 38986104, 61998960], "3.9.6.33": [62030600, 62031936, 62030408, 0, 62031872], "3.9.7.15": [63482696, 63484032, 63482504, 0, 63483968], "3.9.7.25": [63482760, 63484096, 63482568, 0, 63484032], "3.9.7.29": [63486984, 63488320, 63486792, 0, 63488256], "3.9.8.12": [53479320, 53480288, 53479176, 0, 53480252], "3.9.8.15": [64996632, 64997968, 64996440, 0, 64997904], "3.9.8.25": [65000920, 65002256, 65000728, 0, 65002192], "3.9.9.27": [68065304, 68066640, 68065112, 0, 68066576], "3.9.9.35": [68065304, 68066640, 68065112, 0, 68066576], "3.9.9.43": [68065944, 68067280, 68065752, 0, 68067216], "3.9.10.19": [95129768, 95131104, 95129576, 0, 95131040], "3.9.10.27": [95125656, 95126992, 95125464, 0, 95126928], "3.9.11.17": [93550360, 93551696, 93550168, 0, 93551632], "3.9.11.19": [93550296, 93551632, 93550104, 0, 93551568], "3.9.11.23": [93701208, 93700984, 93701016, 0, 93700920], "3.9.11.25": [93701080, 93702416, 93700888, 0, 93702352], "3.9.12.15": [93813544, 93814880, 93813352, 0, 93814816], "3.9.12.17": [93834984, 93836320, 93834792, 0, 93836256], "3.9.12.31": [94516904, 94518240, 94516712, 0, 94518176], "3.9.12.37": [94520808, 94522144, 94522146, 0, 94522080], "3.9.12.45": [94503784, 94505120, 94503592, 0, 94505056], "3.9.12.51": [94555176, 94556512, 94554984, 0, 94556448], "3.9.12.55": [94550988, 94552544, 94551016, 0, 94552480]}
WX_NAMES=("WeChat.exe","WeChatAppEx.exe","Weixin.exe","Wechat.exe","wechat.exe")
def gp_debug():
 s=k.CreateToolhelp32Snapshot(T,0)
 if not s or s==ctypes.c_void_p(-1).value:return[]
 pe=E();pe.a=ctypes.sizeof(pe);r=[]
 if k.Process32First(s,ctypes.byref(pe)):
  while True:
   r.append(pe.j.decode("utf-8",errors="ignore"))
   if not k.Process32Next(s,ctypes.byref(pe)):break
 k.CloseHandle(s);return r
def gp():
 s=k.CreateToolhelp32Snapshot(T,0)
 if not s or s==ctypes.c_void_p(-1).value:return[]
 pe=E();pe.a=ctypes.sizeof(pe);r=[]
 if k.Process32First(s,ctypes.byref(pe)):
  while True:
   n=pe.j.decode("utf-8",errors="ignore")
   if n in WX_NAMES:r.append(pe.c)
   if not k.Process32Next(s,ctypes.byref(pe)):break
 k.CloseHandle(s);return r
def gp_enum():
 """Fallback: use EnumProcesses from psapi (more reliable in some environments)."""
 sz=4096;buf=(ctypes.c_uint*(sz+1))();cb=ctypes.c_uint()
 if not p.EnumProcesses(ctypes.byref(buf),sz*4,ctypes.byref(cb)):return[]
 n=cb.value//4;r=[]
 k.QueryFullProcessImageNameW.restype=ctypes.wintypes.BOOL
 k.QueryFullProcessImageNameW.argtypes=[ctypes.c_void_p,ctypes.wintypes.DWORD,ctypes.c_wchar_p,ctypes.POINTER(ctypes.wintypes.DWORD)]
 for i in range(n):
  pid=buf[i]
  h=k.OpenProcess(0x1000,False,pid)
  if not h:continue
  nm=ctypes.create_unicode_buffer(M)
  sz2=ctypes.wintypes.DWORD(M)
  if k.QueryFullProcessImageNameW(h,0,nm,ctypes.byref(sz2)):
   name=os.path.basename(nm.value)
   if name in WX_NAMES:r.append(pid)
  k.CloseHandle(h)
 return r
def fd(pid):
 h=k.OpenProcess(P,False,pid)
 if not h:return 0,None
 m=B();a=0
 while a<0x7FFFFFFFFFFFFFFF:
  if k.VirtualQueryEx(h,ctypes.c_void_p(a),ctypes.byref(m),ctypes.sizeof(m))==0:break
  if m.e==0x1000 and m.d>0:
   b=ctypes.create_unicode_buffer(M)
   if p.GetMappedFileNameW(h,ctypes.c_void_p(m.a),b,M)>0:
    if"WeChatWin.dll"in b.value:return m.a,h
  a+=max(m.d,0x1000)
 k.CloseHandle(h);return 0,None
def gv():
 for base in[os.environ.get("ProgramFiles",""),os.environ.get("ProgramFiles(x86)",""),os.environ.get("LOCALAPPDATA","")]:
  pp=os.path.join(base,"Tencent","WeChat","WeChatWin.dll")
  if not os.path.exists(pp):continue
  sz=v.GetFileVersionInfoSizeW(pp,None)
  if not sz:continue
  buf=ctypes.create_string_buffer(sz)
  if not v.GetFileVersionInfoW(pp,0,sz,buf):continue
  u=ctypes.wintypes.UINT();l=ctypes.c_void_p()
  if not v.VerQueryValueW(buf,"\\\\",ctypes.byref(l),ctypes.byref(u)):continue
  f=ctypes.cast(l,ctypes.POINTER(F)).contents
  if f.a!=0xFEEF04BD:continue
  return str((f.c>>16)&0xffff)+"."+str(f.c&0xffff)+"."+str((f.d>>16)&0xffff)+"."+str(f.d&0xffff)
 return""
def rm(h,a,sz):
 b=ctypes.create_string_buffer(sz)
 if k.ReadProcessMemory(h,ctypes.c_void_p(a),b,sz,0)==0:return None
 return bytes(b)
def rs(h,a,sz=64):
 d=rm(h,a,sz)
 if not d:return None
 return d.split(b"\x00")[0].decode("utf-8",errors="ignore").strip() or None
def rk(h,a):
 pd=rm(h,a,8)
 if not pd:return None
 ka=int.from_bytes(pd,"little");kd=rm(h,ka,32)
 return kd.hex() if kd else None
def main():
 if sys.platform!="win32":print("[!] Windows only.");sys.exit(1)
 print("[*] Scanning WeChat...",flush=True)
 pids=gp()
 src="ToolHelp32"
 if not pids:
  print("[*] ToolHelp32 found 0, trying EnumProcesses fallback...",flush=True)
  pids=gp_enum();src="EnumProcesses"
 if not pids:
  ap=gp_debug()
  print("[!] WeChat not found via ToolHelp32 or EnumProcesses.",file=sys.stderr)
  print("[!] Found %d total processes."%len(ap),file=sys.stderr)
  if not ap:
   err=ctypes.get_last_error()
   print("[!] CreateToolhelp32Snapshot likely failed (last_error=%s)."%(err,),file=sys.stderr)
   print("[!] Hint: ensure the process has sufficient privileges.",file=sys.stderr)
  for x in ap[:30]:print("  "+x,file=sys.stderr)
  sys.exit(1)
 print("[+] Found %d process(es) via %s"%(len(pids),src))
 key=None;ver=gv();info={}
 print("[+] Version: "+(ver or "??"))
 for pid in pids:
  base,h=fd(pid)
  if not base or not h:continue
  bl=W.get(ver,None)
  if bl and len(bl)>4:
   if bl[0]:info["nickname"]=rs(h,base+bl[0])
   if bl[1]:info["account"]=rs(h,base+bl[1])
   if bl[2]:info["mobile"]=rs(h,base+bl[2])
   if bl[4]:key=rk(h,base+bl[4])
  k.CloseHandle(h)
  if key:break
 if not key:print("[!] Key not found. Supported: "+str(len(W))+" versions.");sys.exit(1)
 nm=info.get("nickname")or info.get("account")or"unknown"
 print("[+] WeChat: "+nm+"  Key: "+key[:8]+"...")
 keys={}
 try:
  import winreg
  for hive in[winreg.HKEY_CURRENT_USER,winreg.HKEY_LOCAL_MACHINE]:
   for sub in["Software\\Tencent\\WeChat","Software\\WOW6432Node\\Tencent\\WeChat"]:
    try:
     rg=winreg.OpenKey(hive,sub);vv,_=winreg.QueryValueEx(rg,"InstallPath");winreg.CloseKey(rg)
     if vv and os.path.isdir(vv):
      for r,ds,fs in os.walk(vv):
       for f in fs:
        if f.endswith(".db"):
         fl=os.path.join(r,f);rl=os.path.relpath(fl,vv).replace("\\","/")
         keys[rl]={"enc_key":key,"salt":""}
    except:pass
 except:pass
 if not keys:
  for db in["session/session.db","general/general.db","contact/contact.db","msg/MSG0.db"]:
   keys[db]={"enc_key":key,"salt":""}
 cd=os.path.join(os.path.expanduser("~"),".dustmirror","pywxdump_cache")
 os.makedirs(cd,exist_ok=True)
 op=os.path.join(cd,"keys.json")
 Path(op).write_text(json.dumps(keys,ensure_ascii=False,indent=2),encoding="utf-8")
 print("[+] Saved "+str(len(keys))+" keys to: "+op);print("[+] Done!")
if __name__=="__main__":main()
