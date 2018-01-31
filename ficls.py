# -*- coding: utf-8 -*-
# CLASS FOR FILTERS FUNCTIONS

import string
import os
import re
import sys
from colorama import Fore, Back, Style

# ++++++++++++++++
# SEARCH FILTERS +
# ++++++++++++++++

class fcls:

	# +++ Dynamic Filters +++
	city = None
	country = None
	port = None   # string split with ','
	os = None
	geo = None   # 54.3453453,32.567236
	ipnetm = None   # ip/netmask  exmp: 100.9.0.0/8   string
	hostname = None
	dateab = None    # for after and befor tag    string

	# +++ Static Filters +++
	# OTHERE TAGS:
	OTHER_TAGs = ['dfp','TorMarket','darkcometRAT','darkcometRAT1','classified','defpass']

	OTHER_TAGs_VAL = ['default password','''html:"tor" html:"market"''','BF7CAB464EFB','''"8EA4AB05FA7E"'''
	,'classified','''"default password"''']

	OTHER_TAGs_COM = ['default passwords','tor markets','DarkComet RAT','DarkComet/NJ RAT','classified things'
	,'providing default password']


	### SCADA TAGS:
	SCADA_TAGs = ['scmd','scada','idroute','eingatech','climate','akcp_embeded','moxa','simatic'
	,'spidercontrol','modicon','ic_104','siemens_saphir','nport_C','siemensS7','STClimate','ruggedcom'
	,'schneiderPCL','bacnet','hwellEX','OERP','plc','labview','niagara200','ABslc5','adcon','moreclimate'
	,'pdu','thus','seeds','windT','hwellBNA','z_world','entrasys','swbox','inverter','s7siemens','vt'
	,'niagaran','senecLES','pvsolar','sunway','siemensICS','schneidetESC','pvinverter','citrix_app'
	,'photovoltaic','simatic_HMI','simatic_net','simens_simaticHMI','solar_log','rockwellPLC'
	,'siemensPLC','ullage','entelitouch','inverterWI','vtscada_1','solarinverter','fujiSiemens_RMI','nordex'
	,'tacxenta913','avaya','clp80','clpNuclear','moxaSIPg','ion','freezer']

	SCADA_TAGs_VAL = ['modbus','scada','helmholz','EIG Embedded Web Server','akcp','AKCP Embedded','moxa'
	,'HMI, XP277','powered by SpiderControl TM','modicon','port:2404 ASDU','wince Content-Length: 12581'
	,'''"Model name : 5232-N" port:23''','Portal0000','Stulz GmbH Klimatechnik','GoAhead-Webs InitialPage.asp'
	,'schneider','bacnet','honeywell Excel','openerp','plc','LabView','niagara200','port:161 SLC5'
	,'title:adcon','iq3','Schleifenbauer','THUS plc','SEEDS gateway','''title:"XZERES Wind"''','honeywell BNA'
	,'Z-World Rabbit 200 OK','entrasys','Sunny WebBox','''title:"Inverter Webinterface"'''
	,'siemens s7 S7 Basic Hardware:','Server: VTScada','niagara_audit -login','title:SenecIES'
	,'''title:"PV Solar Inverter"''','Server: emBetter','Original Siemens Equipment Basic Firmware:'
	,'title:logic','''title:"inverter mintor"''','Citrix Applications:','''"IS2 Web Server"'''
	,'Simatic -S7 HMI','Simatic -S7 -HMI','Location: Default.html -apache -nginx -microsoft -etag -goahead -vxworks -jetty -GoAhead 302 -Cookie'
	,'IPC@CHIP title:Start','port:44818','''"plant identification"''','ULLAGE','enteliTOUCH','''title:"Inverter Monitor" "Connection: Close"'''
	,'''"Server: VTS" -IIS -Apache -nginx 401 -500 -Boa -Sitewatch -Apple -httpd -cpsrvd -Ubicom -DCS-6620'''
	,'Server: http:/www.sajbp.com/','serverview','''Jetty 3.1.8 (Windows 2000 5.0 x86) "200 OK"'''
	,'Tac XENTA 913','avaya','CLP port:80','CLP','Console terminal type','''port:23 "Meter ION"''','title:phasefale']

	SCADA_TAGs_COM = ['modbus','scada','industrial routing','electro industrial gaugetech','climate control'
	,'AKCP Embeded','moxa','simatic','spidercontrol TM','modicon','IC-104','SAPHIR','NPort 5232-N Controllers'
	,'SCADA SIEMENS S7 CP','stulz climate control','ruggedcom','schneider PCL','bacnet','honeywell excel controllers'
	,'OpenERP','PLC','LabView','niagara 200','allen bradley SLC5','adcon telemetry gateway','more climate controls'
	,'power distribution units','THUS PLC','sunEdison Energy and Environment Data System','XZEREZ 422SR Wind Turbine'
	,'honetwell building network adapter','Z_World RABBIT server','Entrasys switches','Sunny WebBox'
	,'inverter webinterface','siemens S7','VTScada ICSA-17-164-01','niagara SCADAOPEN','intelligent energy system'
	,'PV solar inverter logging','sunwaysNT inverter','SiemensICS','schneidet electric scada','PV Inverter'
	,'Citrix','Meteocontrol weblog','Simatic HMI','Simatic HMI 1','Siemens Simatic HMI','solar-log  sloar panels'
	,'rockwell','siemens PLCs','ULLAGE','Delta Entelitouch','Inverter webinterface','VTSCADA','Solar Inverter'
	,'Fujitsu-Siemens RMI','Nordex Control2','TAC/XENTA 913','Avaya Switches','CLP port 80','CLP Nuclear'
	,'MOXA Serial/Ip gateway','ION Smart Meters','Freezer Rooms']


	### HTTP TAGS:
	HTTP_TAGs = ['cds','austw','microhttpd','winRM','cisco_http','sip80','TechVDVR','apachSRV','allapacheV1'
	,'https','netswi','apccardman','tvood','shbox','photosmart','rrv','allHP','epsonP','NepsonP','chSIP'
	,'Iphonelht','rdadmin','iis30','rd1234','aftele','snomvp','djang','owl','gsGXP','windweb','iis20','iqinvision'
	,'HPp','udpxy','cisco_ios','iis40','routedef','HeatMON','OpenWRT','envisalink','ng','ap','iis5','iis6'
	,'iis7','iis75','iis8','iis85','iis9','iis10','gapache']

	HTTP_TAGs_VAL = ['CarelDataServer','Auther: Steven Wu','HTTP/1.0 200 Ok Server: micro_httpd Set-Cookie: Name=; path=/'
	,'port:5985 Microsoft-HTTPAPI/2.0','''Cisco “200 OK” port:80''','sip port:80','Techno Vision Security System'
	,'server:apache','''"apache 1.0*" | "apache 1.1*" | "apache 1.2*" | "apache 1.3*" port:80''','HTTPS'
	,'Network Switch','APC Management Card','http Tilgin Vood','''title:"shell in a box"''','Photosmart'
	,'Server:Thin -3.2.11 -3.1.10 -3.0.19 -2.3.15','HP','http 200 server epson -upnp','http 200 server epson_linux upnp'
	,'camera ip','iPhone lighttpd','Default:+admin','''IIS 3.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1"''','admin+1234'
	,'''"apache 0.9*" port:80''','snom embedded','WSGIServer','Oracle_Web_Listener','Grandstream GXP','WindWeb'
	,'''IIS+2.0 -"6.0" -"7.0" -"7.5" -"5.0" -"5.1"''','iqinvision','hp/device/this.LCDispatcher','udpxy'
	,'cisco-ios','''IIS 4.0  -"6.0" -"7.0" -"7.5" -"5.0" -"5.1" -"404" -"403" -"302"'''
	,'''Enable and Telnet passwords are configured to "password".''','Z-World Rabbit title:Netmonitor'
	,'OpenWRT','envisalink','nginx','apache','iis/5.0','iis/6.0','iis/7.0','iis/7.5','iis/8.0','iis/8.5'
	,'iis/9.0','iis/10.0','apache hostname:.google.com']

	HTTP_TAGs_COM = ['Corel Data Server','Auther: Steven Wu','Micro httpd','WINRM 2.0','CISCO','SIP Server'
	,'Techno Vision DVR','apache server','Apache1 all versions','HTTPS','Network Switches','APC Management Card'
	,'sever tilgin vood','shell in a box','HP Photosmart','Ruby on Rail Vulnerability','All HP'
	,'EPSON Network Printers','NEWER EPSON Network Printers','Chinese sip protocol servers','iPhone litehttpd'
	,'Routers that show admin password in banner','IIS3.0 with remove all false positives'
	,'routers with default user admin and default pass 1234','AFHCAN Telehealth','SNOM VOiP','Django'
	,'Oracle Web Listener','Grandstream GXP VOiP','Wind Webserver','IIS2.0 with remove all false positives'
	,'IQeye Cameras  -  default login root/system','HP Printers','UDPXY','CISCO-IOS','IIS4.0 with remove all false positives'
	,'routers with admin:password on ssh/telnet/http','HeatMiser NetMONITOR','OpenWRT','envisalink alarm controller'
	,'nginx','apache','iis/5.0','iis/6.0','iis/7.0','iis/7.5','iis/8.0','iis/8.5','iis/9.0','iis/10.0'
	,'''google's apache webs''']	


	### SERVER TAGS:
	SERVER_TAGs = ['bomgar','canhtp','kerCTS','lantronix','weedf','plex','icecast','kasper','cudatel','exch'
	,'chrp','monit','ssm','serv','acpp','jserver','passprotect','ongames','sapnet','tilginvood','iomega'
	,'email','Sapachserv','Einternal','minecraft','enviveo','proxmox','whsl','ps4','sps','andserv','SMAslp'
	,'geovision','logitech','print_server','smallB','NETS_web']

	SERVER_TAGs_VAL = ['Server: Bomgar','canon port:80','web stream','Lantronix','weed ftpd server','Plex'
	,'Server: Icecast','hostname:kaspersky.com port:80,21,22','title:CudaTel 200','Exchange','CHRP','monit'
	,'''Supervisor status port:"9001"''','server','port:5009 acpp','''"You're successfully running JSON Server"'''
	,'port:80 title:protected','Server: games','server: SAP NetWeaver Application Server','http Tilgin Vood'
	,'''title:"Iomega"''','email','hamburger 200 ok','''hostname:"internal"''','port:25565 Minecraft protocol 340'
	,'4caster','''title:"Proxmox Virtual Environment"''','remote X-AspNet-Version: 4.0.30319','ps4','SyncThru'
	,'''"server: android"''','Server: Sunny WebBox','server:GeoHttpServer','Logitech Media Server -401 -404'
	,'PRINT_SERVER WEB +200 -401 -NeedPassword','''MicrosoftOfficeWebServer 200 "default.htm", title:"welcome to"'''
	,'Server: uc-httpd 1.0.0 200 OK']

	SERVER_TAGs_COM = ['bomgar support portal','CANON http server','kerio control server','LANTRONIX'
	,'weed ftpd server','Plex Server','ICECAST server','kaspersky','CudaTel communication server login'
	,'microsoft exchange','CHRP','Monit server manager','Supervisor service manager','some server'
	,'apple airport acars server','json server','pass protected dir  ,   it will be good when combined with country filter'
	,'Online Games','SAP NetWeaver','tilginvood','Iomega','email','some apache servers','Exposed Internal servers'
	,'Minecraft servers','Enviveo 4caster','proxmox','Windows Home Sever Logon','PS4','samsung print server'
	,'android server','SMA solar power','GEOVISION','Logitech server','print server','Windows small business server 2003'
	,'NETSurveillance web']


	### FTP TAGS:
	FTP_TAGs = ['vsftpd234','dreambox','ftps','bigfix','Sproftpd','Svsftpd','Spureftpd','filezilla','anonftpd'
	,'asus_ftp','anon_granted','anon_granted1','anon_granted2','anon_granted3','anon_granted4','anon_granted5'
	,'anon_granted6','VxWorksFTP','loggedFTP','weed_ftpd','Olog','netgearFTP','ANproftpd','NETprobe','Special_asus'
	,'All_asus_rtn56u','all_ftp','all_ftp1','Sstingray','kgcftp','netgearANON','netgearFTP1','HPftp','NASanon'
	,'amazon_anonftp','micFTPanon','surgeFTP','comCast_anon','loggedFTP','raspberry_ftp','traffic']

	FTP_TAGs_VAL = ['vsftpd 2.3.4','''dreambox org:"Fastweb" port:23''','ftp 230 -unknown -print','bigfix'
	,'220 ProFTPD 1.3.3a Server (Debian)','vsftpd 2.3.4 port:21','''port:"21" product:"Pure-FTPd"'''
	,'filezilla','''"230 Anonymous user logged in" port:21''','port:21 asus -530','Anonymous access granted -restrictions'
	,'Anonymous access granted','port:21 230','port:21 anonymous','''“Anonymous+access+allowed”  connected -530'''
	,'ftp 230 -unknown -print','230','''VxWorks port:21 "logged in"''','''"Logged" port:21''','weed ftpd server'
	,'230 Login successful.','WNDR3800 logged in','''220 ProFTPD Server "anonymous access granted"''','NETProbe'
	,'ASUS RT-N56U 230','ASUS+RT-N56U','ftp','port:21','StingRay FTP Server 3.0.2 220 214','220 KGC FTP Server ready'
	,'NETGEAR- logged in','NETGEAR-WNDR4700 230','230-Hewlett-Packard','port:21 anonymous logged nas'
	,'''org:"Amazon Technologies" port:21 "Login successful" welcome''','''port:21 User logged in product:"Microsoft ftpd"'''
	,'SurgeFTP','LinksysWRT350N Anonymous access granted','''230 "Logged" port:21''','raspbian-7','vri']

	FTP_TAGs_COM = ['all vsftpd 2.3.4','dreambox ftp server','some ftp servers','bigfix','proftpd 1.3.3a'
	,'vsftpd 2.3.4','pureftpd','filezilla','Anon ftp revised','asus ftp','fully anonymous access granted'
	,'fully anonymous access granted #1','fully anonymous access granted #2','fully anonymous access granted #3'
	,'fully anonymous access granted #4','fully anonymous access granted #5','fully anonymous access granted #6'
	,'VxWorks FTP anonymous','anonymous logged ftp','weed ftpd server','Open FTP servers','NETGEAR ftp login'
	,'proftpd with anonymous access granted','NETProbe','OPEN asus RT-N56U ftp server','asus RT-N56U ftp server'
	,'ftp','ftp #1','Stingray ftp server','KGC ftp server','netgear anonymous loggedin','netgear anon'
	,'HP ftp server','Anon NAS ftp server','amazon anonymous ftp login','Microsoft ftp anonymous','SurgeFTP'
	,'COMCAST ANON ACCESS','logged ftp server , will be good when combined with country filter'
	,'Raspberry can use as ftp','traffic lights']


	### ROUTER TAGS:
	ROUTER_TAGs = ['juniper','alcatelRoute','easybox','indosat','ip9000hd','tlspeed','dslrouter','hugeRouter'
	,'openwrtRoute','rompager_route','rom_page','rompager1','tp','dl','zx','lk','ntg','cis','siemensKPN'
	,'someROM0','zhoneR','ubicomEMB','xfinity','mobily','teldat','freetz','netgearR6250','DI804','virginSU'
	,'virginSUrm','superhubMedia','zyxellp','tenda_wless','ufax2','netish','defUP','atlas_adtran','zte_zxr10'
	,'anongateway','virginMedia','ddwrt','wag120_linksys','IOSssh','tpWR841','zyxelVuln','asusRTN12','insecLAN'
	,'cisco_vsat','airstation','asusRTN13','cisco_defconf','dlink_route','dlink_wenI','xfinity_modem','airlive'
	,'_3com','rom0Vuln','D600CP']

	ROUTER_TAGs_VAL = ['juniper','''"cpm/hops ALCATEL"''','easybox','indosat.com','IP9000HD Web Access'
	,'speedport','''WWW-Authenticate: Basic realm "DSL Router"''','''title:"Protected Object"'''
	,'''HTTP/1.1 200 OK Connection: Keep-Alive Transfer-Encoding: chunked Keep-Alive: timeout=20 ETag: "17b-1a3-541dd9df"'''
	,'Transfer-Encoding: chunked  Server: RomPager/4.51 UPnP/1.0 country:MY','rompager','Server: RomPager'
	,'tp-link','d-link','zyxel','linksys','netgear','cisco','Siemens Subscriber Networks','ZXV10 W300'
	,'ZNID24xxA-Router','Ubicom -401','XFINITY http','''"MOBILY"''','port:23  teldat 2001'
	,'WWW-Authenticate: Basic realm Freetz','port:8443 NETGEAR R6250','''realm="DI-804HV"'''
	,'Last-Modified: Fri, 03 Jun 2016 20:05:30 GMT','''port:8443 country:gb org:"Virgin Media" lighttpd'''
	,'''title:"Super Hub | GUI"''','''title:"Web-Based Configurator"''','tenda ADSL2/2'
	,'''HTTP/1.1 401 Unauthorized WWW-Authenticate: Digest qop="auth", realm="www.ufax2.com"'''
	,'''hash:-704822131 port:"53413"''','''"password 1234"''','port:23 mqqqqqqqqk','ZXR10 carrier'
	,'''"IP_SHARER WEB" -realm''','WMRN PoP at Virgin Media','build 13064 200','Linksys WAG120N','''"cisco cp"'''
	,'''router "HTTP/1.1 200 OK"''','''"P-660HW-T1 v3"''','rt-n12e','''"Configure LAN interface"''','cisco router vsat'
	,'Airstation','RT-N13U port:23','IOS one-time port:23','port:80 thttpd alphanetworks','D-LINK SYSTEMS, INC'
	,'''"Server: lighttpd" title:"Xfinity"''','AirLive WT-2000ARM'
	,'''title:"3Com - OfficeConnect ADSL Wireless 11g Firewall Router"''','kr.yl'
	,'''title:"D-LINK SYSTEMS, INC. | WIRELESS ROUTER | HOME" 200''']

	ROUTER_TAGs_COM = ['juniper','alcatel routers','vodafone easybox','indosat router','IP9000HD Web Access'
	,'telekom speedport','DSL router','huge number of routers','openwrt','rompager routers','rompager'
	,'rompager #1','tplink','dlink','zyxel','linksys','netgear','cisco','siemens KPN routers'
	,'some router with rom0   ip/rom-0','zhone routers','lots of embeded device | most of them  are d-link'
	,'XFINITY routers','mobily routers SA','teldat router','Freetz firmware','netgear R6250','DI-804HV'
	,'virgin superhub 3','virgin superhub 3 remote management','virgin superhub','zyxel login panel'
	,'tenda wireless modem','ufax2 npf601','netish potential backdoor','default user and password'
	,'atlas adtran 500 router','ZTE ZXR10 high-end router','anonymous router interface','virgin media backbone'
	,'DD-WRT config page','linksys wag 120 router','cisco IOS with ssh','tp-link WR841','zyxel vulnerable routers'
	,'asus RT-N12E','LANs without sec   La Perfecto !!!','cisco vsat router','airstation','asus RT-N13U'
	,'cisco routers that are still in default config','dlink routers','dlink routers web interface','xfinity modems'
	,'airlive adsl routers','3com routers','routers that has rom0 vulnerability','D-link D600 control panel']


	### DATABASE TAG:
	DATABASE_TAGs = ['mysql','postgre','mongo','mongo1','riak','elastic','redis','memcached','cassandra','couch']

	DATABASE_TAGs_VAL = ['product:MySQL','port:5432 PostgreSQL','MongoDB Server Information','product:MongoDB'
	,'port:8087 Riak','port:9200 json','product:Redis','product:Memcached','product:Cassandra','product:CouchDB']

	DATABASE_TAGs_COM = ['mysql DB','postgre DB','MongoDB','mongoDB 1','Riak DB','elastic DB','Redis DB'
	,'Memcached DB','Cassandra DB','Couch DB']


	### CAM TAGS:  WEBCAM , CAMERA & CAM
	CAM_TAGs = ['wbc','ctv','dvr','netcam1','easyN','avigilon','wcamXP','wcamXP1','logitecCAM','ipcamFC','netwaveip'
	,'ipcamBA','ipcamBA1','netwaveip1','othipcam','othipcam1','ipcam85open','yc','netwaveip2','avupnp','camAll'
	,'HcamBasic','ic','ic1','basicCAM','ipspeed','foscam','unsecCAM','pavelCAM','hostCAM','tIPcam','Aipcams'
	,'NetCAM','IpVid','DlinkIPCAM','DlinkCAM','boxipcam','foscam_wifi','NTwaveA','CamNi','VidIPcam','MiNiIpCam'
	,'ENipPh','HuawiIpPH','TPlink_Ipcam','andicam','andicam1','tCAM','maygion','maygion1','TeleEye'
	,'TmobileCAM','jaws','trendNet','canonVBC','ciscoCAM','wvc80n','ipcam2','fritz','OBIrisServ','DVRcdown'
	,'SOWC','camWS','NetBotZ','mjpg','mjpg1','IQiN','OCAMS','axis','itron','DVSScam','FlexiDome','iCAN','secSpy'
	,'HomeCAM','PTZicam','PTZ','NUUO','SonyNETCAM','tuxedo','vilar','LNE3003','samsungDVR','dcs5220','galoreIPCAM'
	,'NCC','lightCAM','CAMdork','vivotek','lilin','scCAM','airlink','megapixel','motioneye','NetSurvilanceWEBcam'
	,'inspire','hikvisionNVR','RedLightCAM','RedLight','highDef','loxone','CANONvbm40','DMCS','NCM','polycoms'
	,'HikVision','TeleEyeJV','EverFocus','ANPRC','PIPS','DCS5300','NetCamXL','arecont','chianet','DlinkINetCAM'
	,'vmax','weatherWing','checkstream','go1984','UBNTcam','abelcam','OcamNAU','iCatcher','VScam','ADHweb'
	,'VB100','sqCAMs','CiscoNCAM','imagiatek','bosch','KSC','hipcam','iPolis','maginon','axis_m1103','geovision_ipcam'
	,'timhillone','VulnCAM','speco','heden']

	CAM_TAGs_VAL = ['webcam','cctv','dvr','netcam','''Server: thttpd Basic realm="index.html"''','Avigilon'
	,'''webcamxp product:"webcamXP httpd"''','webcamxp','logitec -401 -400 -301 -302','IP Webcam Server 0.3'
	,'server: netwave IP camera','''Basic realm="IP camera"''','''www-authenticate: basic realm="cam"'''
	,'''server: IP camera product:"Netwave IP camera http config"''','Server: IP Webcam','Ipcam city'
	,'''html:"PLANET IP"''','yawcam','netwave ip','linux upnp avtech','cam','''Basic realm="home cam"'''
	,'ipcam','IP camera','''basic realm="camera"''','ip speed dome httpd','Content-Length:·2574'
	,'IP Webcam Server 0.2','IP Webcam Server','hostname: cam','Server: ip webcam','Server: Android Webcam Server v0.1'
	,'network camera','ip video server -uc-httpd httpd','''Has_screenshot:"true" "Steven Wu"'''
	,'''server: alphapd "HTTP/1.0 200 OK"''','box ip camera httpd','Server ReeCam IP Camera Content-Length 2574'
	,'Netwave IP Camera Content-Length: 2574','Http has_screenshot:true','IP video+camera','mini dome ip camera httpd'
	,'Enterprise IP phone SIP','huawei -301 -302 -400 -401','''title:"IP CAMERA Viewer" Content-Length: 703'''
	,'Android Webcam Server -Authenticate','Android Webcam Server text/html 200','tablet cam','maygion','IPCamera_Logo'
	,'TeleEye','''server: "live" & "200 OK" org:T-Mobile''','''HTTP/1.1 200 OK Server: JAWS org:"SHATEL DSL Network"'''
	,'trendNet','''title:"Network Camera" 200 ok server: vb''',"""title:'+tm01+'""",'WVC80N','IP_camera'
	,'''title:"FRITZ!App Cam "''','jpegpull.htm','Content-length:3233','''title:"Checking Language..."'''
	,'Server: Camera Web Server/1.0','NetBotz Appliance 200','''title:"MJPG-streamer"''','server:=MJPG-Streamer/0.%'
	,'''IQinVision port:"80"''','has_screenshot: -port:3389 -port:3388 -port:5900 -port:5901 -port:6000'
	,'Content-Length: 695','itron','DVSS-HttpServer','FlexiDome','Server: iCanSystem','''title:"SecuritySpy"'''
	,'''Basic realm="home cam"''','''title:"WVC210 Wireless-G PTZ Internet Camera with Audio"'''
	,'''title:"Network Camera with Pan Tilt"''','''title:"Network Video Recorder"''','''gen5th''','threadx -401 -login'
	,'''title:"Vilar IPCamera Login"''','LNE3003 Wireless IP Camera','''title:"Web Viewer for Samsung DVR" Content-Length: 2524'''
	,'''title:"DCS-5220 IP camera"''','server: boa WWW-Authenticate: Camera','''title:"Network Cube Camera"'''
	,'dcs-lig-httpd','cam it','''"VVTK-HTTP-Server"''','Lilin','''html:"mjpeg"'''
	,'''product:"D-Link/Airlink IP webcam http config"'''
	,'''WWW-Authenticate: Basic realm="Megapixel IP Camera" Pragma: no-cache Cache-Control: no-cache Content-Type: text/html'''
	,'motionEye/','''title:"NETSurveillance WEB" Server: uc-httpd 1.0.0''','Content-Length: 1073','''DNVRS-Webs title:"index"'''
	,'Content-Length: 2861  Cache-Control: max-age=86400','atz executive','iqhttpd','port:8090 Server: HyNetOS/2.0'
	,'release-14 20090318','User logged in proceed ADH FTP SERVER','''"Network Card Manager"'''
	,'''"Here is what I know about myself:" && "HTTP Enabled: True" port:23''','hikvision Content-Length: 1341'
	,'''title:"TeleEye Java Viewer"''','Server: HyNetOS title:EverFocus','''P372 port:"23"''','PIPS AUTOPLATE'
	,'''title:"DCS-5300G" Server: D-Link Internet Camera''','''title:"NetCamXL"''','arecont'
	,'''"Powered by Nodinfo(SECRET!)"''','d-Link Internet Camera, 200 OK','''title:"Login cgicc form"'''
	,'''title:"Weather Wing"''','WEBCAM HTTP/1.1 200 OK  Server: MJPG-Streamer/0.2','go1984'
	,'Server: UBNT Streaming Server v1.2','abelcam','''title:"Network Camera VB-M600" 200 ok server: vb ETag:"1279180162"'''
	,'Server: i-Catcher Console','goahead-webs unauthorized port:81','ADH-web','Server: VB100','sq-webcam'
	,'''title:'+tm01+' Content-Length: 4132''','imagiatek ipcam','Server: VCS-VideoJet-Webserver','zmfhaltm'
	,'Hipcam RealServer/V1.0 has_screenshot:true','SAMSUNG iPolis','Server: mcdhttpd/','''product:"AXIS M1103 Network Camera"'''
	,'Server: thttpd PHP','''"webcam" "last-modified"''','''server: "IP-Webcam-Server" "HTTP/%.% 200 OK" Access-Control-Allow-Origin: "%"'''
	,'''WWW-Authenticate "SuperNova"''','netwave ip camera content-length: 372']

	CAM_TAGs_COM = ['webcam','cctv','dvr','netcam','easyN ipcam','Avigilon camera','webcamxp','webcamXP1'
	,'logitec CAM','IP Webcams Full control','netwave ipcams','IPCAMs with basic AUTH','IPCAMs with basic AUTH'
	,'Another netwave ipcams','another ipcam search','another ipcam search #1','85% are OPEN - PLANET CO'
	,'YAWCAM','another netwave ipcam search','AVTECH UPnP','just all cam','Home CAMs with BASIC AUTH','ipcam'
	,'another ipcam','basic auth camera','ip speed dome httpd','FOSCAM ip camera','UNSECURE CAMERAS'
	,'phone ipcams by pavel khlebovich','hostname CAM','tons of open ipcams','android ipcams','Network CAMERA'
	,'IP video server','Dlink IPCAMs    La PERFECTO!!!','Dlink CAM','BOX IPCAMs','FOSCAM WiFi CAMs','NETWAVE admin/blank'
	,'HTTP open CAMs    La PERFECTO!!','Video IPCAMs','mini dome IPCAMs','Enterprise IP phone SIP','Huawi webinterface for ip phones'
	,'TPLink IPCAMs','android cam server','android cam server 1','tablet cam','maygion','maygion1','TeleEye   -   def pass : 000000'
	,'TmobileCAM','JAWS CAM','trendNet CAMs','CANON VB CAM','CISCO CAM','WVC80N','IP_camera','FRITZ CAM'
	,'Open Blue Iris Servers','DVR Component download','Sort of WEBCAMs','CAMERA webservers','NetBotz Appliance'
	,'MJPG streamer','MJPG streamer 1','IQiN CAM','many open cams','AXIS network cam','itron','DVSS cam'
	,'FlexiDome','iCanSystem','Security Spy','Home CAMs','PTZ internet CAM','NET cam with pan/tilt/zoom'
	,'NUUO video recorder','Sony NET CAMs','Tuxedo connected controller','Vilar IPCAM','LNE3003 Wireless IP Camera'
	,'samsung DVR','DCS-5220 ipcam','galore ip cams','Network Cuba CAM','light httpd cams','simple cam dork'
	,'vivotek cams','lilin cam','mjpeg live stream cam','airlink cams','megapixel ipcam','motioneye cam'
	,'NetSurvilance WEBcam','Inspire DVR','Hikvivion NVR CAMs','RedLights CAM','RedLights CAM 1','HighDef CAMs'
	,'Loxone Intercome Video','canon VBM40 CAMs','Dedicated Micro Camera Systems','Network Card Managers'
	,'Polycoms with HTTP access','Hikvision CAM','TeleEye Java Viewer','EverFocus CAM Industrial'
	,'Automatic Number Plate Recognition Camera','PIPS AUTOPLATE','DEC-5300G','NetCamXL Video CAMs'
	,'Arecont vision','chianet nodinfo camera','Dlink Internet CAMs','VMax web viewer','Weather Wing'
	,'mostly open - check stream','go1984 server','UBNT CAMs','abelcam','Open CAMs without AUTH'
	,'i-Catcher Console','Vstar , escam and some others','ADH-web','VB100 CAMs','SQ CAMs','CISCO N-CAMs'
	,'imagiatek ipcams','Bosch webcam','Korean School CAMs','HipCam','samsung iPolis','maginon cam'
	,'AXIS M1103 Network Camera','GeoVision Inc - Ipcam/Video server','timhillone viewer','Vulnerable CAMs'
	,'speco ip cams','Heden brand cams']

	# +++ help for dynamic filters +++
	def dhelp(self):
		print (Fore.YELLOW+'''There are 8 Dynamic Filter. CITY , COUNTRY , PORT , OS , GEO , IPNETM , HOSTNAME , DATEAB.
CITY: With this filter you can restrict your search to an specific city.
COUNTRY: With this filter you can restrict your search to an specific country.
PORT: With this filter you can restrict your search to an specific ports and services. REMEMBER to seprate ports with ',' Exmp: 21,22,23
OS: With this filter you can restrict your search to an specific Operation System.
GEO: With this filter you can restrict your search to an specific Geographic Location. REMEMBER to seprate with ',' Exmp: 37.4,24.4
IPNETM: With this filter you can restrict your search to an specific Ip range or subnet. Exmp: 10.9.0.0/8
HOSTNAME: With this filter you can restrict your search to an specific Hostname/Domain. Exmp: .nist.gov
DATEAB: With this filter you can restrict your search to after/before an specific date. Exmp: before:1/01/2014
NOTE: You can use multiple Dynamic filters and for that, seprate filters with ',' Exmp: city,country,port'''+Style.RESET_ALL)