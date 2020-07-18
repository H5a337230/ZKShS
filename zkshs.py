# -*- coding: utf-8 -*-
import sys
#reload(sys)  
#sys.setdefaultencoding('utf-8')
import requests.packages.urllib3
from json import dumps, loads
import requests
import os
import optparse
import re
from colorama import Fore, Back, Style
import string
import itertools
from optparse import OptionGroup
import smtplib
from kr import kre
from ficls import fcls

Tversion = 'VERSION 1.0.3'
kc = kre()
fc = fcls()
#requests.packages.urllib3.disable_warnings()

#################################

def listFunc(filtype):
	if (filtype == 'scada'):
		for fnum in range(len(fc.SCADA_TAGs)):
			print (fc.SCADA_TAGs[fnum])
	elif (filtype == 'http'):
		for fnum in range(len(fc.HTTP_TAGs)):
			print (fc.HTTP_TAGs[fnum])
	elif (filtype == 'server'):
		for fnum in range(len(fc.SERVER_TAGs)):
			print (fc.SERVER_TAGs[fnum])
	elif (filtype == 'ftp'):
		for fnum in range(len(fc.FTP_TAGs)):
			print (fc.FTP_TAGs[fnum])
	elif (filtype == 'modem/router'):
		for fnum in range(len(fc.ROUTER_TAGs)):
			print (fc.ROUTER_TAGs[fnum])
	elif (filtype == 'database'):
		for fnum in range(len(fc.DATABASE_TAGs)):
			print (fc.DATABASE_TAGs[fnum])
	elif (filtype == 'cam'):
		for fnum in range(len(fc.CAM_TAGs)):
			print (fc.CAM_TAGs[fnum])
	elif (filtype == 'other'):
		for fnum in range(len(fc.OTHER_TAGs)):
			print (fc.OTHER_TAGs[fnum])
	elif (filtype == 'dynamic'):
		fc.dhelp()
	else:
		print (Fore.RED+'[!] There is something WRONG with provided value as filter type.'+Style.RESET_ALL)

#################################

def manFunc(cfil):
	for fnum in range(len(fc.OTHER_TAGs)):
		if (cfil == fc.OTHER_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.OTHER_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.SCADA_TAGs)):
		if (cfil == fc.SCADA_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.SCADA_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.HTTP_TAGs)):
		if (cfil == fc.HTTP_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.HTTP_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.SERVER_TAGs)):
		if (cfil == fc.SERVER_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.SERVER_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.FTP_TAGs)):
		if (cfil == fc.FTP_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.FTP_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.ROUTER_TAGs)):
		if (cfil == fc.ROUTER_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.ROUTER_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.DATABASE_TAGs)):
		if (cfil == fc.DATABASE_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.DATABASE_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	for fnum in range(len(fc.CAM_TAGs)):
		if (cfil == fc.CAM_TAGs[fnum].lower()):
			print (Fore.YELLOW+fc.CAM_TAGs_COM[fnum]+'\n'+Style.RESET_ALL)
			sys.exit()
	print (Fore.RED+'[!] Wrong filter name.'+Style.RESET_ALL)

#################################

def keyF(ftype,key):
	if (ftype == 'add'):
		if (key):
			kc.kadd(key)
		else:
			print (Fore.RED+'[!] For this API-KEY Function, You should provide API-KEY as an input argument'+Style.RESET_ALL)
	elif (ftype == 'del'):
		if (key):
			kc.kdel(key)
		else:
			print (Fore.RED+'[!] For this API-KEY Function, You should provide API-KEY as an input argument'+Style.RESET_ALL)
	elif (ftype == 'help'):
		kc.help_menu()
	elif (ftype == 'list'):
		kc.klist()
	else:
		print (Fore.RED+'[!] There is something WRONG with the data that you entered'+Style.RESET_ALL)

#################################

def shprereq(sfilter,dfilter,cq):   # FinalQ = Final Query = sfilter+cq+dfilter
	if (not sfilter):
		sfilter = ''
	elif (sfilter):
		for fnum in range(len(fc.OTHER_TAGs)):
			if (sfilter == fc.OTHER_TAGs[fnum]):
				sfilter = fc.OTHER_TAGs_VAL[fnum]
		for fnum in range(len(fc.SCADA_TAGs)):
			if (sfilter == fc.SCADA_TAGs[fnum]):
				sfilter = fc.SCADA_TAGs_VAL[fnum]
		for fnum in range(len(fc.HTTP_TAGs)):
			if (sfilter == fc.HTTP_TAGs[fnum]):
				sfilter = fc.HTTP_TAGs_VAL[fnum]
		for fnum in range(len(fc.SERVER_TAGs)):
			if (sfilter == fc.SERVER_TAGs[fnum]):
				sfilter = fc.SERVER_TAGs_VAL[fnum]
		for fnum in range(len(fc.FTP_TAGs)):
			if (sfilter == fc.FTP_TAGs[fnum]):
				sfilter = fc.FTP_TAGs_VAL[fnum]
		for fnum in range(len(fc.ROUTER_TAGs)):
			if (sfilter == fc.ROUTER_TAGs[fnum]):
				sfilter = fc.ROUTER_TAGs_VAL[fnum]
		for fnum in range(len(fc.DATABASE_TAGs)):
			if (sfilter == fc.DATABASE_TAGs[fnum]):
				sfilter = fc.DATABASE_TAGs_VAL[fnum]
		for fnum in range(len(fc.CAM_TAGs)):
			if (sfilter == fc.CAM_TAGs[fnum]):
				sfilter = fc.CAM_TAGs_VAL[fnum]
	if (not cq):
		cq = ''
	elif (cq):
		if (sfilter != ''):
			cq = ' '+cq
		else:
			cq = cq
	if (dfilter):
		if (sfilter != '' or cq != ''):
			dfilter = ' '+dfilterdefine(dfilter)
		else:
			dfilter = dfilterdefine(dfilter)
	elif (not dfilter):
		dfilter = ''
	FinalQ = sfilter+cq+dfilter
	if (FinalQ == ''):
		print (Fore.RED+'[!] Your entered data as the filter(s) was incorrect. Check and try again.\n\n'+Style.RESET_ALL)
		sys.exit()
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			#shmainReq(FinalQ,kc.tkeys[0],options.limitN,options.pageN)
			result = shmainReq(FinalQ,kc.tkeys[0],options.limitN,options.pageN)
			for Mcount in range(len(result['matches'])):
				print (Fore.GREEN+str(result['matches'][Mcount]['ip_str'])+'   '+Fore.YELLOW+str(result['matches'][Mcount]['port'])+'   '+Fore.MAGENTA+str(result['matches'][Mcount]['isp'])+'   '+Fore.BLUE+str(result['matches'][Mcount]['location']['country_name'])+'   '+Fore.WHITE+repr(result['matches'][Mcount]['data'])+Style.RESET_ALL)
		else:
			apikey = kc.chokey()
			#shmainReq(FinalQ,apikey,options.limitN,options.pageN)
			result = shmainReq(FinalQ,apikey,options.limitN,options.pageN)
			for Mcount in range(len(result['matches'])):
				print (Fore.GREEN+str(result['matches'][Mcount]['ip_str'])+'   '+Fore.YELLOW+str(result['matches'][Mcount]['port'])+'   '+Fore.MAGENTA+str(result['matches'][Mcount]['isp'])+'   '+Fore.BLUE+str(result['matches'][Mcount]['location']['country_name'])+'   '+Fore.WHITE+repr(result['matches'][Mcount]['data'])+Style.RESET_ALL)
		sys.exit()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()

#################################

def dfilterdefine(dfilter):
	wholeDF = ''
	df = ['city','country','port','os','geo','ipnetm','hostname','dateab']
	dfarray = []
	print (Fore.GREEN+'[*] You choosed to use Dynamic Filter(s) ...')
	for fttype in dfilter.split(','):
		dfarray.append(fttype)
	dfarrayND = list(set(dfarray))
	for kount in range(len(dfarrayND)):
		if (dfarrayND[kount].lower() == df[0]):
			try:
				fc.city = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.city = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			wholeDF = 'city:'+fc.city
		elif (dfarrayND[kount].lower() == df[1]):
			try:
				fc.country = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.country = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city):
				wholeDF += ' country:'+fc.country
			else:
				wholeDF += 'country:'+fc.country
		elif (dfarrayND[kount].lower() == df[2]):
			try:
				fc.port = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.port = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country):
				wholeDF += ' port:'+fc.port
			else:
				wholeDF += 'port:'+fc.port
		elif (dfarrayND[kount].lower() == df[3]):
			try:
				fc.os = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.os = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country or fc.port):
				wholeDF += ' os:'+fc.os
			else:
				wholeDF += 'os:'+fc.os
		elif (dfarrayND[kount].lower() == df[4]):
			try:
				fc.geo = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.geo = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country or fc.port or fc.os):
				wholeDF += ' geo:'+fc.geo
			else:
				wholeDF += 'geo:'+fc.geo
		elif (dfarrayND[kount].lower() == df[5]):
			try:
				fc.ipnetm = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.ipnetm = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country or fc.port or fc.os or fc.geo):
				wholeDF += ' '+fc.ipnetm
			else:
				wholeDF += ''+fc.ipnetm
		elif (dfarrayND[kount].lower() == df[6]):
			try:
				fc.hostname = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.hostname = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country or fc.port or fc.os or fc.geo or fc.ipnetm):
				wholeDF += ' hostname:'+fc.hostname
			else:
				wholeDF += 'hostname:'+fc.hostname
		elif (dfarrayND[kount].lower() == df[7]):
			try:
				fc.dateab = str(raw_input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			except:
				fc.dateab = str(input(Fore.YELLOW+'[?] Please Enter value for '+dfarrayND[kount].lower()+': '))
			if (fc.city or fc.country or fc.port or fc.os or fc.geo or fc.ipnetm or fc.hostname):
				wholeDF += ' '+fc.dateab
			else:
				wholeDF += ''+fc.dateab
	if (wholeDF == ''):
		print (Fore.RED+'[!] Your Entered data as Dynamic Filter(s) was WRONG. Continue with other filter(s) ...'+Style.RESET_ALL)
	return wholeDF


#################################

def shmainReq(Squery,Skey,limitQ,pageQ):
	if (limitQ != None):
		if (pageQ != None):
			limitpage = '&limit='+limitQ+'&page='+pageQ
		else:
			limitpage = '&limit='+limitQ
	else:
		if (pageQ != None):
			limitpage = '&page='+pageQ
		else:
			limitpage = ''
	try:
		responseDATA = requests.get('https://api.shodan.io/shodan/host/search?query='+Squery+'&key='+Skey+limitpage)
		if (responseDATA.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(responseDATA.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		responseDATA = loads(responseDATA.text)   # responseDATA.text OR responseDATA.content
		if (responseDATA.get('error', None)):
			print (Fore.RED+'[!] '+str(responseDATA['error'])+Style.RESET_ALL)
		else:
			return responseDATA
			#for Mcount in range(len(responseDATA['matches'])):
			#	print (Fore.GREEN+str(responseDATA['matches'][Mcount]['ip_str'])+'   '+Fore.YELLOW+str(responseDATA['matches'][Mcount]['port'])+'   '+Fore.MAGENTA+str(responseDATA['matches'][Mcount]['isp'])+'   '+Fore.BLUE+str(responseDATA['matches'][Mcount]['location']['country_name'])+'   '+Fore.WHITE+repr(responseDATA['matches'][Mcount]['data'])+Style.RESET_ALL)
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)
		sys.exit()


#################################


def Hchecker(tip):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.get('https://api.shodan.io/labs/honeyscore/'+tip+'?key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			print (Fore.GREEN+str(response)+Style.RESET_ALL)
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def dnscheck(hname):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.get('https://api.shodan.io/dns/resolve?hostnames='+hname+'&key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			for item in hname.split(','):
				print (Fore.GREEN+item+': '+str(response[item])+Style.RESET_ALL)
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def Rdnscheck(rev_ip):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.get('https://api.shodan.io/dns/reverse?ips='+rev_ip+'&key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			for item in rev_ip.split(','):
				if (not response[item]):
					print (Fore.YELLOW+'None for '+item+Style.RESET_ALL)
				else:
					print (Fore.GREEN+item+': '+str(response[item][0])+Style.RESET_ALL)
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def newalert(name,target,expire_time):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	if (not expire_time):
		json_data = {'name': name,'filters': {'ip': target}, 'key': api_key}
	else:
		json_data = {'name': name,'filters': {'ip': target}, 'expires': expire_time, 'key': api_key}
	try:
		response = requests.post('https://api.shodan.io/shodan/alert', data=json_data)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			print (Fore.GREEN+'alert created and '+Style.RESET_ALL)
		#print (loads(response.text)['error'])
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def alertinfo(alert_id):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.get('https://api.shodan.io/shodan/alert/'+alert_id+'/info?key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			print (Fore.GREEN+'alert name: '+str(response['name'])+Fore.MAGENTA+'    created date: '+str(response['created'])+Fore.BLUE+'    ip: '+str(response['filters']['ip'][0])+Fore.YELLOW+'    id: '+str(response['id']))
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def alertdel(alert_id):
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.delete('https://api.shodan.io/shodan/alert/'+alert_id+'?key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			print (Fore.GREEN+'Your specified alert deleted'+Style.RESET_ALL)
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def alertlist():
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			api_key = kc.tkeys[0]
		else:
			api_key = kc.chokey()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
	try:
		response = requests.get('https://api.shodan.io/shodan/alert/info?key='+api_key)
		if (response.status_code == 401):
			try:
				print (Fore.RED+'[!] '+str(response.json()['error'])+Style.RESET_ALL)
			except Exception as e:
				print (Fore.RED+'[!] Invalid API key'+Style.RESET_ALL)
			sys.exit()
		else:
			response = loads(response.text)
			for alertcount in range(len(response)):
				print (Fore.GREEN+'alert name: '+str(response[alertcount]['name'])+Fore.MAGENTA+'    created date: '+str(response[alertcount]['created'])+Fore.BLUE+'    ip: '+str(response[alertcount]['filters']['ip'][0])+Fore.YELLOW+'    id: '+str(response[alertcount]['id']))
	except Exception as e:
		print (Fore.RED+'[!] Failed, Try Again.\t'+str(e)+Style.RESET_ALL)


#################################


def POpenRelay(portNum,Msender,Mreceiver,Mdata):
	Mcontent = '''From: <%s>
	TO: <%s>
	Content-Type: text/plain; charset=iso-8859-1
	%s''' %(Msender,Mreceiver,Mdata)
	smtpquery = 'smtp port:%s' %portNum
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			smtpRES = shmainReq(smtpquery,kc.tkeys[0],options.limitN,options.pageN)
		else:
			apikey = kc.chokey()
			smtpRES = shmainReq(smtpquery,apikey,options.limitN,options.pageN)
		for Mcount in range(len(smtpRES['matches'])):
			if (('smtps' in repr(smtpRES['matches'][Mcount]['data']).lower()) or ('esmtp' in repr(smtpRES['matches'][Mcount]['data']).lower())):
				smtpTRG = smtplib.SMTP_SSL(port=portNum,timeout = 15)
				tlsu = True
			else:
				smtpTRG = smtplib.SMTP(port=portNum,timeout = 15)
				tlsu = False
			try:
				smtpTRG.connect(str(smtpRES['matches'][Mcount]['ip_str']))
				if (tlsu):
					smtpTRG.starttls()
				smtpTRG.ehlo('google.com')
				smtpTRG.sendmail(Msender,Mreceiver,Mcontent)
				smtpTRG.quit()
				print (Fore.RED+'[!]VULNERABLE[!]'+Style.RESET_ALL)
			except Exception as e:
				if (('500' in str(e)) or ('501' in str(e))):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tSyntax Error - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('503' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tBad sequence of commands, or requires authentication - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('504' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tCommand parameter is not implemented - Vulnerable'+Style.RESET_ALL)
				elif (('510' in str(e)) or ('511' in str(e))):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tBad email address - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('512' in str(e)):
					print(Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tHost server for the recipient`s domain name cannot be found in DNS - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('513' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tAddress type is incorrect - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('530' in str(e)):
					print (Fore.GREEN+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tAuthentication problem - SAFE'+Style.RESET_ALL)
				elif ('541' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tThe recipient address rejected your message - Vulnerable'+Style.RESET_ALL)
				elif ('550' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tNon-existent email address - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('551' in str(e)):
					print (Fore.GREEN+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tUser not local or invalid address - relay denied - SAFE'+Style.RESET_ALL)
				elif ('552' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tExceeded storage allocation - Vulnerable'+Style.RESET_ALL)
				elif ('553' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tMailbox name invalid - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('554' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+'\tTransaction has failed - Maybe Vulnerable'+Style.RESET_ALL)
				else:
					print(Fore.MAGENTA+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(portNum)+' - Protocol Problem(try again): \t'+str(e)+Style.RESET_ALL)
		sys.exit()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()


#################################


def noPOpenRelay(Msender,Mreceiver,Mdata):
	Mcontent = '''From: <%s>
	TO: <%s>
	Content-Type: text/plain; charset=iso-8859-1
	%s''' %(Msender,Mreceiver,Mdata)
	#smtpquery = 'smtp port:%s' %portNum
	if (kc.ckfile()):
		if (len(kc.tkeys) == 1):
			smtpRES = shmainReq('smtp',kc.tkeys[0],options.limitN,options.pageN)
		else:
			apikey = kc.chokey()
			smtpRES = shmainReq('smtp',apikey,options.limitN,options.pageN)
		for Mcount in range(len(smtpRES['matches'])):
			if (('smtps' in repr(smtpRES['matches'][Mcount]['data']).lower()) or ('esmtp' in repr(smtpRES['matches'][Mcount]['data']).lower())):
				smtpTRG = smtplib.SMTP_SSL(port=smtpRES['matches'][Mcount]['port'],timeout = 15)
				tlsu = True
			else:
				smtpTRG = smtplib.SMTP(port=smtpRES['matches'][Mcount]['port'],timeout = 15)
				tlsu = False
			try:
				smtpTRG.connect(str(smtpRES['matches'][Mcount]['ip_str']))
				if (tlsu):
					smtpTRG.starttls()
				smtpTRG.ehlo('google.com')
				smtpTRG.sendmail(Msender,Mreceiver,Mcontent)
				smtpTRG.quit()
				print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\t[!]VULNERABLE[!]'+Style.RESET_ALL)
			except Exception as e:
				if (('500' in str(e)) or ('501' in str(e))):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tSyntax Error - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('503' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tBad sequence of commands, or requires authentication - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('504' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tCommand parameter is not implemented - Vulnerable'+Style.RESET_ALL)
				elif (('510' in str(e)) or ('511' in str(e))):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tBad email address - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('512' in str(e)):
					print(Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tHost server for the recipient`s domain name cannot be found in DNS - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('513' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tAddress type is incorrect - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('530' in str(e)):
					print (Fore.GREEN+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tAuthentication problem - SAFE'+Style.RESET_ALL)
				elif ('541' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tThe recipient address rejected your message - Vulnerable'+Style.RESET_ALL)
				elif ('550' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tNon-existent email address - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('551' in str(e)):
					print (Fore.GREEN+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tUser not local or invalid address - relay denied - SAFE'+Style.RESET_ALL)
				elif ('552' in str(e)):
					print (Fore.RED+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tExceeded storage allocation - Vulnerable'+Style.RESET_ALL)
				elif ('553' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tMailbox name invalid - Maybe Vulnerable'+Style.RESET_ALL)
				elif ('554' in str(e)):
					print (Fore.YELLOW+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+'\tTransaction has failed - Maybe Vulnerable'+Style.RESET_ALL)
				else:
					print(Fore.MAGENTA+str(smtpRES['matches'][Mcount]['ip_str'])+':'+str(smtpRES['matches'][Mcount]['port'])+' - Protocol Problem(try again): \t'+str(e)+Style.RESET_ALL)
		sys.exit()
	else:
		print (Fore.RED+'[!] There is something WRONG with Key file(Maybe its EMPTY or Key file NOT EXISTS)'+Style.RESET_ALL)
		sys.exit()


#################################


if __name__=='__main__':
	print (Fore.CYAN + '''
				 _____        __ _     __    
				/ _  /  /\ /\/ _\ |__ / _\   
				\// /  / //_/\ \| '_ \\ \    
				 / //\/ __ \ _\ \ | | |\ \   
				/____/\/  \/ \__/_| |_\__/   
                                  
				                        coded by Z3r0''')
	print (Fore.RED + '''\t\t\t\t\t\t\tCodename - ZEROARY\n\n''')
	print (Fore.CYAN + '''
		This is ' ZKShS '. With this you can search shodan without any knowledge about
		its queries. Most Queries and Filters have been implemented inside that and
		you can choose which one you want to use.
		It contains more than 400 filters to help you search shodan better.
		If you want to list implemented queries, use ' --listing <filter_type> ' command.
		This prints all implemented filters in its kind.
		If you want to see info about each filter, use ' --man <filter_name> ' command.
		There is possibilty to execute custom queries and if you want to search shodan
		with your own query, you can use ' --cquery <QUERY> ' command.
		Now, You can use DNS/Reverse_DNS/honeypot checking services and
		using alert service to monitor a network range.
		For Open Relay Bulk Scanner, you can provide page & limit filters(IF YOU WISH),if
		you dont provide these filters, results will be just for first page.
		ALERT FUNCTIONS ARE EXPERIMENTAL.
		<< I extremly suggest to Read description for query that you want to use. >>
		'''+Style.RESET_ALL)
	parser = optparse.OptionParser( version = Tversion )
	group = OptionGroup(parser,'Filter Options')
	group.add_option('--listing', action='store' , dest='listf' , help='will list related filters [ Two kind of filters are available static: (scada, http, server, ftp, modem/router, database, cam, other) and dynamic. For static filters you should specify type, like scada or any of them but for dynamic filters just use dynamic ]' , type='string')
	group.add_option('--man', action='store', dest='fname' , help='will print description for selected static filter')
	group.add_option('--sfil', action='store', dest='stfilter' , help='static filter')
	group.add_option('--dfil', action='store', dest='dyfilter' , help='dynamic filter')
	group.add_option('--cquery', action='store', dest='cqu' , help='will use your custom query | can combine with choosed filter')
	group.add_option('--pnum', action='store', dest='pageN' , help='will return your requested page of the searched data')
	group.add_option('--qlimit', action='store', dest='limitN' , help='will limit the returned data')
	parser.add_option_group(group)
	group = OptionGroup(parser,'Api-Key Options')
	group.add_option('--kf', action='store', dest='keyfunk' , help='Add or Delete Key(s), print API-KEY help menu and also list all KEYs [default is list KEYs - add|del|help|list]' , type='string')
	group.add_option('--api', action='store', dest='api_key' , help='API-KEY')
	parser.add_option_group(group)
	group = OptionGroup(parser,'HoneyPot Checker')
	group.add_option('--honeycheck', action='store_true', default=False, dest='honeycheck', help='Calculates honeypot probability score ranging from 0 (not a honeypot) to 1.0 (is a honeypot) of target ip')
	group.add_option('--hoip', action='store', dest='honey_ip', help='IP address of target to check if it is honeypot or not')
	parser.add_option_group(group)
	group = OptionGroup(parser,'DNS/Reverse_DNS')
	group.add_option('--dhost', action='store', dest='dns_host', help='hostname(s) - separated with comma')
	group.add_option('--rdnsip', action='store', dest='rdns_IP', help='IP(s) for reverse DNS - separated with comma')
	parser.add_option_group(group)
	group = OptionGroup(parser,'Network Alert')
	group.add_option('--calert', action='store_true', default=False, dest='create_alert', help='create a network alert for a defined IP/netblock which can be used to subscribe to changes/ events that are discovered within that range.')
	group.add_option('--alertname', action='store', dest='alert_name', help='defind name for created alert')
	group.add_option('--alerttarget', action='store', dest='alert_target', help='target IP/netblock for alert')
	group.add_option('--alertexp', action='store', dest='alert_expire', help='Number of seconds that the alert should be active(OPTIONAL)')
	group.add_option('--alertid', action='store', dest='alert_id', help='alert id to check its info')
	group.add_option('--alertin', action='store_true', default=False, dest='alert_info', help='alert info command')
	group.add_option('--dalert', action='store_true', default=False, dest='delete_alert', help='deleting alert with specified alert id')
	group.add_option('--lalerts', action='store_true',default=False, dest='list_alerts', help='List whole activated alerts of your account')
	parser.add_option_group(group)
	group = OptionGroup(parser,'SMTP OpenRelay bulk Scanner')
	group.add_option('--orscan', action='store_true', default=False, dest='orelay_scan', help='SMTP OpenRelay Bulk Scanner')
	group.add_option('--orport', action='store', dest='orelay_port', help='SMTP OpenRelay Bulk Scanner`s port definition')
	group.add_option('--mto', action='store', dest='mailto', help='Sender Address')
	group.add_option('--mfr', action='store', dest='mailfrom', help='Receiver Address')
	group.add_option('--mdt', action='store', dest='maildata', help='Receiver Address')
	parser.add_option_group(group)
	options,_ = parser.parse_args()
	###
	if (options.listf and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.pageN and options.limitN and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.fname and options.honey_ip and options.rdns_IP and options.stfilter and options.dyfilter and options.cqu and options.keyfunk and options.api_key and options.dns_host and options.honeycheck)):
		listFunc(options.listf.lower())
	###
	elif (options.fname and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.pageN and options.limitN and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.listf and options.honey_ip and options.rdns_IP and options.stfilter and options.dyfilter and options.cqu and options.keyfunk and options.api_key and options.dns_host and options.honeycheck)):
		manFunc(options.fname.lower())
	###
	elif (options.stfilter or options.dyfilter or options.cqu and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.keyfunk and options.honey_ip and options.rdns_IP and options.api_key and options.fname and options.listf and options.dns_host and options.honeycheck)):
		shprereq(options.stfilter,options.dyfilter,options.cqu)
	###
	elif (options.keyfunk and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.pageN and options.limitN and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.fname and options.honey_ip and options.stfilter and options.dyfilter and options.rdns_IP and options.cqu and options.listf and options.dns_host and options.honeycheck)):
		keyF(options.keyfunk.lower(),options.api_key)
	###
	elif (options.honeycheck and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.pageN and options.limitN and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.keyfunk and options.fname and options.stfilter and options.rdns_IP and options.dyfilter and options.dns_host and options.cqu and options.listf)):
		if (options.honey_ip):
			Hchecker(options.honey_ip)
		else:
			print (Fore.RED+'[!] You did not Enter The Target IP Address'+Style.RESET_ALL)
	###
	elif (options.dns_host and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.rdns_IP and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		dnscheck(options.dns_host)
	###
	elif (options.rdns_IP and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.dns_host and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		Rdnscheck(options.rdns_IP)
	###
	elif (options.create_alert and options.alert_name and options.alert_target and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.alert_id and options.list_alerts and options.delete_alert and options.alert_info and options.rdns_IP and options.dns_host and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		newalert(options.alert_name,options.alert_target,options.alert_expire)
	###
	elif (options.alert_id and options.alert_info and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.create_alert and options.alert_name and options.alert_target and options.list_alerts and options.delete_alert and options.rdns_IP and options.dns_host and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		alertinfo(options.alert_id)
	###
	elif (options.alert_id and options.delete_alert and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.create_alert and options.alert_name and options.alert_target and options.list_alerts and options.alert_info and options.rdns_IP and options.dns_host and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		alertdel(options.alert_id)
	###
	elif (options.list_alerts and not (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and options.orelay_port and options.create_alert and options.alert_name and options.alert_target and options.alert_id and options.delete_alert and options.alert_info and options.rdns_IP and options.dns_host and options.honey_ip and options.keyfunk and options.honeycheck and options.fname and options.stfilter and options.dyfilter and options.cqu and options.listf)):
		alertlist()
	###
	elif (options.maildata and options.mailfrom and options.mailto and options.orelay_scan and not (options.listf and options.alert_id and options.alert_name and options.alert_target and options.alert_expire and options.create_alert and options.list_alerts and options.delete_alert and options.alert_info and options.fname and options.honey_ip and options.rdns_IP and options.stfilter and options.dyfilter and options.cqu and options.keyfunk and options.api_key and options.dns_host and options.honeycheck)):
		if (options.orelay_port):
			POpenRelay(options.orelay_port,options.mailfrom,options.mailto,options.maildata)
		else:
			print (Fore.YELLOW+"*** You didnt specified port, it will check smtp servers on all ports ***"+Style.RESET_ALL)
			noPOpenRelay(options.mailfrom,options.mailto,options.maildata)
	###
	else:
		parser.print_help()
		sys.exit()
	print(Style.RESET_ALL)
