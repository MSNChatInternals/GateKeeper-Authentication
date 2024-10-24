"""

passport.py

Copyright (C) 2002  zmic  (zmiczmic@hotmail.com)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

"""


import urllib,urllib,os,re,sys,random,time,httplib
import socket,select,thread,Queue,types

#os.environ["http_proxy"]="http://proxy.pandora.be:8080"
#os.environ["http_proxy"]="http://127.0.0.1:5555"


#  search list of strings on rexep
def search_list (L, regexp, all = 0):
  if type (L) is types.StringType:
    L = [L]
  results = []
  for x in L:
    mo = regexp.search (x)
    if mo:
      G = mo.groups ()
      if len (G) == 1:
        G = G[0]
      if not all:
        return G
      results.append (G)
  return results 



re_cookie_auth = re.compile (r'Set-Cookie: MSPAuth=(.*?);')
re_cookie_prof = re.compile (r'Set-Cookie: MSPProf=(.*?);')

re_t = re.compile (r'&t=(.*?)&')
re_p = re.compile (r'&p=(.*?)&')
re_url = re.compile (r'URL=(.*)"')
re_set_cookie = re.compile (r'Set-Cookie: (.*?)\r\n')
re_location = re.compile (r'Location: (.*)\r\n')
re_src = re.compile (r"src='(chatroom_ui.*?)'")
re_MSNREGCOOKIE = re.compile ('NAME="MSNREGCookie".*?VALUE="(.*?)"')



def find_cookies (headers, cookies):

  for s in search_list (headers, re_set_cookie, 1):
    for x in s.split (';'):
      m = x.split ('=')
      if len (m) == 2:
        key = m[0].strip ()
        if key in ['MSPAuth', 'MSPProf', 'ChatURL', 'MSNChatNN']:
  	  cookies[m[0].strip ()]= m[1]

def handle_302 (url, cookies, depth = ''):
   #print "====================================================================="
   print depth + url[0:50] + '...'
   #print cookies
   opener=urllib.URLopener()
   opener.addheader("User-Agent", r"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)")
   cookie = ''
   for x,y in cookies.items ():
     cookie += '%s=%s; ' %(x,y)
   opener.addheader('Cookie',cookie[:-1])
   try:
     data = opener.open(url).read()
     MSNREGCOOKIE = search_list (data, re_MSNREGCOOKIE)
     if MSNREGCOOKIE:
       # well done, thou faithful servant
       print "Found MSNREGCOOKIE!"
       return MSNREGCOOKIE
     url = 'http://chat.msn.be/' + search_list (data, re_src)
     return handle_302 (url, cookies, depth + '  ')
   except IOError, arg:
     #print arg
     #print arg[3].headers
     new_url = search_list (arg[3].headers, re_location)
     url = new_url
     find_cookies (arg[3].headers, cookies)
     return handle_302 (url, cookies, depth + '  ')

#
#
#  httplib and urllib seem to be buggy on SSL-connections to IIS   :/
#  If you manage to make this work with standard Python modules, please let me know.
#  M2Crypto at http://www.post1.com/home/ngps/m2/
#
from M2Crypto import httpslib


def do_https (host, post, body, try_to_find_MSNREGCOOKIE):
   print "SSL connection to " + post[:40] + '...'
   host= host + ":443"
   hs = httpslib.HTTPS()
   #hs.set_debuglevel(4)
   hs.connect(host)
   hs.putrequest('POST',post)
   hs.putheader('Content-Length', str(len(body)))
   hs.putheader('Accept-Encoding', 'identity')
   hs.putheader('Accept',r'image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/msword, */*')
   hs.putheader('Referer',r'http://login.passport.com')
   hs.putheader('Accept-Language',r'nl-be')
   hs.putheader('Content-Type',r'application/x-www-form-urlencoded')
   hs.putheader('Proxy-Connection',r'Keep-Alive')
   hs.putheader('User-Agent',r'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)')
   hs.putheader('Host',r'loginnet.passport.com')
   hs.putheader('Pragma',r'no-cache')
   hs.endheaders()
   hs.send(body)
   
   status, reason, header= hs.getreply()
   data=hs.getfile().read()
   
   # avoid being redirected to the download page of the chat client
   cookies = {'hasOCX':'2%2C03%2C0204%2C0801'}

   find_cookies (hs.headers.headers, cookies)
   MSPAuth = cookies['MSPAuth']
   MSPProf = cookies['MSPProf']
   
   t = search_list (data, re_t)
   p = search_list (data, re_p)
   url = search_list (data, re_url)
   
   if not MSPAuth and MSPProf:
     raise "Could not find auth/profile cookie in HTTPS response."
   print "Logged in succesfully!"

   #
   #  at this point, we have the auth and profile cookie.
   #
   if try_to_find_MSNREGCOOKIE:
     print "trying to retrieve MSNREGCOOKIE (may timeout, crash, go in infinite 302 loop, ...)"
     MSNREGCOOKIE = handle_302 (url, cookies)
   else:
     MSNREGCOOKIE = None


   return t, p, MSPAuth, MSPProf, MSNREGCOOKIE



def passport_login (login, domain, password, try_to_find_MSNREGCOOKIE):

  # 
  #  This code is likely to break whenever Microsoft change the html of their chat.msn site,
  #  but that's just the way it is.
  #
  
  opener=urllib.FancyURLopener()
  opener.addheader("User-Agent", r"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.0.3705)")
  lines = opener.open(r"http://chat.msn.be").readlines ()
  #re_some_chatroom = re.compile (r'<a href="(http://chat.msn.be/chatroom.msnw\?rhx=.*?;rhx1=.*?)"') 
  re_some_chatroom = re.compile (r'<a href="(http://chat.msn.be/chatroom.msnw\?rm=.*?)"') 
  chatroom_url = search_list (lines, re_some_chatroom)
  if chatroom_url:
    print "Opening url to some chatroom : ",chatroom_url[:40]+'...'
    lines = opener.open(chatroom_url).read ()
  
    #
    # search for the action that does the login POST
    #
    re_login = re.compile (r'name="hotmail_com" action="(https://(.*?)/.*?)"')
    mo = re_login.search (lines)
    if mo:
      data = {
        'login':login,
        'domain':domain,
        'passwd':password,
        'sec':'0',
        'mspp_shared':'0'
      }
      data = urllib.urlencode(data)
      t, p, MSPAuth, MSPProf, MSNREGCOOKIE = do_https (mo.group(2), mo.group (1), data, try_to_find_MSNREGCOOKIE)
      return t, p, MSNREGCOOKIE


if __name__ == '__main__':
  MSPAuth, MSPProf, MSNREGCOOKIE = passport_login ('Jim', 'hotmail.com', jims_password, 1)
  print "MSPAuth = ",MSPAuth
  print "MSPProf = ",MSPProf
  print "MSNREGCOOKIE = ",MSNREGCOOKIE


  







































