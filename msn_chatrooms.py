"""

msn_chatrooms.py

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



import socket, select, re, md5, urllib
import passport



#====================================================================================================

def challenge_1 (challenge):
  # 
  #  Gabriel the archangel appeared to me last night, and revealed these strings
  #
  #  Be careful if you're not familiar with Python. An 'r' in front of a string means that 
  #  the string should be taken literally (i.e. without interpreting \ as the escape character)
  #
  c1 = "edp{}e|wxrdse}}u666666666666666666666666666666666666666666666666" + challenge
  a1 = md5.new(c1).digest ()
  c2 = "\x0f\x0e\x1a\x11\x17\x0f\x16\x1d\x12\x18\x0e\x19\x0f\x17\x17\x1f" + r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\" + a1
  a2 = md5.new(c2).digest ()
  return a2


#====================================================================================================

numbered_commands = {
  # :TK2CHATWBA09 613 nick :207.68.167.162 6667
  613 : re.compile (r'(?P<nick>\S+) :(?P<server>\S+) (?P<port>\S+)')
}

other_commands = [
  re.compile (r':(?P<nick>.*)!(?P<id>.*@GateKeeperPassport) (?P<command>PRIVMSG) (?P<to>.+) :(?P<message>.+)\r\n'),
  re.compile (r':(?P<nick>.*)!(?P<id>.*@GateKeeperPassport) (?P<command>JOIN) ((\w,)*\w) :(?P<channel>.+)'),
  re.compile (r':(?P<nick>.*)!(?P<id>.*@GateKeeperPassport) (?P<command>WHISPER) (?P<channel>.+) (?P<to>.+) :(?P<message>.+)\r\n'),
  re.compile (r':(?P<nick>.*)!(?P<id>.*@GateKeeperPassport) (?P<command>PART) (?P<channel>.+)\r\n'),
]

re_command = re.compile (r'^\S+ (\d{1,5}) ?(.*)')

class Line:
  pass

def parse_line (line_in):
  if not line_in:
    return None
  line = Line ()
  line.line = line_in
  line.command = 0
  mo = re_command.match (line_in)
  if mo:
    line.command = int (mo.group(1))
    if numbered_commands.has_key (line.command):
      mo = numbered_commands [line.command].match (mo.group(2))
      line.__dict__.update(mo.groupdict ())
  else:
    for r in other_commands:
      mo = r.search (line_in)
      if mo:
        line.__dict__.update(mo.groupdict ())
	break
  return line

def pop_front (L):
  if L:
    return L.pop (0)
  return None

#====================================================================================================

unpack = {
'\\' : '\\',
'b' : ' ',
't' : '\t',
'r' : '\r',
'n' : '\n',
'c' : ',',
'0' : chr(0)
}

pack = {}
for x,y in unpack.items ():
  pack[y] = '\\' + x

# when receiving from server
def unpack_binary_data (data):
  #print '-> %d %r'%(len(data),data)
  unpacked = ''
  translate_next = 0
  for x in data:
    if translate_next:
      unpacked += unpack [x]
      translate_next = 0
    elif x == '\\':
      translate_next = 1
    else:
      unpacked += x
  #print '<- %d %r'%(len(unpacked),unpacked)
  return unpacked 

# when sending to sever
def pack_binary_data (data):
  #print '-> %d %r'%(len(data),data)
  packed = ''
  for x in data:
    packed += pack.get (x,x)
  #print '<- %d %r'%(len(packed),packed)
  return packed
    

#====================================================================================================

class Msn_chatroom_connection:
  def __init__ (self, server, port, MSPAuth, MSPProf, MSNREGCOOKIE, channel = None):
    
    re_challenge = re.compile (r'GKSSP\\0..?\\0\02\\0\\0\\0\02\\0\\0\\0(.*)\r\n')

    if channel:
      #
      # first make a connection to ask on which server the channel lives
      #
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.connect ((server, port))
      self.fd = self.socket.fileno ()
      self.lines_in = []
      self.buffer = ''
      self.socket.send ("IRCVERS IRC6 MSN-OCX!2.03.0204.3001\r\n")
      self.socket.send ("AUTH GateKeeper I :GKSSP\\0\x03r\x02\\0\\0\\0\x01\\0\\0\\0\r\n")
      challenge = unpack_binary_data (re_challenge.search (self.next_line ().line).group(1))
      answer = challenge_1 (challenge)
      answer = 'AUTH GateKeeper S :GKSSP\\0\\0\\0\x02\\0\\0\\0\x03\\0\\0\\0' + pack_binary_data(answer) + 'Sm(\xe4HS\xc1M\x84\x7f\x82\x93\xf9\x8dUC\r\n' 
      self.socket.send (answer)
      self.next_line ()
      self.socket.send ('NICK nick\r\n')
      self.socket.send ('FINDS %' +'%s\r\n'%channel)
      while 1:
        line = self.next_line()
        if line.command == 613:
          break
	if line.command == 702:
	  raise 'channel not found'
      server = line.server
      port = int (line.port)
    
    #
    #  now connect to the irc server
    #
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.connect ((server, port))
    self.fd = self.socket.fileno ()
    self.lines_in = []
    self.buffer = ''
    self.socket.send ('IRCVERS IRC6 MSN-OCX!2.03.0204.0801 chat.msn.be\r\n')   
    self.next_line ()
    self.socket.send ('AUTH GateKeeperPassport I :GKSSP\\0\x03r\x02\\0\\0\\0\x01\\0\\0\\0\r\n')
    challenge = unpack_binary_data (re_challenge.search (self.next_line ().line).group(1))
    answer = challenge_1 (challenge)
    answer = 'AUTH GateKeeperPassport S :GKSSP\\0\xcc\xcc\x02\\0\\0\\0\x03\\0\\0\\0' + pack_binary_data (answer) + '\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\r\n'
    self.socket.send (answer)
    self.next_line ()
    answer = 'AUTH GateKeeperPassport S :%08X%s%08X%s\r\n'%(len(MSPAuth),MSPAuth,len(MSPProf),MSPProf)
    self.socket.send (answer)
    self.next_line ()
    self.socket.send ('PROP $ MSNREGCOOKIE :%s\r\n'%MSNREGCOOKIE)
    self.next_line ()
    self.socket.send ("PROP $ MSNPROFILE :0\r\n")
    if channel:
      self.socket.send ("JOIN %" + channel + "\r\n")
    self.font = '\x01S \x01\x01Tahoma;0'

  def next_line (self, timeout=None):
    if self.lines_in:
      return pop_front (self.lines_in)
    r,w,e = select.select([self.fd],[],[],timeout)
    if r:
      self.handle_read ()
    return pop_front (self.lines_in)

  def handle_read (self):
    input = self.socket.recv (2048)
    if not input:
      # connection has been closed
      return 0
    self.buffer += input
    while 1:
      pos=self.buffer.find('\n')
      if pos==-1: 
        break
      line = self.buffer[0:pos+1]
      print_line = '%r' % line[:-1]
      print print_line[1:-1]
      if line[:4] == 'PING':
        # handle ping silently
        self.socket.send ('PONG \r\n')
      else:
        self.lines_in.append (parse_line (line))
      self.buffer = self.buffer[pos+1:]
    return 1
  
  def message (self, channel, message, font = None):
    # PRIVMSG %#Boston :\x01S \x0b\x01Palatino\\bLinotype;0 Hi Folks\x01\r\n
    if not font:
      font = self.font
    s = "PRIVMSG %%%s :%s %s\x01\r\n" % (channel, font, message)
    self.socket.send (s)

  def whisper (self, channel, nick, message, font = None):
    # WHISPER %#Flapuit __zmic__ :\x01S \x0b\x03Tahoma;0 hallo sweetie\x01\r\n
    if not font:
      font = self.font
    s = "WHISPER %%%s %s :%s %s\x01\r\n" % (channel, nick, font, message)
    self.socket.send (s)

  def mode (self, channel, mode):
    #MODE %#Flapuit +m
    s = "MODE %%%s %s\r\n" % (channel, mode)
    self.socket.send (s)



#=====================================================================================================
#
#     main
#
if __name__ == '__main__':
  
  
  #
  #  your account information
  #
  login    = 'cardinal_richelieu'
  domain   = 'hotmail.com'
  password = my_password

  #
  #  Try to retrieve PassportTicket, PassportProfile, MSNREGCOOKIE from the account information.
  #  Should this fail, set 'try_to_find_MSNREGCOOKIE' to 0. In order to find MSNREGCOOKIE, open
  #  a chatbox on chat.msn.com with the account that you want to use, and look in the html source for:
  #  
  #     "MSNREGCookie"  VALUE="just copy-paste this"  
  #
  #  This value should never change as long as you keep the same nickname (?). You will also find
  #  a usable PassportTicket and PassportProfile at the same place, should all else fail.
  #
  PassportTicket, PassportProfile, MSNREGCOOKIE = passport.passport_login (login, domain, password, try_to_find_MSNREGCOOKIE = 1)


  #
  #  connect to the server that has channel '#ChatAtlanta3'
  #
  C = Msn_chatroom_connection ('207.68.167.253', 6667, PassportTicket, PassportProfile, MSNREGCOOKIE, "#ChatAtlanta3")

  
  #
  #  just go into a receive loop and don't react to anything
  #
  while 1:
    r = C.next_line (1)



