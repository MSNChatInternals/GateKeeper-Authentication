###############################################################
import socket, select, re, md5


def pop_front (L):
  if L:
    return L.pop (0)
  return None

#====================================================================================================

def challenge_1 (challenge):
  c1 = "edp{}e|wxrdse}}u666666666666666666666666666666666666666666666666" + challenge
  a1 = md5.new(c1).digest ()
  c2 = "\x0f\x0e\x1a\x11\x17\x0f\x16\x1d\x12\x18\x0e\x19\x0f\x17\x17\x1f" + r"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\" + a1
  a2 = md5.new(c2).digest ()
  return a2


#====================================================================================================

regexps = {
  # :TK2CHATWBA09 613 nick :207.68.167.162 6667
  613 : re.compile (r'(?P<nick>\S+) :(?P<server>\S+) (?P<port>\S+)')

}


re_command = re.compile (r'\S+ (\d+) ?(.*)')

class Line:
  pass

def parse_line (line_in):
  line = Line ()
  line.line = line_in
  line.command = 0
  mo = re_command.search (line_in)
  if mo:
    line.command = int (mo.group(1))
    if regexps.has_key (line.command):
      mo = regexps [line.command].match (mo.group(2))
      for x,y in mo.groupdict ().items ():
        setattr (line, x, y)
  return line

#====================================================================================================

class Msn_chatroom_connection:
  def __init__ (self, server, port, channel = None):
    
    if channel:
      #
      # first make an connection to ask on which server the channel lives
      #
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.connect ((server, port))
      self.fd = self.socket.fileno ()
      self.lines_in = []
      self.buffer = ''
      self.socket.send ("IRCVERS IRC6 MSN-OCX!2.03.0204.0801\r\n")
      self.socket.send ("AUTH GateKeeper I :GKSSP\\0\x03r\x02\\0\\0\\0\x01\\0\\0\\0\r\n")
      challenge = self.next_line ().rstrip()
      challenge = challenge [-8:]
      answer = challenge_1 (challenge)
      answer = 'AUTH GateKeeper S :GKSSP\\0\\0\\0\x02\\0\\0\\0\x03\\0\\0\\0' + answer + '\xb2\x02"\xbd\xdd\x94sO\xae6\x03j\xfb\xe7\xaal\r\n' 
      self.socket.send (answer)
      self.next_line ()
      self.socket.send ('NICK nick\r\n')
      self.socket.send ('FINDS %' +'%s\r\n'%channel)
      while 1:
        line = parse_line (self.next_line())
        if line.command == 613:
          break
      server = line.server
      port = int (line.port)
    
    print server, port
    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.connect ((server, port))
    self.fd = self.socket.fileno ()
    self.lines_in = []
    self.buffer = ''
    self.socket.send ('IRCVERS IRC6 MSN-OCX!2.03.0204.0801 chat.msn.be\r\n')   
    self.next_line ()
    self.socket.send ('AUTH GateKeeperPassport I :GKSSP\\0\x03r\x02\\0\\0\\0\x01\\0\\0\\0\r\n')
    challenge = self.next_line ().rstrip()
    challenge = challenge [-8:]
    answer = challenge_1 (challenge)
    answer = 'AUTH GateKeeperPassport S :GKSSP\\0\xcc\xcc\x02\\0\\0\\0\x03\\0\\0\\0' + answer + '\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\\0\r\n'
    self.socket.send (answer)
    self.next_line ()

     
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
      print line[:-1]
      self.lines_in.append (line)
      self.buffer = self.buffer[pos+1:]
    return 1


if __name__ == '__main__':
  C = Msn_chatroom_connection ('207.68.167.253', 6667, "#SocialTalk")
  while 1:
    r = C.next_line (1)