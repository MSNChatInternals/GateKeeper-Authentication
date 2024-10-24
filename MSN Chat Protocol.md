### Forum Topic: MSN Chat Protocol

Source: [hypothetic.org Discussion Forums](http://www.hypothetic.org/) ([Mike Mintz](http://www.mikemintz.com/))

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Fri, 26 Apr 2002 14:19:38 +0000  
**Subject:** MSN Chat protocol

Hi.

I need a MSN chat client for Linux. Don't ask why :) . Do you know a program doing that? If not.. do you know the chat protocol. It looks like an irc but I don't understand the connections stuff. I hope somebody will help me.

Regards,  
Daniel

---

#### From: Mike Mintz <HIDDEN@hypothetic>
**Date:** Fri, 26 Apr 2002 15:49:03 +0000  
**Subject:** Re: MSN Chat protocol

Sorry, I don't know how this protocol works. I know that it used to be IRC itself, but they changed, probably to ensure users were connecting from their webpage.

If you are really interested in finding this protocol and nobody has already figured it out, I would recommend getting a packet sniffer to reverse engineer it, or maybe setting a browser proxy to a local one that logs data (I don't know if that would work).

---

#### From: Andrew Heebner <andrew@evilwalrus.com>
**Date:** Mon, 06 May 2002 22:18:31 +0000  
**Subject:** Re: MSN Chat protocol

I've done a complete client/bot in PHP for IRC... it'll be added to the PEAR class repository soon.. also have one completed for AIM and MSN... thanks for the text here Mike, without it, I'd be aimless on the MSN protocol.. next challenge: Yahoo messenger.

~! Andrew Heebner

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Tue, 07 May 2002 11:07:18 +0000  
**Subject:** Re: MSN Chat protocol

Hi.

I am looking for a way to login to the MSN chat (not MSN messenger). If you know how to do it, please let me know.

Regards,  
Daniel

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Tue, 07 May 2002 13:19:43 +0000  
**Subject:** Re: MSN Chat protocol

hi there,  
i __partly__ reverse-engineered the login to the msn chatrooms (it was a very rainy last sunday). It contains some messy md5 stuff. Mike, if you allow me, i will just copy-paste the python script that does the stuff as a reference.  
Some remarks:
- For some reason that i fail to understand, it works only about 50% of the times. But given a couple a tries, you're guaranteed to get in. So if you get the ":TK2CHATWBA07 910 nickname :Authentication Failed", just try again.
- At the moment i'm stuck at the point were the user sends some info based on a very hairy mess of webpage accesses :/ This is the last phase of the authentication.

```python
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
```

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Tue, 07 May 2002 13:21:02 +0000  
**Subject:** Re: MSN Chat protocol

ow nice, the message board fucked up my nice python indentation *sigh*

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Tue, 07 May 2002 13:34:22 +0000  
**Subject:** Re: MSN Chat protocol

Thank you. I don't know python but I understand what is happening.

Can you tell me how did you find out those strings for the challenge_1 function?

Regards,  
Daniel

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Tue, 07 May 2002 13:53:29 +0000  
**Subject:** Re: MSN Chat protocol

I found the md5 function in MsnChat40.ocx. It's at 0x72033c6a. If you put a breakpoint there, you can retrieve the input from memory. The strings seem to be constant and independent of you user-id. Your id is only established at the point where i'm stuck.

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Tue, 07 May 2002 13:59:00 +0000  
**Subject:** Re: MSN Chat protocol

Wow. You are quite good. Let me know when you find out the entire secret. I will try finding it too but I think your much better than me at doing this.

Thanks again.  
Daniel

---

#### From: Mike Mintz <HIDDEN@hypothetic>
**Date:** Tue, 07 May 2002 15:58:41 +0000  
**Subject:** Re: MSN Chat protocol

Wow, that's great that you got all that! Sorry about the indentation problem; I didn't enable attachments on this forum.

I just viewed the source of this page and extracted your message, replaced the `<br />`'s and `</>`'s, and put it into a file, and it worked :-). I uploaded it temporarily to [url]http://www.hypothetic.org/docs/msn/msnchat.py[/url] if others want to take a look at it (with the working indentation). I hope you don't mind, I can take it off if you want.

Great Work!  
- Mike Mintz

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Wed, 08 May 2002 20:00:32 +0000  
**Subject:** Re: MSN Chat protocol

No i don't mind at all :)

Meanwhile, i've been able to do the .Net passport login in Python, using secure socket layer. It returns 2 session keys that allow me to get past the next authentication step on the chat server. The final step is sending an ID that is associated with the nickname that you registered. I've no idea how to get to this ID, but it seems to be constant, so i could use one that i snooped from my logfiles. Of course this is far from an ideal solution.

So in fact i managed to complete the login, join a channel and see talk-events come in. I will post some code, but i have to clean it up a bit first.

---

#### From: Mike Mintz <HIDDEN@hypothetic>
**Date:** Wed, 08 May 2002 21:00:34 +0000  
**Subject:** Re: MSN Chat protocol

How did you get it to log in if you hadn't figured out that final step ID? Did you just make it constant in the script you posted so it was actually logging into your account, or what?

If it wasn't SSL, you could just log all of the traffic going through, and find where the key's matched the MSN chat protocol to the .Net passport login.

Again, great work!  
- Mike Mintz

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Thu, 09 May 2002 16:26:34 +0000  
**Subject:** Re: MSN Chat protocol

When you want to chat on the msn chatrooms, you have to register a nickname first. It seems that the server associates an unique, constant ID with each nickname that is registered. The final step of the login is that you send this ID, to establish your nickname on the chat. I simply fished one such ID from the tcp-dumps of a Messenger session, and hardcoded it in my script, and it works. I can even share this nick between different .NET accounts (but only one user at a time).  
What i really want is to establish this nick ID given the .NET username and password. From looking looking at the logs, this seems possible by sending some request to http://nickname.msn.com, but there's a lot of cookies involved and i've not had any success with it

Meanwhile i fixed the first stage of the login. The success-rate is now ~100% :)

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Sat, 11 May 2002 06:31:07 +0000  
**Subject:** Re: MSN Chat protocol

Hi.

I hope you get that code better because is not working for me. I think the cause is here:

```python
answer = 'AUTH GateKeeper S :GKSSP\\0\\0\\0\x02\\0\\0\\0\x03\\0\\0\\0' + answer + '\xb2\x02"\xbd\xdd\x94sO\xae6\x03j\xfb\xe7\xaal\r\n'
```

The last constant string ... is not so constant.

After the code you wrote the chat sends to strings which are taken from cookies.

The first cookie is "MSPProf" but the chat adds something like "0000003" or "0000005" etc. I don't know what is setting this number.

The second string is the "MSNChatNN" cookie.

MSPPRof is set by a script called (with redirect) from login. The login stuff is using HTTPS and I don't know how to decrypt the stuff.

MSNChatNN is set by /msnchat/1033/utf8/msnredir.asp.

You said that your code is working 100% now so I think I need a way to go through the HTTPS stuff. I would love to find a way to avoid using the HTTPS.

Tell me what you think.

Regards,  
Daniel

---

#### From: zmic <zmiczmic@hotmail.com>
**Date:** Sat, 11 May 2002 14:46:57 +0000  
**Subject:** Re: MSN Chat protocol

there is no way to avoid the SSL stuff if you want to login to your .NET passport.

The numbers that get pasted in front of the cookies is the length of the cookie, in hexadecimal

regards,  
zmic

---

#### From: Daniel Negrea <daniel_negrea(no_spam)@yahoo.com>
**Date:** Sat, 11 May 2002 14:52:34 +0000  
**Subject:** Re: MSN Chat protocol

hi.

That's bad. I will have a look at the curl library.  
That number is not a length. The cookie is aprox. 2 lines long and the number is like 000000x . Under 10.

Would you post the fix code for the MD5 stuff?

Regards,  
Daniel

---

#### From: yoni <yoniel@hotmail.com>
**Date:** Sat, 01 Jun 2002 02:16:48 +0000  
**Subject:** Re: MSN Chat protocol

Hello Guys

is there ant samples in VB for msn chat room?

any help will be welcomed

Thx

---

#### From: Bryan <bryan_2002_@hotmail.com>
**Date:** Sun, 23 Jun 2002 17:23:33 +0000  
**Subject:** Re: MSN Chat protocol

hi. ive written a msn chat client in VB for windows. its not complete but it will get you logged in. email me if you want me to send it to you!
