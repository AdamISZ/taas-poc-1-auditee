import socket
irc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
from shared.tlsn_common import config as config
verbose = False

def ltc(msg):
    """Log to console"""
    if verbose:
        print (msg)

def start_connection(my_nick):
    '''Connects to IRC using my_nick as nick and the settings for IRC
    in the config file in shared.config_location.
    No return - failure will be indicated by Exceptions.
    '''
    irc_socket.connect((config.get('IRC','irc_server'), int(config.get('IRC','irc_port'))))
    irc_socket.send('USER %s %s %s %s' % ('these', 'arguments', 'are', 'optional') + '\r\n')
    irc_socket.send('NICK ' + my_nick + '\r\n')
    irc_socket.send('JOIN %s' % ('#'+config.get('IRC','channel_name')) + '\r\n')
    irc_socket.settimeout(1)


def send_raw(data):
    '''Sending a single message without authentication or acks
    '''
    bytes_sent = irc_socket.send('PRIVMSG ' + '#' + config.get('IRC','channel_name') +' ' + data +' \r\n')
    ltc('SENT: ' + str(bytes_sent) + ' ' + data)
    return bytes_sent

def receive_single_msg(my_nick=None):
    '''Receive a single message of tlsnotary format either sent directly to this
    nick (meaning message length is 7 including nick), or not specifically
    to this nick (message length is 6).
    Non blocking receipt; if no message is found or the message doesn't match,
    returns False.
    If a matching message is found, returns (<msg>,<nick of sending counterparty>)
    '''
    msg_buffer = ''
    try: msg_buffer = irc_socket.recv(1024)
    except: return False
    if not msg_buffer: return False

    ltc(msg_buffer)

    #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
    messages = msg_buffer.split('\r\n')
    for onemsg in messages:
        msg = onemsg.split()
        if len(msg)==0 : continue  #stray newline
        if ping_pong(msg): continue
        if not ((len(msg) == 7 and my_nick) or (len(msg) == 6 and not my_nick)): continue

        correct_without_nick = (msg[1]=='PRIVMSG' and msg[2]=='#' + config.get('IRC','channel_name'))
        correct_with_nick = my_nick and (msg[1]=='PRIVMSG' and msg[2]=='#' + config.get('IRC','channel_name') \
                                        and msg[3]==':'+my_nick)

        if not ((my_nick and correct_with_nick) or (correct_without_nick)):
            continue
        if not my_nick:
            return (msg[3:],find_nick(msg))
        else:
            return (msg[3:],find_nick(msg))

    #no messages were a match
    return False

def ping_pong(msg):
    '''Answer with PONG as per RFC 1459'''
    if msg[0] == "PING":
        irc_socket.send("PONG %s" % msg[1])
        return True
    return False

def find_nick(msg):
    '''Returns message sender's nick from the IRC message format'''
    exclamation_mark_position = msg[0].find('!')
    return msg[0][1:exclamation_mark_position]

def msg_receiver(my_nick,counterparty_nick):
    msg_buffer = ''
    try: msg_buffer = irc_socket.recv(1024)
    except: return None #1 sec timeout
    if not msg_buffer: return None

    #sometimes the IRC server may pack multiple PRIVMSGs into one message separated with /r/n/
    messages = msg_buffer.split('\r\n')

    for onemsg in messages:
        msg = onemsg.split()
        if len(msg) == 0: continue  #stray newline

        if ping_pong(msg): continue

        #filter irrelevant chan messages
        if not len(msg) >= 5: continue
        if not (msg[1] == 'PRIVMSG' and msg[2] == '#' + config.get('IRC','channel_name') and msg[3] == ':'+my_nick ): continue
        if not counterparty_nick == find_nick(msg): continue

        #this is one of our messages; output to console
        ltc('RECEIVED:' + msg_buffer)

        return msg[4:]

    return None
