# This example is downloaded from https://pymotw.com/2/select/
# Copyright (c) 2015, Doug Hellmann, All Rights Reserved
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import select
import socket
import sys
import Queue

# Create a TCP/IP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setblocking(0)

# Bind the socket to the port
server_address = ('localhost', 10000)
print >>sys.stderr, 'starting up on %s port %s' % server_address
server.bind(server_address)

# Listen for incoming connections
server.listen(5)

# Keep up with the queues of outgoing messages
message_queues = {}

# Do not block forever (milliseconds)
TIMEOUT = 0

# Commonly used flag setes
READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
READ_WRITE = READ_ONLY | select.POLLOUT

# Set up the poller
poller = select.poll()
poller.register(server, READ_ONLY)
poller_len = 1

# Map file descriptors to socket objects
fd_to_socket = { server.fileno(): server,
               }

while poller_len > 0:

    # Wait for at least one of the sockets to be ready for processing
    print >>sys.stderr, '\nwaiting for the next event'
    events = poller.poll(TIMEOUT)

    for fd, flag in events:

        # Retrieve the actual socket from its file descriptor
        s = fd_to_socket[fd]

        # Handle inputs
        if flag & (select.POLLIN | select.POLLPRI):

            if s is server:
                # A "readable" server socket is ready to accept a connection
                connection, client_address = s.accept()
                print >>sys.stderr, 'new connection from', client_address
                connection.setblocking(0)
                fd_to_socket[ connection.fileno() ] = connection
                poller.register(connection, READ_ONLY)
                poller_len += 1

                # Give the connection a queue for data we want to send
                message_queues[connection] = Queue.Queue()

            else:
                data = s.recv(1024)
                if data:
                    # A readable client socket has data
                    print >>sys.stderr, 'received "%r" from %s' % (data, s.getpeername())
                    message_queues[s].put(data)
                    # Add output channel for response
                    poller.modify(s, READ_WRITE)
                else:
                    # Interpret empty result as closed connection
                    print >>sys.stderr, 'closing', client_address, 'after reading no data'
                    # Stop listening for input on the connection
                    poller.unregister(s)
                    poller_len -= 1
                    s.close()

                    # Remove message queue
                    del message_queues[s]
        elif flag & select.POLLHUP:
            # Client hung up
            print >>sys.stderr, 'closing', client_address, 'after receiving HUP'
            # Stop listening for input on the connection
            poller.unregister(s)
            poller_len -= 1
            s.close()
        elif flag & select.POLLOUT:
            # Socket is ready to send data, if there is any to send.
            try:
                next_msg = message_queues[s].get_nowait()
            except Queue.Empty:
                # No messages waiting so stop checking for writability.
                print >>sys.stderr, 'output queue for', s.getpeername(), 'is empty'
                poller.modify(s, READ_ONLY)
            else:
                print >>sys.stderr, 'sending "%s" to %s' % (next_msg, s.getpeername())
                s.send(next_msg)
        elif flag & select.POLLERR:
            print >>sys.stderr, 'handling exceptional condition for', s.getpeername()
            # Stop listening for input on the connection
            poller.unregister(s)
            poller_len -= 1
            s.close()

            # Remove message queue
            del message_queues[s]
