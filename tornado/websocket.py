#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import string
import struct
import hashlib
import functools
import logging
import tornado.escape
import tornado.web

# The WebSockets protocol includes binary data, so we need to be sure that data
# read is interpreted as a raw bytestream, not unicode. This tests to see if
# this version of Python knows about the 'bytes' builtin, and falls back to
# 'str' otherwise.
try:
    _bytes = __builtins__.bytes
except AttributeError:
    _bytes = str

class WebSocketHandler(tornado.web.RequestHandler):
    """A request handler for HTML 5 Web Sockets.

    See http://www.w3.org/TR/2009/WD-websockets-20091222/ for details on the
    JavaScript interface. We implement the protocol as specified at
    http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-55.

    Here is an example Web Socket handler that echos back all received messages
    back to the client:

      class EchoWebSocket(websocket.WebSocketHandler):
          def open(self):
              self.receive_message(self.on_message)

          def on_message(self, message):
              self.write_message(u"You said: " + message)
              # receive_message only reads a single message, so call it
              # again to listen for the next one
              self.receive_message(self.on_message)

    Web Sockets are not standard HTTP connections. The "handshake" is HTTP,
    but after the handshake, the protocol is message-based. Consequently,
    most of the Tornado HTTP facilities are not available in handlers of this
    type. The only communication methods available to you are send_message()
    and receive_message(). Likewise, your request handler class should
    implement open() method rather than get() or post().

    If you map the handler above to "/websocket" in your application, you can
    invoke it in JavaScript with:

      var ws = new WebSocket("ws://localhost:8888/websocket");
      ws.onopen = function() {
         ws.send("Hello, world");
      };
      ws.onmessage = function (evt) {
         alert(evt.data);
      };

    This script pops up an alert box that says "You said: Hello, world".
    """
    def __init__(self, application, request):
        tornado.web.RequestHandler.__init__(self, application, request)
        self.stream = request.connection.stream

    def _execute(self, transforms, *args, **kwargs):
        headers = dict((k.lower(), v) for k, v in self.request.headers.iteritems())
        if headers.get("upgrade") != "WebSocket" or \
           headers.get("connection") != "Upgrade" or \
           not headers.get("origin"):
            message = "Expected WebSocket headers"
            self.stream.write(
                "HTTP/1.1 403 Forbidden\r\nContent-Length: " +
                str(len(message)) + "\r\n\r\n" + message)

            return

        # Note: there are basically two kinds of handshakes that can happen. In
        # WebSocket draft specifications before draft 76 (June 2010) things are
        # simple, the server just needs to respond with some upgrade headers and
        # a WebSocket-{Origin,Location}. Starting with draft 76, clients send
        # two additional headers, Sec-WebSocket-Key{1,2} and a secret value in
        # the first 8 bytes of the request body. The code below is a bot
        # convoluted, but it handles both kinds of handshakes.

        key1 = _bytes(headers.get("sec-websocket-key1"))
        key2 = _bytes(headers.get("sec-websocket-key2"))

        def key_value(key):
            val = int(''.join(c for c in key if c in string.digits), 10)
            divisor = sum(1 for c in key if c == ' ')
            return struct.pack('!L', val / divisor)

        if not (key1 and key2):
            respond_handshake('')

        try:
            s1 = key_value(key1)
            s2 = key_value(key2)
        except (ValueError, ZeroDivisionError), e:
            return respond_handshake(None)

        def compute_secret(body):
            secret = hashlib.md5(s1 + s2 + _bytes(body)).digest()
            respond_handshake(secret)

        def respond_handshake(response_body):
            # If response_body is None, then there was a handshake
            # error. Otherwise, response_body is an empty string for an
            # old-style handshake, and it's a 16 byte computed secret for a new
            # style handshake.
            if response_body is None:
                # there was a handshake error
                message = "WebSocket handshake failed"
                self.stream.write(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: " +
                    str(len(message)) + "\r\n\r\n" + message)
                return

            response = (
                "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
                "Upgrade: WebSocket\r\n"
                "Connection: Upgrade\r\n"
                "Server: TornadoServer/0.1\r\n")
            if response_body:
                response += (
                    "Sec-WebSocket-Origin: " + headers["origin"] + "\r\n"
                    "Sec-WebSocket-Location: ws://" + self.request.host +
                    self.request.path + "\r\n\r\n" + response_body)
            else:
                response += (
                    "WebSocket-Origin: " + headers["origin"] + "\r\n"
                    "WebSocket-Location: ws://" + self.request.host +
                    self.request.path + "\r\n\r\n")
            self.stream.write(response)
            self.async_callback(self.open)(*args, **kwargs)

        self.stream.read_bytes(8, compute_secret)

    def write_message(self, message):
        """Sends the given message to the client of this Web Socket."""
        if isinstance(message, dict):
            message = tornado.escape.json_encode(message)
        if isinstance(message, unicode):
            message = message.encode("utf-8")
        assert isinstance(message, str)
        self.stream.write("\x00" + message + "\xff")

    def receive_message(self, callback):
        """Calls callback when the browser calls send() on this Web Socket."""
        callback = self.async_callback(callback)
        self.stream.read_bytes(
            1, functools.partial(self._on_frame_type, callback))

    def close(self):
        """Closes this Web Socket.

        The browser will receive the onclose event for the open web socket
        when this method is called.
        """
        self.stream.close()

    def async_callback(self, callback, *args, **kwargs):
        """Wrap callbacks with this if they are used on asynchronous requests.

        Catches exceptions properly and closes this Web Socket if an exception
        is uncaught.
        """
        if args or kwargs:
            callback = functools.partial(callback, *args, **kwargs)
        def wrapper(*args, **kwargs):
            try:
                return callback(*args, **kwargs)
            except Exception, e:
                logging.error("Uncaught exception in %s",
                              self.request.path, exc_info=True)
                self.stream.close()
        return wrapper

    def _on_frame_type(self, callback, byte):
        if ord(byte) & 0x80 == 0x80:
            raise Exception("Length-encoded format not yet supported")
        self.stream.read_until(
            "\xff", functools.partial(self._on_end_delimiter, callback))

    def _on_end_delimiter(self, callback, frame):
        callback(frame[:-1].decode("utf-8", "replace"))

    def _not_supported(self, *args, **kwargs):
        raise Exception("Method not supported for Web Sockets")

for method in ["write", "redirect", "set_header", "send_error", "set_cookie",
               "set_status", "flush", "finish"]:
    setattr(WebSocketHandler, method, WebSocketHandler._not_supported)
