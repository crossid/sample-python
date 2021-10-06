import os
from base64 import b64encode

import http.server
import http.cookies
import socketserver
from http import HTTPStatus

from urllib.parse import parse_qs
from cryptography.fernet import Fernet

from client import OIDCClient



secret = Fernet.generate_key()
f = Fernet(secret)

client = OIDCClient(os.getenv('ISSUER_BASE_URL'), 
                    os.getenv('CLIENT_ID'), 
                    os.getenv('CLIENT_SECRET'), 
                    os.getenv('REDIRECT_URI'))

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path, _, query_string = self.path.partition('?')
        query = parse_qs(query_string)

        if path == '/':
          self.index_GET()
        elif path == '/login':
          self.login_GET()
        elif path == '/logout':
          self.logout_GET()
        elif path == '/callback':
          self.callback_GET(query)
        elif path == '/protected':
          self.protected_GET()
        else:            
          self.send_response(HTTPStatus.NOT_FOUND)
          self.end_headers()

    def set_cookies(self, cookies):
      for _, value in cookies.items():
        self.send_header('Set-Cookie', value.output(None,''))

    def get_cookies(self):
        cookie = http.cookies.SimpleCookie()
        cookies = {}
        if self.headers.get('Cookie') != None:
          cookie.load(self.headers.get('Cookie'))
          for n, c in cookie.items():            
            cookies[n] = f.decrypt(c.value.encode()).decode()

        return cookies

    def index_GET(self):
        self.send_response(HTTPStatus.OK)
        self.send_header( 'Content-type', 'text/html' )
        self.end_headers()
        self.wfile.write( open('index.html', 'rb').read())

    def login_GET(self):
        nonce = b64encode(os.urandom(32))
        state = b64encode(os.urandom(32))

        cookie = http.cookies.SimpleCookie()
        cookie['nonce'] = f.encrypt(nonce).decode()
        cookie['nonce']['secure'] = True
        cookie['nonce']['httponly'] = True

        cookie['state'] = f.encrypt(state).decode()
        cookie['state']['secure'] = True
        cookie['state']['httponly'] = True

        auth_url = client.auth_url(state, scope=["openid", "profile", "email"], nonce = nonce)

        self.send_response(HTTPStatus.FOUND)
        self.set_cookies(cookie)
        self.send_header('Location',auth_url)
        self.end_headers()

    def callback_GET(self, query):
      cookies = self.get_cookies()

      code = query.get('code', [''])[0]
      if code == '':
        self.send_response(HTTPStatus.BAD_REQUEST)
        self.send_header( 'Content-type', 'text/html' )
        self.end_headers()
        self.wfile.write('missing code')
        return
      
      state = query.get('state', [''])[0]
      saved_state = cookies['state']
      if state != saved_state:
        self.send_response(HTTPStatus.BAD_REQUEST)
        self.send_header( 'Content-type', 'text/html' )
        self.end_headers()
        self.wfile.write('bad state')
        return

      tokens = client.exchange_token(code)

      saved_nonce = cookies['nonce']

      id_token = client.decode(tokens.id_token, nonce=saved_nonce)

      logout_url = client.end_session_endpoint + "?id_token_hint=" +  tokens.id_token + "&post_logout_redirect_uri=https://localhost"

      self.send_response(HTTPStatus.OK)
      self.send_header( 'Content-type', 'text/html' )
      self.end_headers()
      self.wfile.write('<html><body>Hello {}.<br/>Your access token is {}<br/><button><a href="{}">Logout</a></button></body></html>'
                      .format(id_token['name'], tokens.access_token, logout_url).encode())

    def has_any_scopes(self, token, scopes) -> bool:
      return len(set(token.get('scp', [])).intersection(scopes)) > 0

    def protected_GET(self):
      tok = self.headers.get('Authorization', '')
      if 'Bearer ' not in tok:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header( 'Content-type', 'text/html' )
        self.end_headers()
        self.wfile.write('missing authorization header')
        return

      token = tok.replace('Bearer ', '')

      cookies = self.get_cookies()

      nonoce = cookies.get('nonce', '')

      try:
        access_token = client.decode(token, nonce = nonoce)
        if not self.has_any_scopes(access_token, ['profile']):
          self.send_response(HTTPStatus.FORBIDDEN)
          self.send_header( 'Content-type', 'text/html' )
          self.end_headers()
          self.wfile.write(b'missing scopes')
          return

      except Exception as e:
          self.send_response(HTTPStatus.UNAUTHORIZED)
          self.send_header( 'Content-type', 'text/html' )
          self.end_headers()
          self.wfile.write(e)
          return
      
      self.send_response(HTTPStatus.OK)
      self.send_header( 'Content-type', 'text/plain' )
      self.end_headers()
      self.wfile.write(b'You are authenticated')

      





port = int(os.getenv('PORT', 8080))
print('Listening on port %s' % (port))
httpd = socketserver.TCPServer(('', port), Handler)
httpd.serve_forever()