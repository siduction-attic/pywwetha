#! /usr/bin/python
'''
pywwetha is a minimal web server.

Name: 
* piwwetha is a native american tribe. 
* It is written in python.
* It makes similar things like the apache does. 
* pywwetha is not known by some search engines at its birth.
  
Created on 28.10.2011

@author: Hamatoma
'''

import os, sys, re, subprocess, BaseHTTPServer, glob

VERSION = '0.1-2'
VERSION_EXTENDED = VERSION + ' (2011.11.10)' 
def say(msg):
    '''Prints a message if allowed.
    @param msg: the message to print
    ''' 
    global config
    if config != None and config._verbose:
        print msg
    if config != None and config._doLog:
        log(msg)
        
def sayError(msg):
    '''Prints an error message if possible.
    @param msg: the message to print
    ''' 
    global config
    if config != None and not config._daemon:
        print '+++ ', msg
    if config != None and config._doLog:
        log('+++ ' + msg)

def log(msg):
    global config
    if config._logFile == None:
        config._logFile = open('/tmp/pywwetha.log', 'a')
    config._logFile.write(msg + "\n")
    config._logFile.flush()
        
class Host:
    '''Holds the data of a virtual host
    '''
    def __init__(self, name):
        '''Constructor.
        @param name: the name of the virtual host 
        '''
        self._name = name
        self._items = dict()
        
class Config:
    '''Manages the configuration data
    '''
    def __init__(self):
        '''Constructor.
        '''
        self._debug = False
        self._verbose = False
        self._daemon = False
        self._logFile = None
        self._translatePathInfo = None
        self._port = 80
        self._hosts = dict()
        self._doLog = False
        self._currentHost = None
        self._hosts['localhost'] = Host('localhost')
        configfiles = glob.glob('/etc/pywwetha/*.conf')
        for conf in configfiles:
            self.readConfig(conf)
        self.postRead()
        self._mimeTypes = {
            'html' : 'text/html',
            'htm' : 'text/html',
            'css' : 'text/css',
            'txt' : 'text/plain',
            'jpeg' : 'image/jpeg',
            'png' : 'image/png',
            'jpg' : 'image/jpeg',
            'gif' : 'image/gif',
            'ico' : 'image/x-icon',
            'js' : ' application/x-javascript'
        }
        self._fileMatcher = re.compile(r"[.](css|html|htm|txt|png|jpg|jpeg|gif|svg|ico|js)$", re.I)
        self._server = dict()
        self._environ = os.environ
        os.environ.clear()
        
    def postRead(self):
        '''Does initialization code after reading the configuration.
        '''
        item = 'cgiExt'
        extDefault = 'php'
        if item in self._hosts['localhost']._items:
            extDefault = self._hosts['localhost']._items[item]
        for host in self._hosts:
            ext = extDefault
            if item in self._hosts[host]._items:
                ext = self._hosts[host]._items[item]
            pattern = "(.*[.](%s))((/[^?]+)?(\?(.*)))?" % ext
            self._hosts[host]._urlMatcher = re.compile(pattern)
   
    def readConfig(self, name):
        '''Reads the configuration file.
        @param name: the name of the configuration file
        '''
        handle = file(name)
        if not handle:
            sayError("not readable: %s" % name)
        else:
            say(name + ":")
            vhostMatcher = re.compile(r'([-a-zA-z0-9._]+):(\w+)\s*=\s*(.*)')
            varMatcher = re.compile(r'(\w+)\s*=\s*(.*)')
            itemMatcher = re.compile(r'(documentRoot|cgiProgram|cgiArgs|cgiExt|index)$')
            lineNo = 0
            for line in handle:
                lineNo += 1
                if lineNo > 30:
                    pass
                matcher = vhostMatcher.match(line)
                host = None
                if matcher != None:
                    vhost = matcher.group(1)
                    var = matcher.group(2)
                    value = matcher.group(3)
                    if vhost in self._hosts:
                        host = self._hosts[vhost]
                    else:
                        host = Host(vhost)
                        self._hosts[vhost] = host
                        
                    if itemMatcher.match(var) != None:
                        host._items[var] = value
                        if var == 'documentRoot' and not os.path.isdir(value):
                            sayError('%s-%d: %s is not a directory' % (name, lineNo, value))
                        elif var == 'cgiProgram' and not os.path.isfile(value):
                            sayError('%s-%d: %s does not exist: ' % (name, lineNo, value))
                        else:
                            say('%s: %s=%s' % (vhost, var, value))
                    else:
                        sayError("%s-%d: unknown item: %s" % (name, lineNo, var))
                else:
                    matcher  = varMatcher.match(line)
                    if matcher != None:
                        var = matcher.group(1)
                        value = matcher.group(2)
                        if var == 'port':
                            matcher = re.match(r'(\d+)$', value)
                            self._port = int(value) if matcher else 0;
                            if self._port <= 0 or self._port >= 65535:
                                sayError('%s-%d: wrong port: %s' % (name, lineNo, value))
                            else:
                                say('%s=%s' % (var, value))
                        elif var == 'user' or var == 'group':
                            # Not used by the server:
                            say('%s=%s' % (var, value))
                        elif var == 'debug':
                            self._debug = re.match(r'[tT1]', value)
                        else:
                            sayError("%s-%d: unknown item: " % (name, lineNo, var))
            handle.close()
             
    def getItemOfHost(self, name):
        '''Returns the specified item of the current virtual host.
        @param name: the name of the item
        @return: None: undefined item. Otherwise: the value of the item 
        '''
        rc = None
        host = self._currentHost
        if host == None:
            host = self._hosts['localhost']
        if name in host._items:
            rc = host._items[name]
        else:
            host = self._hosts['localhost']
            if name in host._items:
                rc = host._items[name]
        return rc
    
    def getMimeType(self, name):
        '''Finds the mime type.
        @param name: the resource name
        @return: None: Unknown resource. Otherwise: the mime type of the resource
        ''' 
        matcher = self._fileMatcher.search(name)
        if matcher:
            rc = self._mimeTypes[matcher.group(1)]
        else:
            rc = None
        return rc
    
    def isCgi(self, name):
        '''Tests whether a resource is a cgi script.
        @param name: the resource name
        @return: True: the resource is a cgi script. False: otherwise
        '''
        pattern = '\.(' + self.getItemOfHost('cgiExt') + ')' 
        matcher = re.search(pattern, name)
        rc = matcher != None
        return rc
    
    def errorMesssage(self, msg):
        '''Builds a html page with an error message.
        @param msg    error message
        @return: a valid html page with the error message
        '''
        rc = '''
<html>
<body>
</body>
<h1>Webserver Problem (pywwetha)</h1>
<p>%s</p>
</html>
        ''' % msg
        return rc
    def splitUrl(self, path):
        '''Splits the URL into parts.
        The parts will be stored in <code>self._server</code>.
        @param path: the url without protocol, host and port
        '''
        matcher = self._currentHost._urlMatcher.match(path)
        self._server['REQUEST_METHOD'] = 'GET'
        docRoot = self.getItemOfHost('documentRoot') 
        if matcher == None:
            self._server['SCRIPT_FILENAME'] = docRoot + path
            self._server['QUERY_STRING'] = '' 
            self._server['REQUEST_URI'] = path
            self._server['SCRIPT_NAME'] = path
        else:
            ext = self.getItemOfHost('cgiExt')
                
            self._server['SCRIPT_FILENAME'] = docRoot + matcher.group(1)
            query = matcher.group(6)
            self._server['QUERY_STRING'] = query 
            self._server['REQUEST_URI'] = path
            self._server['SCRIPT_NAME'] = matcher.group(1)
            pathInfo = matcher.group(4)
            self._server['PATH_INFO'] = pathInfo
            
    def setVirtualHost(self, host):
        '''Sets the current virtual host.
        @param host: the host expression, e.g. abc:8086
        '''
        hostinfo = re.split(':', host)
        hostname = hostinfo[0]
        self._currentPort = hostinfo[1] if len(hostinfo) > 1 else str(self._port)
        if len(self._currentPort) == 0:
            self._currentPort = 80
        if not hostname in self._hosts:
            hostname = 'localhost'
        self._currentHost = self._hosts[hostname]
        
    def getHeader(self, server, key):
        '''Returns a value of the headers.
        The key will be compared case insensitive.
        @param server: the server with the headers
        @param key:    the key to search for
        @return: None key not found. Otherwise: the value
        '''
        rc = None
        key = key.lower()
        for key1 in server.headers.dict.iterkeys():
            if key1.lower() == key:
                rc = server.headers.dict[key1]
                break
        return rc
    
    def runCgi(self, server):
        '''Runs the cgi program and writes the result.
        @param server: the server
        '''
        docRoot = self.getItemOfHost('documentRoot')
        # Necessary for running php-cgi:
        self._server['REDIRECT_STATUS'] = '1'
        self._server['HTTP_HOST'] = self._currentHost._name + ':' + self._currentPort
        self._server['REMOTE_ADDR'] = server.client_address[0]
        self._server['REMOTE_PORT'] = server.client_address[1]
        value = self.getHeader(server, 'user-agent')
        if value != None:
            self._server['HTTP_USER_AGENT'] = value
        value = self.getHeader(server, 'accept-language')
        if value != None:
            self._server['HTTP_ACCEPT_LANGUAGE'] = value
        self._server['SERVER_ADDR'] = '127.0.0.1'
        self._server['SERVER_NAME'] = self._currentHost._name
        self._server['SERVER_PORT'] = self._currentPort
        self._server['DOCUMENT_ROOT'] = docRoot
        pathInfo = self._server['PATH_INFO'] if 'PATH_INFO' in self._server else ""
        if pathInfo == None:
            pathInfo = ""
        self._server['PATH_TRANSLATED'] = docRoot + pathInfo
        for key, value in self._server.iteritems():
            if value == None:
                value = '' 
            os.environ[key] = str(value)
            if self._verbose: 
                log(key + "=" + str(value))
        filename = self._server['SCRIPT_FILENAME']
        say('Script: ' + filename)
        args = self.getItemOfHost('cgiArgs')
        args = re.split(r'\|', args)
        for ii in xrange(len(args)):
            if args[ii] == '${file}':
                args[ii] = filename
        prog = self.getItemOfHost('cgiProgram')
        if not os.path.exists(prog):
            content = self.errorMesssage('cgi program not found: ' + prog)
        else:
            args.insert(0, prog)
            
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = process.communicate()
            content = output[0]
            err = output[1]
            if self._debug or (err != None and len(err) > 0):
                say('Error(s) found')
                err = str(err)
                say(err[0:160])
                ix = content.find('</body>')
                if ix < 0:
                    content = self.errorMesssage(
                        'cgi program %s find errors:' % prog, str(err))
                else:
                    content = (content[0:ix] + "<pre>CGI-ERRORS:\n"
                        + err + "\n</pre>\n" + content[ix+7:])
                    
                
        if content.find('Status:') != 0:
            server.send_response(200)
            if content.find('Content-type: ') < 0:
                say("Content type not found. Generating...")
                mimeType = 'text/html'
                server.send_header('Content-type', mimeType)
                server.end_headers()
            server.wfile.write(content)
            say('Content: ' + content[0:80] + '...')
        else:
            lines = content.split("\n")
            cols = lines[0].split(" ")
            status = int(cols[1])
            server.send_response(status)
            for ii in xrange(len(lines)):
                if ii > 0:
                    line = lines[ii].rstrip()
                    index = line.find(': ')
                    if index > 0:
                        say(line)
                        server.send_header(line[0:index], line[index+1:])
            server.end_headers()
            
    
class WebServer(BaseHTTPServer.BaseHTTPRequestHandler):
    '''Implements a web server.
    '''
    def do_GET(self):
        '''Handles a GET request.
        '''
        global config
        config.setVirtualHost(self.headers.dict['host'])
        if self.path == '/':
            self.path = '/' + config.getItemOfHost('index')
        filename = config.getItemOfHost('documentRoot') + self.path
        say('GET: ' + filename)
        try:
            if config.isCgi(self.path):
                config.splitUrl(self.path)
                config.runCgi(self)
            else:
                mimeType = config.getMimeType(self.path)
                if mimeType == None:
                    self.send_error(404,'File Not Found: %s' % self.path)
                else:
                    handle = open(filename)
                    self.send_response(200)
                    self.send_header('Content-type', mimeType)
                    self.end_headers()
                    self.wfile.write(handle.read())
                    handle.close()
                
        except IOError:
            self.send_error(404,'File Not Found: %s' % self.path)
     

    def do_POST(self):
        '''Handles a POST request.
        '''
        try:
            set.do_GET(self)
        except :
            pass

def main():
    '''Do the real things.
    '''
    global config
    config = None
    config = Config()
    for ii in xrange(len(sys.argv)):
        if sys.argv[ii] == '--daemon':
            config._daemon = True
            config._verbose = False
        elif sys.argv[ii] == '--verbose':
            config._verbose = True
        elif sys.argv[ii] == '--debug':
            config._debug = True
        elif sys.argv[ii] == '--log':
            config._doLog = True
        elif sys.argv[ii] == '--check-config':
            config._verbose = True
            # read again with error reporting:
            config = Config()
            return
        elif sys.argv[ii] == '--version':
            print VERSION_EXTENDED
            return
        elif sys.argv[ii] == '--version-short':
            print VERSION
            return
        elif sys.argv[ii] == '--help':
            print '''
pywwetha %s
A simple webserver for static html and CGI.

Usage: pywwetha.py <opts>
<opt>:
--verbose    
    Issues some messages
--log
    Writes messages to /tmp/pywwetha.log
--debug
    Insert php-cgi warnings and errors into the html pages
--daemon
    Runs as daemon
--check-config
    Checks the configuration and exits
--version
    Issues the version and exits
--version-numeric
    Issues the version as a short value: %s
--help
    Issues this info
            ''' % (VERSION_EXTENDED, VERSION)
            return
    try:
        server = BaseHTTPServer.HTTPServer(('', config._port), WebServer)
        if not config._daemon:
            say('Starting pywwetha on port %d (Ctrl-C to stop)' % config._port)
        server.serve_forever()
    except KeyboardInterrupt:
        if not config._daemon:
            say('Stopping pywwetha...')
        server.socket.close()

if __name__ == '__main__':
    main()