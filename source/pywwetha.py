#! /usr/bin/python
'''
pywwetha is a minimal web server.

Name:
* piwwetha is a native american tribe.
* It is written in python.
* It makes similar things like the apache does.
* pywwetha is not known by some search engines (at pywwetha's birth).

Created on 28.10.2011

@author: Hamatoma
'''

import os, sys, re, subprocess, BaseHTTPServer, glob, pwd, grp
import logging, time
import traceback
import djinn.wsgihandler

VERSION = '2015.10.08'
VERSION_EXTENDED = VERSION

logger = logging.getLogger("pywwetha")

def say(msg):
    '''Prints a message if allowed.
    @param msg: the message to print
    '''
    global config
    if config != None and config._verbose:
        sys.stdout.write(msg + '\n')
    log(msg)

def sayError(msg):
    '''Prints an error message if possible.
    @param msg: the message to print
    '''
    global config
    if config != None and config._verbose:
        sys.stdout.write("+++ " + msg + '\n')
    logger.error(msg)

def log(msg):
    logger.info(msg)

def errorMessage(self, msg):
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


class Host:
    '''Holds the data of a virtual host
    '''
    def __init__(self, name, config):
        '''Constructor.
        @param name: the name of the virtual host
        '''
        self._name = name
        self._port = 80
        self._items = dict()
        self._urlMatcher = None
        self._config = config
        self._application = None

    def getItem(self, name, defaultValue = None):
        '''Returns a property of the host.
        @param name:        name of the property
        @param defaultValue if the property does not exist this
                            value will be returned
        @return: the property value or the default value
        '''
        rc = self._items[name] if name in self._items else defaultValue
        return rc

    def isCgi(self, name):
        '''Tests whether a resource is a cgi script.
        @param name: the resource name
        @return: True: the resource is a cgi script. False: otherwise
        '''
        pattern = '\.(' + self.getItem('cgiExt') + ')'
        matcher = re.search(pattern, name)
        rc = matcher != None
        return rc

    def isDjango(self):
        rc = self.getItem('cgiProgram') == 'django'
        return rc

    def isDjinn(self):
        rc = self.getItem('cgiProgram') == 'djinn'
        return rc

    def isWSGI(self):
        rc = self.getItem('cgiProgram') == 'WSGI'
        return rc

    def getHeader(self, webServer, key):
        '''Returns a value of the headers.
        The key will be compared case insensitive.
        @param webServer: the webServer with the headers
        @param key:    the key to search for
        @return: None key not found. Otherwise: the value
        '''
        rc = None
        key = key.lower()
        for key1 in webServer.headers.dict.iterkeys():
            if key1.lower() == key:
                rc = webServer.headers.dict[key1]
                break
        return rc

    def buildMeta(self, method, webServer, environment):
        '''Builds the meta info of the CGI / WSDI program.
        @param environment: the dictionary to fill
        '''
        docRoot = self.getItem('documentRoot')
        # Necessary for running php-cgi:
        environment['REDIRECT_STATUS'] = '1'
        environment['HTTP_HOST'] = self._name
        environment['REMOTE_ADDR'] = webServer.client_address[0]
        environment['REMOTE_PORT'] = webServer.client_address[1]
        value = self.getHeader(webServer, 'user-agent')
        if value != None:
            environment['HTTP_USER_AGENT'] = value
        value = self.getHeader(webServer, 'accept-language')
        if value != None:
            environment['HTTP_ACCEPT_LANGUAGE'] = value
        environment['SERVER_ADDR'] = '127.0.0.1'
        environment['SERVER_NAME'] = self._name
        environment['SERVER_PORT'] = self._port
        environment['DOCUMENT_ROOT'] = docRoot
        if config._debug:
            flags = os.getenv('TRACE_FLAGS')
            if flags == None:
                flags = '*'
            environment['TRACE_FLAGS'] = flags
            say('TraceFlags: ' + flags)

        pathInfo = environment['PATH_INFO'] if 'PATH_INFO' in environment else ""
        if pathInfo == None:
            pathInfo = ""
        environment['PATH_TRANSLATED'] = docRoot + pathInfo
        environment['REQUEST_METHOD'] = method
        environment['CONTENT_LENGTH'] = 0
        environment['wsgi.input'] = webServer.rfile
        environment['wsgi.errors'] = sys.stdout
        environment['wsgi.multithread'] = False
        environment['wsgi.multiprocess'] = False
        environment['wsgi.run_once'] = False

    def splitUrl(self, method, path, script, environment):
        '''Splits the URL into its parts.
        The parts will be stored in <code>environment</code>.
        @param method: 'get' or 'post'
        @param path: the url without protocol, host and port
        @param defaultScript: the script name (URL) if it cannot retrieved by the URL
        @param environment: a dictionary containing the values to change
        '''
        matcher = self._urlMatcher.match(path)
        docRoot = self.getItem('documentRoot')
        if matcher == None:
            environment['REQUEST_METHOD'] = method
            environment['SCRIPT_FILENAME'] = docRoot + path
            environment['QUERY_STRING'] = ''
            environment['REQUEST_URI'] = path
            environment['SCRIPT_NAME'] = script
            environment['PATH_INFO'] = path
        else:
            environment['SCRIPT_FILENAME'] = docRoot + matcher.group(1)
            query = matcher.group(6)
            environment['QUERY_STRING'] = query
            environment['REQUEST_URI'] = path
            environment['SCRIPT_NAME'] = matcher.group(1)
            pathInfo = matcher.group(4)
            environment['PATH_INFO'] = pathInfo

    def extendPythonPath(self):
        '''Extends the search path for modules from the configuration.
        '''
        path = self.getItem('pythonPath')
        if path != None:
            ix = 0
            for item in re.split(r'[;:]', path):
                if item not in sys.path:
                    logger.debug("python path has been extended: " + item)
                    sys.path.insert(ix, item)
                    ix += 1
            # remove source/pywwetha from the scriptname:
            base = os.path.dirname(os.path.dirname(sys.argv[0]))
            if path not in sys.path:
                sys.path.insert(ix, base)
        item = self.getItem('documentRoot')
        if item not in sys.path:
            sys.path.insert(0, item)

    def handleStatics(self, webServer):
        '''Handles request of static content if the request is static.
        @return:     True: request has been static and is handled.
                     False: otherwise
        '''
        rc = False
        if webServer.path.startswith('/static/') or webServer.path == "/favicon.ico":
            prefix = self.getItem('wsgiStaticPagePrefix', "")
            filename = self.getItem('documentRoot') + prefix + webServer.path
            mimeType = self._config.getMimeType(filename)
            if not os.path.exists(filename):
                log("file not found: " + filename)
            else:
                webServer.sendFile(filename, mimeType)
            rc = True
        return rc

    def runCgi(self, method, webServer):
        '''Runs the cgi program and writes the result.
        @param method: 'get' or 'post'
        @param webServer: the webServer
        '''
        config = self._config
        self.buildMeta(method, webServer, config._server, config)
        self.splitUrl(method, webServer.path, webServer.path, config._server)
        for key, value in config._server.iteritems():
            if value == None:
                value = ''
            os.environ[key] = str(value)
            if config._verbose:
                log(key + "=" + str(value))
        filename = config._server['SCRIPT_FILENAME']
        say('Script: ' + filename)
        args = self.getItem('cgiArgs')
        args = re.split(r'\|', args)
        for ii in xrange(len(args)):
            if args[ii] == '${file}':
                args[ii] = filename
        prog = self.getItem('cgiProgram')
        if not os.path.exists(prog):
            content = errorMessage('cgi program not found: ' + prog)
        else:
            args.insert(0, prog)

            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = process.communicate()
            content = output[0]
            err = output[1]
            if config._debug and err != None and len(err) > 0:
                say('Error(s) found')
                err = str(err)
                say(err[0:160])
                ix = content.find('</body>')
                if ix < 0:
                    content = errorMessage(
                        "cgi program %s find errors:\n %s" % (prog, str(err)))
                else:
                    content = (content[0:ix] + "<pre>CGI-ERRORS:\n"
                        + err + "\n</pre>\n" + content[ix+7:])
        if content.find('Status:') != 0:
            webServer.send_response(200)
            if content.find('Content-type: ') < 0:
                say("Content type not found. Generating...")
                mimeType = 'text/html'
                webServer.send_header('Content-type', mimeType)
            webServer.end_headers()
            webServer.wfile.write(content)
            say('Content: ' + content[0:80] + '...')
        else:
            lines = content.split("\n")
            cols = lines[0].split(" ")
            status = int(cols[1])
            webServer.send_response(status)
            for ii in xrange(len(lines)):
                if ii > 0:
                    line = lines[ii].rstrip()
                    index = line.find(': ')
                    if index > 0:
                        say(line)
                        webServer.send_header(line[0:index], line[index+1:])
            webServer.end_headers()

    def importModule(self, key):
        '''Calls a module given by an entry of the config.
        @param config:    the configuration data
        @param key:       the name of the entry in the config
        @return:          None: module not found
                          otherwise: the loaded module
        '''
        module = self.getItem(key)
        if module == None:
            errorMessage('{:s} not found in {:}'.format(key,
                self._name))
        else:
            module = self.getModule(module)
        return module

    def getModule(self, name):
        '''Gets a module by name.
        If not loaded it will be loaded.
        @param config: the configuration info for the application subsystem
        @param name:    the name of the module
        @return:        the module
        '''
        if name not in sys.modules:
            log('importing ' + name)
            __import__(name)
        module = sys.modules[name]
        return module

    def runWSGI(self, module, webServer):
        '''Starts the application using the WebServerGatewayInterface.
        @param config: the configuration info for the application subsystem
        @param module: the module containing the WSGI definitions.<br>
                        May be a path like main.wsgi. Will be imported
        @param method: 'get' or 'post'
        @return:        the answer of the WSGI application: WsgiResponse...
        '''
        module = self.getModule(module)
        application = module.application

        response = application.__call__(webServer._wsgiEnvironment,
                webServer._startResponse)
        return response


    def handleWSGI(self, method, webServer):
        '''Handles a WSGI application.
        @param method: 'get' or 'post'
        @param config: configuration info
        '''
        if not self.handleStatics(webServer):
            self.prepareWSGI(method)
            response = self.runWSGI(config, "wsgi", webServer)
            webServer.handleContent(response)

    def handleDjango(self, method, webServer):
        '''Handles a Python Django application.
        @param method: 'get' or 'post'
        @param config: configuration info
        '''
        if not self.handleStatics(webServer):
            self.prepareWSGI(method)
            name = config.getItemOfHost("djangoRoot")
            response = self.runWSGI(config, name)
            self.handleContent(response)

    def prepareWSGI(self, method, webServer):
        '''Does common things for calling WSGI.
        @param config:    configuration data
        @param method:    get or post
        '''
        environment = {}
        self.buildMeta(method, webServer, environment)
        # e.g. "GET /home HTTP/1.1"
        pathInfo = re.split(' ', webServer.raw_requestline)[1]
        script = self.getItem('documentRoot') + '/wsgi.py'
        environment['REQUEST_METHOD'] = method
        environment['SCRIPT_FILENAME'] = script
        ix = pathInfo.find('?')
        environment['QUERY_STRING'] = '' if ix < 0 else pathInfo[ix+1:]
        environment['REQUEST_URI'] = pathInfo
        environment['SCRIPT_NAME'] = "/wsgi.py"
        environment['PATH_INFO'] = pathInfo
        webServer._wsgiEnvironment = environment

    def handleDjinn(self, method, webServer):
        '''Handles a Djinn application.
        Djinn is a replacement of Django.
        @param method: 'get' or 'post'
        @param webServer: the web server instance
        '''
        if not self.handleStatics(webServer):
            if self._application != None:
                self.prepareWSGI(method, webServer)
                response = self._application.__call__(webServer._wsgiEnvironment, webServer.startResponse)
                if response == None:
                    webServer.send_error(404, "Address not found: {:s}"
                        .format(webServer.path))
                else:
                    webServer.handleContent(response)
        pass

class Config:
    '''Manages the configuration data
    '''
    def __init__(self):
        '''Constructor.
        '''
        self._debug = False
        self._logLevel = logging.WARNING
        self._verbose = False
        self._daemon = False
        self._translatePathInfo = None
        self._port = 80
        self._listenerIp = "127.0.0.86"
        self._hosts = dict()
        self._userId = None
        self._groupId = None
        self._hosts['localhost'] = Host('localhost', self)
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
            'js' : ' application/x-javascript',
            'svg' : 'image/svg+xml',
            'ttf' : 'application/octet-stream'
        }
        self._fileMatcher = re.compile(r"[.](css|html|htm|txt|png|jpg|jpeg|gif|svg|ico|js|ttf)$", re.I)
        self._server = dict()
        self._environ = os.environ
        os.environ.clear()

    def getName(self, currentHost):
        rc = currentHost._name if currentHost != None else 'localhost'
        return rc

    def postRead(self):
        '''Does initialization code after reading the configuration.
        '''
        item = 'cgiExt'
        extDefault = 'php'
        if item in self._hosts['localhost']._items:
            extDefault = self._hosts['localhost']._items[item]
        for hostname in self._hosts:
            ext = extDefault
            host = self._hosts[hostname]
            if item in host._items:
                ext = host._items[item]
            pattern = "(.*[.](%s))((/[^?]+)?(\?(.*)))?" % ext
            host._urlMatcher = re.compile(pattern)
            host.extendPythonPath()
            if host.isDjinn():
                module = host.importModule("djinnUrls")
                if module != None:
                    host._application = djinn.wsgihandler.WSGIHandler(
                            module.getPatterns())


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
            itemMatcher = re.compile(
                r'(documentRoot|cgiProgram|cgiArgs|cgiExt|index|djangoRoot|djinnUrls|djinnBase|pythonPath|wsgiStaticPagePrefix)$')
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
                        host = Host(vhost, self)
                        self._hosts[vhost] = host

                    if itemMatcher.match(var) != None:
                        host._items[var] = value
                        if var == 'documentRoot' and not os.path.isdir(value):
                            sayError('%s-%d: %s is not a directory' % (name, lineNo, value))
                        elif var == 'cgiProgram' and not (
                                value == "django" or value == "WSGI"
                                or value == "djinn"
                                or os.path.isfile(value)):
                            sayError('%s-%d: CGI not found: %s' % (name, lineNo, value))
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
                        elif var == 'user':
                            no = None
                            try:
                                no = pwd.getpwnam(value)[2]
                            except:
                                no = None
                            if no == os.getuid():
                                value += " unused"
                            else:
                                self._userId = no
                            say("%{:s}={:s}".format(var, value))
                        elif var == 'group':
                            no = None
                            try:
                                no = grp.getgrnam(value)[2]
                            except:
                                no = None
                            if no == os.getgid():
                                value += " unused"
                            else:
                                self._groupId = no
                            say('%s=%s' % (var, value))
                        elif var == "listeningIp":
                            self._listenerIp = value
                            say('%s=%s' % (var, value))
                        elif var == 'debug':
                            self._debug = re.match(r'[tT1]', value)
                        elif var == 'loglevel':
                            matcher = re.match(r'(\d+)', value)
                            if matcher == None:
                                sayError("%s-%d: log level must be a number: %s"
                                    (name, lineNo, value))
                            else:
                                level = int(matcher.group(1))
                                if level < 0 or level % 10 != 0 or level > logging.CRITICAL:
                                    sayError("%s-%d: wrong level: {:d}. Use 0, 10, 20..50."
                                             .format(name, lineNo, level))
                                else:
                                    self._logLevel = int( level)

                        else:
                            sayError("%s-%d: unknown var: %s" % (name, lineNo, var))
            handle.close()

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

    def splitUrlRaw(self, method, path, script, environment):
        '''Splits the URL into its parts.
        The parts will be stored in <code>environment</code>.
        @param path: the url without protocol, host and port
        @param script: the script name (in local filesystem)
        @param environment: a dictionary containing the values to change
        '''
        environment['REQUEST_METHOD'] = method
        environment['SCRIPT_FILENAME'] = script
        environment['QUERY_STRING'] = ''
        environment['REQUEST_URI'] = path
        environment['SCRIPT_NAME'] = "/" + os.path.basename(script)
        environment['PATH_INFO'] = path

    def getCurrentHost(self, host):
        '''Sets the current virtual host.
        @param host: the host expression, e.g. abc:8086
        '''
        hostinfo = re.split(':', host)
        hostname = hostinfo[0]
        port = hostinfo[1] if len(hostinfo) > 1 else str(self._port)
        port = 80 if len(port) == 0 else int(port)
        if not hostname in self._hosts:
            hostname = 'localhost'
        rc = self._hosts[hostname]
        rc._port = port
        logger.debug("Virtual host {:s} recognized as {:s}:{:d}".format(
                host, hostname, port))
        return rc


class WebServer(BaseHTTPServer.BaseHTTPRequestHandler):
    '''Implements a web server.
    '''

    def send_error(self, code, message=None):
        self.error_message_format = '''<html>
<head>
<title>Error response</title>
<head>
<body>
<h1>Error response</h1>
<p>Error code %(code)d
<p>Message:
<pre>
%(message)s
</pre>
</body>
</html>
'''
        BaseHTTPServer.BaseHTTPRequestHandler.send_error(self, code, message)

    def startResponse(self, status, responseHeaders):
        '''Handler of the header. Is part of the WSGI.
        @param status: the HTTP status of the response, e.g. '200 OK'
        @param responseHeaders: a list of tuples containing the HTTP headers,
                            e.g. [('Content-Type', 'text/plain'), ...]
        '''
        statusNo = int(status[0:3])
        self.send_response(statusNo)
        for pair in responseHeaders:
            self.send_header(pair[0], pair[1])

    def sendFile(self, filename, mimeType):
        '''Sends a file to the browser:
        '''
        if not os.path.exists(filename):
            self.send_error(404,'File not Found: %s' % self.path)
        else:
            if mimeType == None:
                mimeType = 'application/octet-stream'
            handle = open(filename)
            self.send_response(200)
            self.send_header('Content-type', mimeType)
            self.end_headers()
            self.wfile.write(handle.read())
            handle.close()

    def handleContent(self, response):
        '''Handles the content of a HttpResponse.
        @param response:    a HttpResponse (or similar) instance
        '''
        if hasattr(response, 'content'):
            content = response.content.encode("utf-8")
            length = len(content)
            self.send_header('Content-Length', str(length))
            # @ToDo: writing cookies
            self.end_headers()
            self.wfile.write(content)
        elif type(response) == list:
            total = 0
            for line in response:
                total += len(line)
            self.send_header('Content-Length', str(total))
            # @ToDo: writing cookies
            self.end_headers()
            for line in response:
                self.wfile.write(line)
        else:
            self.end_headers()


    def do_GET(self):
        '''Handles a GET request.
        '''
        self.do_it('get')

    def do_it(self, method):
        '''Handles a request (GET or POST).
        @param method: 'get' or 'post'
        '''
        #env = os.environ
        global config
        host = self.headers.dict['host']
        currentHost = config.getCurrentHost(host)
        if self.path == '/':
            self.path = '/' + currentHost.getItem('index', "home")
        say(self.raw_requestline[0:-1])
        try:
            if currentHost.isDjango():
                currentHost.handleDjango(method, self)
            elif currentHost.isDjinn():
                currentHost.handleDjinn(method, self)
            elif currentHost.isWSGI():
                currentHost.handleWSGI(method, self)
            elif currentHost.isCgi(self.path):
                currentHost.runCgi(method, self)
            else:
                filename = config.getItemOfHost('documentRoot') + self.path
                if not os.path.exists(filename):
                    log("file not found: " + filename)
                else:
                    mimeType = config.getMimeType(filename)
                    self.sendFile(filename, mimeType)

        except IOError:
            msg = traceback.format_exc()
            self.send_error(404, "File Not Found: {:s}\n{:s}".format(self.path, msg))
        except:
            logger.exception("page creation failed")
            content = "Server error in {:s}\n{:s}".format(
                self.path, traceback.format_exc())
            self.send_error(500, content)


    def do_POST(self):
        '''Handles a POST request.
        '''
        self.do_it('post')

def usage(msg = None):
    say('''
pywwetha %s
A simple webserver for static html and CGI.

Usage: pywwetha.py <opts>
<opt>:
--verbose
    Issues some messages
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
            ''' % (VERSION_EXTENDED, VERSION))
    if msg != None:
        sayError(msg)
    sys.exit(1)

def main():
    '''Do the real things.
    '''
    global config
    config = None
    fnLog = "/tmp/pywwetha.log"
    if os.path.exists(fnLog):
        os.unlink(fnLog)
    level = logging.DEBUG if "DEBUG" in os.environ else logging.ERROR
    logging.basicConfig(filename=fnLog, level=level)
    config = Config()
    logLevel = config._logLevel
    doCheck = False
    for ii in xrange(1, len(sys.argv)):
        if sys.argv[ii] == '--daemon':
            config._daemon = True
        elif sys.argv[ii] == '--verbose':
            say("depricated: --verbose")
        elif sys.argv[ii] == '--debug':
            config._debug = True
            logLevel = logging.DEBUG
        elif sys.argv[ii] == '--check-config':
            doCheck = True
            return
        elif sys.argv[ii] == '--version':
            say(VERSION_EXTENDED)
            return
        elif sys.argv[ii] == '--version-short':
            say(VERSION)
            return
        elif sys.argv[ii] == '--help':
            usage()
        else:
            usage('unknown option: ' + sys.argv[ii])
    if doCheck and logLevel < logging.WARNING:
        logLevel = logging.WARNING
    if logLevel < logging.ERROR:
        for item in logging.root.handlers:
            item.setLevel(logLevel)
        logger.setLevel(logLevel)
    if not config._daemon:
        handler = logging.StreamHandler()
        handler.setLevel(logLevel)
        logger.addHandler(handler)
    if doCheck:
        # read again with error reporting:
        config = Config()

    dateStr = time.ctime(time.time())
    say("Starting pywwetha with log level {:s} {:s}".format(
        logging.getLevelName(logLevel), dateStr))
    try:
        if config._listenerIp == None:
            config._listenerIp = ""
        server = BaseHTTPServer.HTTPServer((config._listenerIp, config._port), WebServer)
        if config._groupId != None:
            say("changing gid: {:d}".format(config._groupId))
            os.setregid(config._groupId, config._groupId)
        if config._userId != None:
            say("changing uid: {:d}".format(config._userId))
            os.setreuid(config._userId, config._userId)
        say("listening on {:s}:{:d} ...".format(config._listenerIp, config._port))
        server.serve_forever()
    except KeyboardInterrupt:
        if not config._daemon:
            say('Stopping pywwetha...')
        server.socket.close()
    except Exception as e:
        sayError('failed with port={:d}: {:s}'.format(config._port, repr(e)))

if __name__ == '__main__':
    main()
