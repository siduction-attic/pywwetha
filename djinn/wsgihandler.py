'''
Created on 07.09.2013

@author: hm
'''

import logging
from django.http import HttpResponse, HttpResponsePermanentRedirect
logger = logging.getLogger(__name__)

urlPatterns = []

def findUrl(url):
    '''Returns the first matching UrlInfo object.
    @param url    the url to search
    @return:     None: not found
                 otherwise: an UrlInfo instance
    '''
    global urlPatterns
        
    rc = None
    if url.startswith("/"):
        url = url[1:]
    for item in urlPatterns:
        if item._regExpr.search(url):
            rc = item
            break
    return rc

 
def decodeUrl(url):
    '''Decodes the special characters in an URL into normal string.
    Special chars are %hh where hh is a 2 digit hexadecimal number.
    @param url:     the url to decode
    @return:        the decoded string
    '''
    rc = ""
    url = url.replace("+", " ")
    ix = last = 0
    while ix >= 0 and last < len(url):
        ix = url.find("%", last)
        if ix < 0:
            rc += url[last:]
        else:
            rc += url[last:ix]
            hexNumber = url[ix+1:ix+3]
            cc = int(hexNumber, 16)
            rc += chr(cc)
            last = ix + 3
    return rc


class WSGIHandler(object):
    '''
    Implements the a simple replacement of Django which implements the 
    Web Server Gateway Interface (WSGI)
    '''


    def __init__(self):
        '''Constructor.
        '''
        self._environ = None
        self._request = None
        
           
    def putCookies(self, cookies):
        '''Write the cookies to the client.
        @param cookies:    a dictionary with the cookies
        '''
        pass
    
    def writeContent(self, content):
        '''Writes the content of the current page to the client.
        @param content:     the page content (normally HTML)
        '''
        pass
    
    def handle(self, application, documentRoot, startResponse):
        '''Handles a HTTP request.
        @param application:    the name of the application (is the virtual host)
        @param documentRoot:   the base path of the application
        '''
        rc = None
        if not "PATH_INFO" in self._environ:
            logger.error("missing PATH_INFO")
        else:
            url = self._environ["PATH_INFO"]
            headers = []
            info = findUrl(url)
            if info == None:
                logger.error("Page not found: " + url)
            else:
                handler = info._urlHandler
                self._request.documentRoot = documentRoot
                rc = handler.__call__(self._request)
                # rc is a HttpResponse or a HttpResponsePermanentRedirect
                if isinstance(rc, HttpResponse):
                    # CONTENT_LENGTH will be added by the caller! 
                    self.content = rc.content
                    header = ("Content-Type", "text/html")
                    headers.append(header)
                elif isinstance(rc, HttpResponsePermanentRedirect):
                    header = ("Location", rc.absUrl)
                    headers.append(header)
                startResponse.__call__(rc.status, headers)
        return rc
            
    def __call__(self, environ, startResponse):
        '''the main method of the WSGI.
        @param environ:        the parameters as a dictionary
        @param startResponse:  a callable starting the HTTP response.
                               def startResponse(status, headers)
                               e.g. startResponse("200 OK", [("LEN", "20")]
        '''
        
        application = environ["HTTP_HOST"]
        docRoot = environ["DOCUMENT_ROOT"]
        self._environ = environ
        self._request = WSGIRequest(environ)
        
        rc = self.handle(application, docRoot, startResponse)
        return rc
        
class WSGIRequest:
    '''Implements the request instance expected from WSGI applications.
    '''
    def __init__(self, environ):
        self._cookies = {}
        self.META = environ
        self.GET = {}
        self.POST = {}
        self.COOKIES = {}
        self.buildGET(environ)
        self.buildCookies(environ)

    def buildGET(self, environ):
        '''Builds the GET dictionary from an URL.
        @param environ:    the data from the client
        '''
        self.GET = {}
        if "QUERY_STRING" in environ:
            queryString = environ["QUERY_STRING"]
            items = queryString.split("&")
            for varDef in items:
                if varDef == "":
                    continue
                if varDef.find("=") > 0:
                    (name, value) = varDef.split("=", 1)
                else:
                    (name, value) = (varDef, "")
                name = decodeUrl(name)
                value = decodeUrl(value)
                self.GET[name] = value
            
    def buildCookies(self, environ):
        '''Fills the dictionary COOKIES.
        @param httpCookies: the http-url of the cookies
        '''
        self.COOKIES = {}
        if "HTTP_COOKIE" in environ:
            queryString = environ["HTTP_COOKIE"]
        
            