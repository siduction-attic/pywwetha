# coding=utf-8
'''
Created on 07.09.2013

@author: hm
'''
import unittest

from source.djingis import Djingis, decodeUrl

class Test(unittest.TestCase):


    def setUp(self):
        environ = { "PATHINFO" : "/installer/home", 
                   "QUERY_STRING" : "abc=def&song=%DCber+den+Wolken"}
        self._request = Djingis(None, environ)


    def tearDown(self):
        pass


    def testDecodeUrl(self):
        self.assertEqual("ä öü ÄÖÜ ß", decodeUrl(u"%E4+%F6%fc+%C4%d6%DC+%DF"))
        self.assertEqual("abc", decodeUrl("abc"))

    def testBase(self):
        self.assertEquals("def", self._request.GET["abc"])
        self.assertEquals(u"Über den Wolken", self._request.GET["song"])
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testDecodeUrl']
    unittest.main()