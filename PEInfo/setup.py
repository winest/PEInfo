from distutils.core import setup
import py2exe

setup(
    console = [{"script" : "PEInfo.py"}] ,
    zipfile = None ,
    options = { 
                  "py2exe" : {
                                 "bundle_files" : 1 ,
                                 "compressed" : True ,
                                 "includes" : ["xlsxwriter" , "chardet" , "pefile" , "requests"]
                             }
              }
)