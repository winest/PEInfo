#pip3 install configparser pefile xlsxwriter chardet
import os
import sys
import logging
import traceback
import configparser
import time
import fnmatch
import xlsxwriter
import argparse

from HashInfo import *

from HandleBasicInfo import *
from HandleVirusTotal import *
from HandleDetux import *



if __name__ == "__main__" :
    logging.basicConfig( format="[%(asctime)s][%(levelname)s][%(process)04X:%(thread)04X][%(filename)s][%(funcName)s_%(lineno)d]: %(message)s" , level=logging.DEBUG )
    strMainDir = os.path.dirname( sys.argv[0] )
    if ( 0 == len( strMainDir ) ) :
        strMainDir = "."
    strMainPy = os.path.basename( sys.argv[0] )

    #Parameter parsing and checking
    cmdParser = argparse.ArgumentParser( description="====================================\n"\
                                                     "Show PE information by winest\n"\
                                                     "====================================" , 
                                         epilog="Example: python3 {} \"C:\\Windows\\System32\\calc.exe;a03fe2d6566d7e9c167216acb55d3f6c\"\n"
                                                "         python3 {} -f \"FileList.txt\"".format( strMainPy , strMainPy ) ,
                                         formatter_class=argparse.RawDescriptionHelpFormatter )
    cmdParser.add_argument( "PathsOrHashes" , nargs="?" , help="File Path/Directory Path/Hashes separated by \";\"" )
    cmdParser.add_argument( "-f" , "--file" , dest="FileWithList" , type=open , help="File which contains file path/directory path/hash for each line" )
    args = cmdParser.parse_args()

    #Must enter either file or path/hash
    if args.FileWithList == None and args.PathsOrHashes == None :
        cmdParser.print_help()
        print( "\nPress any key to leave" )
        input()
        sys.exit( 0 )

    
        
    try :
        print( "Load config from {}\\{}".format( strMainDir , "PEInfo.ini" ) )
        g_config = configparser.ConfigParser()
        g_config.read( "{}\\{}".format( strMainDir , "PEInfo.ini" ) )
        logging.getLogger().setLevel( g_config["Debug"]["LogLevel"] )
    
        #Get the list of file or hash
        setFilePaths = set()
        reMd5 = re.compile( "^[a-fA-F0-9]{32}$" )
        reSha1 = re.compile( "^[a-fA-F0-9]{40}$" )
        reSha256 = re.compile( "^[a-fA-F0-9]{64}$" )

        if args.FileWithList :
            for line in args.FileWithList.readlines() :
                strPathOrHash = line.strip()
                if ( os.path.isfile(strPathOrHash) ) :
                    if fnmatch.fnmatch( strPathOrHash , g_config["General"]["FilenameFilter"] ) :
                        setFilePaths.add( strPathOrHash )
                elif ( os.path.isdir(strPathOrHash) ) :
                    print( "Search {0:s} under \"{1:s}\"".format(g_config["General"]["FilenameFilter"],strPathOrHash) )
                    for strDirPath , lsDirNames , lsFileNames in os.walk( strPathOrHash ) :
                        for strFileName in fnmatch.filter( lsFileNames , g_config["General"]["FilenameFilter"] ) :
                            setFilePaths.add( os.path.join( strDirPath , strFileName ) )
                elif reMd5.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = strPathOrHash , aSha1 = None , aSha256 = None ) )
                elif reSha1.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = None , aSha1 = strPathOrHash , aSha256 = None ) )
                elif reSha256.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = None , aSha1 = None , aSha256 = strPathOrHash ) )
                else :
                    raise ValueError( "Invalid input parameter: {}".format(hash) )

        if args.PathsOrHashes :
            for strPathOrHash in args.PathsOrHashes.split( ";" ) :
                if ( os.path.isfile(strPathOrHash) ) :
                    if fnmatch.fnmatch( strPathOrHash , g_config["General"]["FilenameFilter"] ) :
                        setFilePaths.add( strPathOrHash )
                elif ( os.path.isdir(strPathOrHash) ) :
                    print( "Search {0:s} under \"{1:s}\"".format(g_config["General"]["FilenameFilter"],strPathOrHash) )
                    for strDirPath , lsDirNames , lsFileNames in os.walk( strPathOrHash ) :
                        for strFileName in fnmatch.filter( lsFileNames , g_config["General"]["FilenameFilter"] ) :
                            setFilePaths.add( os.path.join( strDirPath , strFileName ) )
                elif reMd5.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = strPathOrHash , aSha1 = None , aSha256 = None ) )
                elif reSha1.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = None , aSha1 = strPathOrHash , aSha256 = None ) )
                elif reSha256.match( strPathOrHash ) :
                    CHashes().Add( CHashItem( aMd5 = None , aSha1 = None , aSha256 = strPathOrHash ) )
                else :
                    raise ValueError( "Invalid input parameter: {}".format(hash) )

            

        #Create excel if needed
        g_bWriteExcel = ( False != g_config.getboolean( "General" , "WriteExcel" ) )
        g_excel = None
        g_excelFmt = { "Top" : None , "Vcenter" : None , "WrapTop" : None , "WrapVcenter" : None }
        if g_bWriteExcel :
            strOutputDir = "{}\\Output".format( strMainDir )
            os.makedirs( strOutputDir , exist_ok=True )
            g_excel = xlsxwriter.Workbook( "{}\\PEInfo-{}.xlsx".format(strOutputDir , time.strftime("%Y%m%d_%H%M%S")) )
            g_excelFmt["Top"] = g_excel.add_format( {"valign" : "top"} )
            g_excelFmt["Vcenter"] = g_excel.add_format( {"valign" : "vcenter"} )
            g_excelFmt["WrapTop"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "top"} )
            g_excelFmt["WrapVcenter"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "vcenter"} )



        #Start to get file information
        if ( len(setFilePaths) ) :
            HandleBasicInfo( setFilePaths , g_config , g_excel , g_excelFmt , strMainDir )

        if ( False != g_config.getboolean( "Features" , "VirusTotal" ) ) :
            HandleVirusTotal( g_config , g_excel , g_excelFmt )

        if ( False != g_config.getboolean( "Features" , "Detux" ) ) :
            HandleDetux( g_config , g_excel , g_excelFmt )



        #Close the excel
        if g_bWriteExcel :
            g_excel.close()
    except Exception as ex :
        print( traceback.format_exc() )
        logging.exception( ex )
    print( "Press any key to leave" )
    input()