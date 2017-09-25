#pip3 install configparser pefile xlsxwriter chardet
import os
import sys
import logging
import traceback
import configparser
import time
import fnmatch
import xlsxwriter

from HashInfo import *

from HandleBasicInfo import *
from HandleDetux import *
from HandleVirusTotal import *



if __name__ == "__main__" :
    logging.basicConfig( format="[%(asctime)s][%(levelname)s][%(process)04X:%(thread)04X][%(filename)s][%(funcName)s_%(lineno)d]: %(message)s" , level=logging.DEBUG )

    if len( sys.argv ) <= 1 :
        print( "Usage: {} <File Path/Directory Path/Hashes Separated By \";\">".format( os.path.basename( sys.argv[0] ) ) )
        print( "Press any key to leave" )
        input()
        sys.exit( 0 )

    g_strMainDir = os.path.dirname( sys.argv[0] )
    if ( 0 == len( g_strMainDir ) ) :
        g_strMainDir = "."
        
    try :
        print( "Load config from {}\\{}".format( g_strMainDir , "PEInfo.ini" ) )
        g_config = configparser.ConfigParser()
        g_config.read( "{}\\{}".format( g_strMainDir , "PEInfo.ini" ) )
        logging.getLogger().setLevel( g_config["Debug"]["LogLevel"] )
    
        #Get the list of filenames
        setFilePaths = set()
        reMd5 = re.compile( "^[a-fA-F0-9]{32}$" )
        reSha1 = re.compile( "^[a-fA-F0-9]{40}$" )
        reSha256 = re.compile( "^[a-fA-F0-9]{64}$" )

        for strPathOrHash in sys.argv[1].split( ";" ) :
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
            strOutputDir = "{}\\Output".format( g_strMainDir )
            os.makedirs( strOutputDir , exist_ok=True )
            g_excel = xlsxwriter.Workbook( "{}\\PEInfo-{}.xlsx".format(strOutputDir , time.strftime("%Y%m%d_%H%M%S")) )
            g_excelFmt["Top"] = g_excel.add_format( {"valign" : "top"} )
            g_excelFmt["Vcenter"] = g_excel.add_format( {"valign" : "vcenter"} )
            g_excelFmt["WrapTop"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "top"} )
            g_excelFmt["WrapVcenter"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "vcenter"} )

        #Start to get file information
        if ( len(setFilePaths) ) :
            HandleBasicInfo( setFilePaths , g_config , g_excel , g_excelFmt , g_strMainDir )

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