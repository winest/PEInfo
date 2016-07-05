#pip3 install configparser, pefile, xlsxwriter, and chardet
import os
import sys
import logging
import traceback
import configparser
import fnmatch
import time
import xlsxwriter

from HandleBasicInfo import *



if __name__ == "__main__" :
    logging.basicConfig( format="[%(asctime)s][%(levelname)s][%(process)04X:%(thread)04X][%(filename)s][%(funcName)s_%(lineno)d]: %(message)s" , level=logging.DEBUG )

    if len( sys.argv ) <= 1 :
        print( "Usage: {} <FileOrDirectoryPath>".format( os.path.basename( sys.argv[0] ) ) )
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
        g_setFilePaths = set()
        strPath = sys.argv[1]
        print( "Search {0:s} under \"{1:s}\"".format(g_config["General"]["FilenameFilter"],strPath) )
        if ( os.path.isfile(strPath) ) :
            if fnmatch.fnmatch( strPath , g_config["General"]["FilenameFilter"] ) :
                g_setFilePaths.add( strPath )
        elif ( os.path.isdir(strPath) ) :
            for dirpath , dirnames , filenames in os.walk( strPath ) :
                for filename in fnmatch.filter( filenames , g_config["General"]["FilenameFilter"] ) :
                    g_setFilePaths.add( os.path.join( dirpath , filename ) )
        else :
            raise ValueError( "Neither file nor directory" , strPath )

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
        HandleBasicInfo( g_setFilePaths , g_config , g_excel , g_excelFmt , g_strMainDir )

        #Close the excel
        if g_bWriteExcel :
            g_excel.close()
    except Exception as ex :
        print( traceback.format_exc() )
        logging.exception( ex )
    print( "Press any key to leave" )
    input()