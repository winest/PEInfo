import os
import sys
import logging
import traceback
import configparser
import time
import re
import json
import urllib.request
import http.client
import xlsxwriter

from collections import defaultdict
from gzip import GzipFile

from ExcelInfo import *
from HashInfo import *



class CDetux :
    def __init__( aSelf , aApiKey ) :
        aSelf.m_dictCache = {}    #<key , value> = <hash , hash properties dict>
        aSelf.m_strRawResult = None
        aSelf.m_strHttpHeaders = { "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36" ,
                                   "Accept-Encoding": "gzip, deflate" }
        aSelf.m_strApiKey = aApiKey

        aSelf.reMd5 = re.compile( "^[a-fA-F0-9]{32}$" );
        aSelf.reSha1 = re.compile( "^[a-fA-F0-9]{40}$" );
        aSelf.reSha256 = re.compile( "^[a-fA-F0-9]{64}$" );

    def Query( aSelf , aHash , aTimeout = 10 , aRetryCnt = 5 ) :
        if not aHash :
            return None
        elif aHash in aSelf.m_dictCache.keys() :
            logging.info( "{}: Cache hit".format(aHash) )
            return aSelf.m_dictCache[aHash]
        else :
            strHashType = ""
            if aSelf.reSha256.match(aHash) :
                strHashType = "sha256"
            elif aSelf.reSha1.match(aHash) :
                strHashType = "sha1"
            elif aSelf.reMd5.match(aHash) :
                strHashType = "md5"
            else :
                logging.error( "Hash type is invalid" )
                return None

            while aRetryCnt > 0 :
                try :
                    params = urllib.parse.urlencode( { "api_key" : aSelf.m_strApiKey , strHashType : aHash } )
                    req = urllib.request.Request( "https://detux.org/api/report.php" , headers = aSelf.m_strHttpHeaders )
                    rsp = urllib.request.urlopen( req , params.encode("utf-8") , aTimeout )
                    strEncoding = rsp.info().get( "Content-Encoding" )
                    if strEncoding and strEncoding.lower() == "gzip" :
                        result = GzipFile( fileobj = rsp ).read()
                    else :
                        result = rsp.read()
                    result = result.decode( "utf-8" ) if result else "<NULL>"
                    aSelf.m_strRawResult = result
                    return aSelf.Parse( aHash , result )
                except ( urllib.error.HTTPError , urllib.error.URLError , http.client.HTTPException ) as err :
                    logging.warning( err )
                    aRetryCnt -= 1
                except Exception as err :
                    print( traceback.format_exc() )
                    logging.exception( err )
                    break
            return None

    def GetRawResult( aSelf ) :
        return aSelf.m_strRawResult

    def Parse( aSelf , aHash , aDetuxRet ) :
        if aHash in aSelf.m_dictCache.keys() :
            return aSelf.m_dictCache[aHash]
        elif "<NULL>" == aDetuxRet :
            return None
        else :
            d = defaultdict( set )
            parsed = json.loads( aDetuxRet )
            
            #{"status":"0","message":"No result found"}
            #{"status":"1","message":{"protocol":["UDP"],"ip":["4.2.2.2"],"filetype":"ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, stripped","tag":""}}
            if "status" in parsed :
                d["status"] = parsed["status"]

            if "message" in parsed and parsed["message"] != "No result found":
                parsedMessage = parsed["message"]
                lsSimpleFields = [ "filetype" , "tag" , "sample_filepath" , "pcap_filepath" , "orig_file_name" , "md5" , "sha1" , "sha256" ]
                for field in lsSimpleFields :
                    if field in parsedMessage and 0 < len(parsedMessage[field]) :
                        d[field] = parsedMessage[field]

            aSelf.m_dictCache[aHash] = d
            return d





def HandleDetux( aConfig , aExcel , aExcelFmts ) :
    #Get config
    bWriteExcel = ( False != aConfig.getboolean( "General" , "WriteExcel" ) )
    nTimeout = aConfig.getint( "General" , "QueryTimeout" ) / 1000
    nMaxRetryCnt = aConfig.getint( "General" , "QueryRetryCnt" )
    bWriteRaw = ( False != aConfig.getboolean( "Debug" , "WriteRaw" ) )
    strApiKey = aConfig.get( "ApiKeys" , "Detux" )
    if ( 32 != len(strApiKey) ) :
        raise ValueError( "Detux's API key is incorrect, please check your configuration in PEInfo.ini" )

    #Set interesting fields information
    SHEET_NAME = "Detux"
    sheetInfo = CExcelSheetInfo( SHEET_NAME )
    sheetInfo.AddColumn( "md5"              , CExcelColumnInfo( 0 , "md5" , 20 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "sha1"             , CExcelColumnInfo( 1 , "sha1" , 20 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "sha256"           , CExcelColumnInfo( 2 , "sha256" , 20 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "status"           , CExcelColumnInfo( 3 , "status" , 10 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "orig_file_name"   , CExcelColumnInfo( 4 , "orig_file_name" , 40 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "filetype"         , CExcelColumnInfo( 5 , "filetype" , 40 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "tag"              , CExcelColumnInfo( 6 , "tag" , 20 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "sample_filepath"  , CExcelColumnInfo( 7 , "sample_filepath" , 40 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "pcap_filepath"    , CExcelColumnInfo( 8 , "pcap_filepath" , 40 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "Raw"              , CExcelColumnInfo( 9 , "Raw" , 100 , aExcelFmts["WrapTop"] ) )

    if bWriteExcel :
        #Initialize sheet by sheetInfo
        sheet = None
        for sheet in aExcel.worksheets() :
            if sheet.get_name() == SHEET_NAME :
                break
        if sheet == None or sheet.get_name() != SHEET_NAME :
            sheet = aExcel.add_worksheet( SHEET_NAME )

        #Set column layout in excel
        for strColName , info in sheetInfo.GetColumns().items() :
            sheet.set_column( "{}:{}".format(info.strColId,info.strColId) , info.nColWidth , info.strColFormat )



    #Start to get hash information
    uCount = 0
    detux = CDetux( strApiKey )    
    for hashItem in CHashes().ValuesCopy() :
        #Write default value for all fields
        for info in sheetInfo.GetColumns().values() :
            sheet.write( uCount + 1 , info.nColIndex , "<NULL>" )

        #Write the hash we are querying to excel
        strHash = None
        if hashItem.md5 :
            strHash = hashItem.md5
            if bWriteExcel :
                sheet.write( uCount + 1 , sheetInfo.GetColIndexByName( "md5" ) , strHash )
        if hashItem.sha1 :
            strHash = hashItem.sha1
            if bWriteExcel :
                sheet.write( uCount + 1 , sheetInfo.GetColIndexByName( "sha1" ) , strHash )
        if hashItem.sha256 :
            strHash = hashItem.sha256
            if bWriteExcel :
                sheet.write( uCount + 1 , sheetInfo.GetColIndexByName( "sha256" ) , strHash )

        #Start to query
        print( "Checking Detux for {}".format( strHash ) )        
        result = detux.Query( strHash , nTimeout , nMaxRetryCnt )
        if result :
            strMd5 = result["md5"] if "md5" in result else None
            strSha1 = result["sha1"] if "sha1" in result else None
            strSha256 = result["sha256"] if "sha256" in result else None
            CHashes().Add( CHashItem(aMd5 = strMd5 , aSha1 = strSha1 , aSha256 = strSha256) )

            for key , value in result.items() :
                print( "    {:16}{}".format( key , value ) )
                if bWriteExcel :
                    nColIndex = -1
                    for strColName , info in sheetInfo.GetColumns().items() :
                        if info.reColName.search( key ) != None :
                            nColIndex = info.nColIndex
                            break
                    if isinstance( value , list ) :
                        sheet.write( uCount + 1 , nColIndex , os.linesep.join(value) )
                    else :
                        sheet.write( uCount + 1 , nColIndex , value )
            if bWriteExcel and bWriteRaw :
                sheet.write( uCount + 1 , sheetInfo.GetColumn("Raw").nColIndex , detux.GetRawResult() )

        print( "\n" )
        uCount = uCount + 1
        


    #Make an excel table so one can find correlations easily
    if bWriteExcel :
        lsColumns = []
        for i in range ( 0 , len(sheetInfo.GetColumns()) ) :
            lsColumns.append( { "header" : sheetInfo.GetColNameByIndex(i) } )
        sheet.add_table( "A1:{}{}".format(chr( ord('A')+len(sheetInfo.GetColumns())-1 ) , uCount+1) , 
                         { "header_row" : True , "columns" : lsColumns } 
                       )
        sheet.freeze_panes( 1 , 1 )