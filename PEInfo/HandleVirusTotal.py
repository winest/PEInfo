#pip3 install configparser xlsxwriter
import os
import sys
import logging
import traceback
import configparser
import time
import re
import json
import requests
import http.client
import xlsxwriter

from collections import defaultdict
from gzip import GzipFile

from ExcelInfo import *



class CVirusTotal :
    def __init__( aSelf , aApiKey ) :
        aSelf.m_dictCache = {}    #<key , value> = <hash , hash properties dict>
        aSelf.m_strRawResult = None
        aSelf.m_strHttpHeaders = { "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36" ,
                                   "Accept-Encoding": "gzip, deflate" }
        aSelf.m_strApiKey = aApiKey

    def Query( aSelf , aHash , aTimeout = 10 , aRetryCnt = 5 ) :
        if not aHash :
            return None
        elif aHash in aSelf.m_dictCache.keys() :
            logging.info( "{}: Cache hit".format(aHash) )
            return aSelf.m_dictCache[aHash]
        else :
            while aRetryCnt > 0 :
                try :
                    params = { "apikey" : aSelf.m_strApiKey , "resource" : aHash }
                    rsp = requests.get( "https://www.virustotal.com/vtapi/v2/file/report" , params = params , headers = aSelf.m_strHttpHeaders )
                    if rsp.ok and 0 == len(rsp.text) : #Free API can only query 4 times per minute
                        print( "Seems quota reach...sleep 30 seconds" )
                        time.sleep( 30 )
                        continue

                    result = rsp.json()
                    aSelf.m_strRawResult = rsp.text
                    return aSelf.Parse( aHash , result )
                except requests.exceptions.RequestException as err :
                    logging.warning( err )
                    aRetryCnt -= 1
                except Exception as err :
                    print( traceback.format_exc() )
                    logging.exception( err )
                    break
            return None

    def GetRawResult( aSelf ) :
        return aSelf.m_strRawResult

    def Parse( aSelf , aHash , aVirusTotalRet ) :
        if aHash in aSelf.m_dictCache.keys() :
            return aSelf.m_dictCache[aHash]
        elif None == aVirusTotalRet :
            return None
        else :
            d = defaultdict( set )
            parsed = aVirusTotalRet
            
            #{
            #'response_code': 1,
            #'verbose_msg': 'Scan finished, scan information embedded in this object',
            #'resource': '99017f6eebbac24f351415dd410d522d',
            #'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
            #'md5': '99017f6eebbac24f351415dd410d522d',
            #'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
            #'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
            #'scan_date': '2010-05-15 03:38:44',
            #'positives': 40,
            #'total': 40,
            #'scans': {
            #   'Avast': {'detected': false, 'version': '4.8.1351.0', 'result': null, 'update': '20100514'},
            #   'NOD32': {'detected': true, 'version': '5115', 'result': 'a variant of Win32/Qhost.NTY', 'update': '20100514'},
            #   .
            #   .
            #   .
            #   'Symantec': {'detected': true, 'version': '20101.1.0.89', 'result': 'Trojan.KillAV', 'update': '20100515'},
            #   'TrendMicro-HouseCall': {'detected': true, 'version': '9.120.0.1004', 'result': 'TROJ_VB.JVJ', 'update': '20100515'},
            # },
            #'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/'
            #}
            if "response_code" in parsed and 1 == parsed["response_code"] :
                lsSimpleFields = [ "md5" , "sha1" , "sha1256" ]
                for field in lsSimpleFields :
                    if field in parsed and 0 < len(parsed[field]) :
                        d[field] = parsed[field]

                if "scans" in parsed :
                    parsedScans = parsed["scans"]
                    for vendor in parsedScans :
                        if "result" in parsedScans[vendor] :
                            detection = parsedScans[vendor]["result"]
                            if detection and 0 < len(detection) :
                                d[vendor] = detection
                            else :
                                d[vendor] = "<NULL>"

            aSelf.m_dictCache[aHash] = d
            return d





def HandleVirusTotal( aHashes , aConfig , aExcel , aExcelFmts ) :
    #Get config
    bWriteExcel = ( False != aConfig.getboolean( "General" , "WriteExcel" ) )
    nTimeout = aConfig.getint( "General" , "QueryTimeout" ) / 1000
    nMaxRetryCnt = aConfig.getint( "General" , "QueryRetryCnt" )
    bWriteRaw = ( False != aConfig.getboolean( "Debug" , "WriteRaw" ) )
    strApiKey = aConfig.get( "ApiKeys" , "VirusTotal" )
    if ( 64 != len(strApiKey) ) :
        raise ValueError( "VirusTotal's API key is incorrect" )

    if bWriteExcel :
        SHEET_NAME = "VirusTotal"

        #Set interesting fields information
        sheetInfo = CExcelSheetInfo( SHEET_NAME )
        sheetInfo.AddColumn( "md5"              , CExcelColumnInfo( 0 , "md5" , 20 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "sha1"             , CExcelColumnInfo( 1 , "sha1" , 20 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "sha256"           , CExcelColumnInfo( 2 , "sha256" , 20 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "ESET-NOD32"       , CExcelColumnInfo( 3 , "(ESET-)?NOD32" , 40 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "Kaspersky"        , CExcelColumnInfo( 4 , "Kaspersky" , 40 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "Microsoft"        , CExcelColumnInfo( 5 , "Microsoft" , 40 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "TrendMicro"       , CExcelColumnInfo( 6 , "TrendMicro" , 40 , aExcelFmts["Top"] ) )
        sheetInfo.AddColumn( "Raw"              , CExcelColumnInfo( 7 , "Raw" , 100 , aExcelFmts["WrapTop"] ) )

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
    vt = CVirusTotal( strApiKey )
    for strHash in aHashes :
        print( "Checking VirusTotal for {}".format( strHash ) )

        result = vt.Query( strHash , nTimeout , nMaxRetryCnt )
        if result :
            for key , value in result.items() :
                print( "{} = {}".format( key , value ) )
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
                sheet.write( uCount + 1 , sheetInfo.GetColumn("Raw").nColIndex , vt.GetRawResult() )

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