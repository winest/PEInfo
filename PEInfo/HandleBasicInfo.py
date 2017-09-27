import os
import sys
import logging
import traceback
import configparser
import time
import subprocess
import pefile
import peutils
import hashlib
import xlsxwriter
import chardet
from collections import defaultdict

from Singleton import *
from ExcelInfo import *
from HashInfo import *




class CPeid( metaclass = Singleton ) :
    def __init__( aSelf , aPatternFile ) :
        with open( aPatternFile , "rt" , encoding="utf8" ) as db :
            aSelf._sig = peutils.SignatureDatabase( data = db.read() )
    def Match( aSelf , aPe , aEpOnly=True , aSectionStartOnly=False ) :
        return aSelf._sig.match( aPe , aEpOnly , aSectionStartOnly )
    def MatchAll( aSelf , aPe , aEpOnly=True , aSectionStartOnly=False ) :
        return aSelf._sig.match_all( aPe , aEpOnly , aSectionStartOnly )





def GetFileHashes( aFilePath , aHasherNames , aBlocksize = 64 * 1024 ):
    lsHashers = list()
    for hasherName in aHasherNames :
        lsHashers.append( hashlib.new(hasherName) )

    with open( aFilePath , "rb" ) as file :
        buf = file.read( aBlocksize )
        while len( buf ) > 0 :
            for hasher in lsHashers :
                hasher.update( buf )
            buf = file.read( aBlocksize )

    lsHashes = list()
    for hasher in lsHashers :
        lsHashes.append( hasher.hexdigest() )
    return lsHashes



def GetPeid( aPatternFile , aPe ) :
    lsPeids = CPeid( aPatternFile ).MatchAll( aPe )
    lsRet = []
    if None != lsPeids :
        for pair in lsPeids :
            for peid in pair :
                lsRet.append( peid )
    return lsRet



def GetCompileTime( aPe ) :
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(aPe.FILE_HEADER.TimeDateStamp) )



def GetPdbStrings( aPe ) :
    #http://www.debuginfo.com/articles/debuginfomatch.html#debuginfoinpe
    #http://www.godevtool.com/Other/pdb.htm
    lsPdbs = []
    MAX_PATH = 260
    try :
        if ( hasattr(aPe , "DIRECTORY_ENTRY_DEBUG") ) :
            for dbg in aPe.DIRECTORY_ENTRY_DEBUG :
                if dbg.struct.Type == 2 :
                    if dbg.struct.AddressOfRawData == 0 : #PDB 2.0
                        dbgRva = aPe.get_rva_from_offset( dbg.struct.PointerToRawData )
                        rawPdb = aPe.get_data( dbgRva + 0x10 , MAX_PATH )
                    else : #PDB 7.0
                        rawPdb = aPe.get_data( dbg.struct.AddressOfRawData + 0x18 , MAX_PATH )
                    rawPdbLen = 0
                    for rawPdbByte in rawPdb :
                        if rawPdbByte == 0 :
                            break;
                        else :
                            rawPdbLen = rawPdbLen + 1
                    rawPdb = rawPdb[0:rawPdbLen]
                    dictEncoding = chardet.detect( rawPdb )
                    if ( dictEncoding ) :
                        encName = dictEncoding["encoding"]
                        lsPdbs.append( "({}) {}".format( encName , rawPdb.decode(encName) ) )
                    else :
                        lsPdbs.append( "({Unknown}) {}".format( rawPdb ) )
    except Exception as ex :
        logging.exception( "GetPdbStrings() failed" )
    return sorted( lsPdbs )



def GetExportFuncs( aPe ) :
    lsExported = list()
    if ( hasattr(aPe , "DIRECTORY_ENTRY_EXPORT") ) :
        for exp in aPe.DIRECTORY_ENTRY_EXPORT.symbols :
            lsExported.append( exp.name )
    return sorted( lsExported )










def HandleBasicInfo( aFilePaths , aConfig , aExcel , aExcelFmts , aMainDir ) :
    #Get config
    bWriteExcel = ( False != aConfig.getboolean( "General" , "WriteExcel" ) )

    #Set interesting fields information
    SHEET_NAME = "BasicInfo"
    sheetInfo = CExcelSheetInfo( SHEET_NAME )
    sheetInfo.AddColumn( "FileName"    , CExcelColumnInfo( 0 , "FileName" , 20 , aExcelFmts["WrapVcenter"] ) )
    sheetInfo.AddColumn( "BasicHash"   , CExcelColumnInfo( 1 , "BasicHash" , 46 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "PEID"        , CExcelColumnInfo( 2 , "PEID" , 32 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "ImpHash"     , CExcelColumnInfo( 3 , "ImpHash" , 32 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "CompileTime" , CExcelColumnInfo( 4 , "CompileTime" , 18 , aExcelFmts["Top"] ) )
    sheetInfo.AddColumn( "PDB"         , CExcelColumnInfo( 5 , "PDB" , 90 , aExcelFmts["WrapTop"] ) )
    sheetInfo.AddColumn( "ExportFunc"  , CExcelColumnInfo( 6 , "ExportFunc" , 90 , aExcelFmts["WrapTop"] ) )

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



    #Start to get file information
    uCount = 0
    for strFilePath in aFilePaths :
        try :
            #Write default value for all fields
            for info in sheetInfo.GetColumns().values() :
                sheet.write( uCount + 1 , info.nColIndex , "<NULL>" )

            #Name
            print( "{}:".format( os.path.basename(strFilePath) ) )
            if bWriteExcel :
                sheet.write( uCount + 1 , sheetInfo.GetColumn("FileName").nColIndex , "{}{}({})".format(os.path.basename(strFilePath),os.linesep,strFilePath) )

            #Basic hash
            if ( False != aConfig.getboolean( "Features" , "BasicHash" ) ) :
                lsHasherNames = [ "md5" , "sha1" , "sha256" ]   #Case-sensitive
                lsHashes = GetFileHashes( strFilePath , lsHasherNames )

                CHashes().Add( CHashItem( aMd5 = lsHashes[lsHasherNames.index("md5")] , aSha1 = lsHashes[lsHasherNames.index("sha1")] , aSha256 = lsHashes[lsHasherNames.index("sha256")] ) )

                strTmpHash = ""
                for strHasherName , strHash in zip(lsHasherNames , lsHashes) :
                    strHasherNameDisplay = strHasherName.upper() if strHasherName.islower() or strHasherName.isupper() else strHasherName
                    print( "    {:16}{}".format( strHasherNameDisplay , strHash ) )
                    if bWriteExcel :
                        if 0 < len(strTmpHash) :
                            strTmpHash += os.linesep
                        strTmpHash += "{}={}".format(strHasherNameDisplay,strHash)
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("BasicHash").nColIndex , strTmpHash )

            #Put pe initialization here to support hash calculation even it's not a valid PE file
            pe = pefile.PE( strFilePath )

            if ( False != aConfig.getboolean( "Features" , "PEID" ) ) :
                lsPeid = GetPeid( "{}\\_Tools\\userdb.txt".format(aMainDir) , pe )
                print( "    {:16}{}".format( "PEID" , lsPeid ) )
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("PEID").nColIndex , os.linesep.join(lsPeid) )

            if ( False != aConfig.getboolean( "Features" , "ImpHash" ) ) :
                strImpHash = pe.get_imphash()
                print( "    {:16}{}".format( "ImpHash" , strImpHash ) )
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("ImpHash").nColIndex , strImpHash )

            if ( False != aConfig.getboolean( "Features" , "CompileTime" ) ) :
                strCompileTime = GetCompileTime( pe )
                print( "    {:16}{}".format( "CompileTime" , strCompileTime ) )
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("CompileTime").nColIndex , strCompileTime )

            if ( False != aConfig.getboolean( "Features" , "PDB" ) ) :
                lsPdb = GetPdbStrings( pe )
                print( "    {:16}{}".format( "PDB" , lsPdb ) )
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("PDB").nColIndex , os.linesep.join(lsPdb) )

            if ( False != aConfig.getboolean( "Features" , "ExportFunc" ) ) :
                lsExportFuncs = GetExportFuncs( pe )
                print( "    {:16}{}".format( "Export" , lsExportFuncs ) )
                if bWriteExcel :
                    sheet.write( uCount + 1 , sheetInfo.GetColumn("ExportFunc").nColIndex , os.linesep.join(lsExportFuncs) )
        except pefile.PEFormatError :
            logging.warning( "{} is not a valid PE file".format(strFilePath) )
        except PermissionError :
            logging.warning( "{} can not be opened".format(strFilePath) )

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

    