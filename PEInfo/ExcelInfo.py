import os
import sys
import re



class CExcelSheetInfo :
    strSheetName = None
    mapColInfo = None               #<key , value> = <column name , CExcelColumnInfo>
    def __init__( aSelf , aSheetName ) :
        aSelf.strSheetName = aSheetName
        aSelf.mapColInfo = dict()

    def AddColumn( aSelf , aColName , aExcelColInfo ) :
        aSelf.mapColInfo[aColName] = aExcelColInfo

    def GetColumn( aSelf , aColName ) :
        return aSelf.mapColInfo[aColName]

    def GetColumns( aSelf ) :
        return aSelf.mapColInfo

    def GetColNameByIndex( aSelf , aColIndex ) :
        for strColName , info in aSelf.mapColInfo.items() :
            if info.nColIndex == aColIndex :
                return strColName
        return None




class CExcelColumnInfo :
    nColIndex = None                #Index of column start from 0
    strColId = None                 #Index of column start from "A"
    reColName = None                #Related names which also represent the column in regular expression
    nColWidth = None                #Width of the column
    strColFormat = None             #Excel display fromat used by the column
    def __init__( aSelf , aColIndex , aColNameRegex , aColWidth , aColFormat ) :
        aSelf.nColIndex = aColIndex
        aSelf.strColId = chr( ord('A') + aColIndex )
        aSelf.reColName = re.compile( aColNameRegex )
        aSelf.nColWidth = aColWidth
        aSelf.strColFormat = aColFormat