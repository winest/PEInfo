@set @_ThisWillNeverBeUsed=0 /*
@ECHO OFF
CD /D "%~dp0"
CSCRIPT "%~0" //Nologo //E:JScript %1 %2 %3 %4 %5 %6 %7 %8 %9
IF %ERRORLEVEL% LSS 0 ( ECHO Failed. Error code is %ERRORLEVEL% )
PAUSE
EXIT /B
*/

var WshFileSystem = new ActiveXObject( "Scripting.FileSystemObject" );
var WshShell = WScript.CreateObject( "WScript.Shell" );
var WshEnv = WshShell.Environment( "Process" )
WScript.Echo( "Current directory is \"" + WshShell.CurrentDirectory + "\"" );

var strFilePath32 = GetFilePath( "python3.exe" , null , ["%PATH%"] );
WScript.Echo( "FilePath32 is \"" + strFilePath32 + "\"" );

//Use * for files
//Use AllFilesystemObjects for files and directories
if ( true == WriteReg( "HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shell\\PE Info\\Command\\" , "\"" + strFilePath32 + "\" \"" + WshShell.CurrentDirectory + "\\PEInfo.py\" \"%1\"" , "REG_SZ" ) )
{
    WScript.Echo( "Successfully End" );
    WScript.Quit( 0 );
}
else
{
    WScript.Echo( "Failed" );
    WScript.Quit( -1 );
}



function WriteReg( aValName , aValContent , aValType )
{
    try
    {
        //REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_BINARY
        //RegWrite will write at most one DWORD to a REG_BINARY value. Larger values are not supported with this method.
        WshShell.RegWrite( aValName , aValContent , aValType );
        return true;
    }
    catch( err )
    {
        return false;
    }
}

function GetFilePath( aFileName , aSearchDirList , aSearchEnvList )
{
    var bFound = false;
    var strExePath = aFileName;
    if ( WshFileSystem.FileExists( WshShell.CurrentDirectory + "\\" + aFileName ) )
    {
        strExePath = WshShell.CurrentDirectory + "\\" + aFileName;
        bFound = true;
    }
    if ( false == bFound && aSearchDirList )    //Only perform one-depth search
    {
        for ( var i in aSearchDirList )
        {
            var strDir = aSearchDirList[i];
            if ( 0 < strDir.length && '\\' == strDir.charAt(strDir.length - 1) )
            {
                strDir = strDir.substr( 0 , strDir.length - 1 );
            }
            if ( WshFileSystem.FileExists( strDir + "\\" + aFileName ) )
            {
                strExePath = strDir + "\\" + aFileName;
                bFound = true;
            }
        }
    }
    if ( false == bFound && aSearchEnvList )
    {
        for ( var i in aSearchEnvList )
        {
            var strEnvPaths = WshShell.ExpandEnvironmentStrings( aSearchEnvList[i] ).split( ";" );
            for ( var j in strEnvPaths )
            {
                var strDir = strEnvPaths[j];
                if ( 0 < strDir.length && '\\' == strDir.charAt(strDir.length - 1) )
                {
                    strDir = strDir.substr( 0 , strDir.length - 1 );
                }
                if ( WshFileSystem.FileExists( strDir + "\\" + aFileName ) )
                {
                    strExePath = strDir + "\\" + aFileName;
                    bFound = true;
                }
            }
        }
    }
    return strExePath;
}