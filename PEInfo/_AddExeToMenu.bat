@set @_ThisWillNeverBeUsed=0 /*
@ECHO OFF
CD /D "%~dp0"
CSCRIPT "%~0" //Nologo //E:JScript %1 %2 %3 %4 %5 %6 %7 %8 %9
IF %ERRORLEVEL% LSS 0 ( ECHO Failed. Error code is %ERRORLEVEL% )
PAUSE
EXIT /B
*/

var WshShell = WScript.CreateObject( "WScript.Shell" );
WScript.Echo( "Current directory is \"" + WshShell.CurrentDirectory + "\"" );

//Use * for files
//Use AllFilesystemObjects for files and directories
if ( true == WriteReg( "HKEY_CLASSES_ROOT\\AllFilesystemObjects\\shell\\PE Info\\Command\\" , "\"" + WshShell.CurrentDirectory + "\\PEInfo.exe\" \"%1\"" , "REG_SZ" ) )
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
