@ECHO OFF
CD /D "%~dp0"

SET "OutDir=Output"

IF NOT EXIST "%OutDir%" ( MKDIR "%OutDir" )
python3 setup.py py2exe -d "%~dp0\%OutDir%"

PAUSE