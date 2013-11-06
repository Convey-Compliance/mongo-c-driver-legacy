@SET FrameworkDir=C:\Windows\Microsoft.NET\Framework64\
@SET FrameworkVersion=v4.0.30319
@SET FrameworkSDKDir=

@ECHO Setting environment for using Visual Studio

@SET PATH=%FrameworkDir%%FrameworkVersion%;%FrameworkSDKDir%;%PATH%

msbuild ..\src\MongoC.sln "/p:Platform=Win32;Configuration=Debug"
IF ERRORLEVEl 1 EXIT

msbuild ..\src\MongoC.sln "/p:Platform=Win32;Configuration=Release"
IF ERRORLEVEl 1 EXIT

msbuild ..\src\MongoC.sln "/p:Platform=x64;Configuration=Debug"
IF ERRORLEVEl 1 EXIT

msbuild ..\src\MongoC.sln "/p:Platform=x64;Configuration=Release"
IF ERRORLEVEl 1 EXIT

