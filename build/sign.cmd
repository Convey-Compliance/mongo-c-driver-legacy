pushd ..\build-toolbox\CodeSign
call SignIt_signtool.bat ..\..\bin\Win32\Release\MongoC.dll
call SignIt_signtool.bat ..\..\bin\x64\Release\MongoC.dll
popd