$vers="10.1.1"
Remove-Item "fmt-$($vers)*" -Recurse -Force -Verbose

curl.exe -L https://github.com/fmtlib/fmt/releases/download/$vers/fmt-$($vers).zip -o fmt-$($vers).zip
Expand-Archive -Path "fmt-$vers.zip"
Set-Location ".\fmt-$vers"


New-Item -ItemType Directory "build"
Set-Location ".\build"
$env:CFLAGS="-m32";
$env:CXXFLAGS="-m32";

cmake ../ -D FMT_TEST=OFF
cmake --build ./