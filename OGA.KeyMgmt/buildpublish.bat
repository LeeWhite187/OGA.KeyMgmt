REM OGA Key Management Library

REM Build the library...
dotnet restore "./OGA.KeyMgmt_NET5/OGA.KeyMgmt_NET5.csproj"
dotnet build "./OGA.KeyMgmt_NET5/OGA.KeyMgmt_NET5.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.KeyMgmt_NET5/OGA.KeyMgmt_NET5.csproj"
dotnet build "./OGA.KeyMgmt_NET5/OGA.KeyMgmt_NET5.csproj" -c DebugWin --runtime win --no-self-contained

dotnet restore "./OGA.KeyMgmt_NET6/OGA.KeyMgmt_NET6.csproj"
dotnet build "./OGA.KeyMgmt_NET6/OGA.KeyMgmt_NET6.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.KeyMgmt_NET6/OGA.KeyMgmt_NET6.csproj"
dotnet build "./OGA.KeyMgmt_NET6/OGA.KeyMgmt_NET6.csproj" -c DebugWin --runtime win --no-self-contained

dotnet restore "./OGA.KeyMgmt_NET7/OGA.KeyMgmt_NET7.csproj"
dotnet build "./OGA.KeyMgmt_NET7/OGA.KeyMgmt_NET7.csproj" -c DebugLinux --runtime linux --no-self-contained

dotnet restore "./OGA.KeyMgmt_NET7/OGA.KeyMgmt_NET7.csproj"
dotnet build "./OGA.KeyMgmt_NET7/OGA.KeyMgmt_NET7.csproj" -c DebugWin --runtime win --no-self-contained

REM Create the composite nuget package file from built libraries...
C:\Programs\nuget\nuget.exe pack ./OGA.KeyMgmt.nuspec -IncludeReferencedProjects -symbols -SymbolPackageFormat snupkg -OutputDirectory ./Publish -Verbosity detailed

REM To publish nuget package...
dotnet nuget push -s http://192.168.1.161:8080/v3/index.json ".\Publish\OGA.KeyMgmt.1.3.1.nupkg"
dotnet nuget push -s http://192.168.1.161:8080/v3/index.json ".\Publish\OGA.KeyMgmt.1.3.1.snupkg"
