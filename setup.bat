COPY run.bat C:\Users\test\Documents
COPY *.py C:\Users\test\Documents
COPY cert.ps1 C:\Users\test\Documents

::start cmd.exe /k conda.bat

start "" "C:\Users\test\Documents\run.bat.lnk.lnk"

pause