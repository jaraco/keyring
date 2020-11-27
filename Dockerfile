FROM mcr.microsoft.com/windows/servercore:ltsc2019
RUN powershell -c "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex"
RUN choco feature enable -n allowGlobalConfirmation
RUN choco install git python
RUN python -m pip install -U pip pipx
RUN setx path "%path%;C:\Users\ContainerAdministrator\.local\bin"
RUN pipx install tox
RUN setx TOX_WORK_DIR C:\tox
CMD powershell
