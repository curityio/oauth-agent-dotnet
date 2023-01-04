FROM mcr.microsoft.com/dotnet/aspnet:7.0

WORKDIR /usr/api
COPY bin/Release/net7.0/linux-x64/publish/*  /usr/api/

RUN adduser --disabled-password --home /home/apiuser --gecos '' apiuser
USER apiuser
CMD ["dotnet", "oauth-agent.dll"]