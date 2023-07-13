FROM mcr.microsoft.com/dotnet/aspnet:7.0

WORKDIR /usr/api
COPY bin/Release/net7.0/linux-x64/publish/*  /usr/api/

RUN groupadd --gid 10000 apiuser \
  && useradd --uid 10001 --gid apiuser --shell /bin/bash --create-home apiuser
USER 10001

CMD ["dotnet", "oauth-agent.dll"]