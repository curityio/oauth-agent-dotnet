FROM mcr.microsoft.com/dotnet/aspnet:8.0

ARG PLATFORM
WORKDIR /usr/api
COPY $PLATFORM/bin/Release/net8.0/linux-$PLATFORM/publish/*  /usr/api/

RUN groupadd --gid 10000 apiuser \
  && useradd --uid 10001 --gid apiuser --shell /bin/bash --create-home apiuser
USER 10001

CMD ["dotnet", "oauth-agent.dll"]