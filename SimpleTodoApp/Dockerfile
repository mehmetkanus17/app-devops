# Stage 1: Build the application
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Proje dosyasını kopyala ve restore et
COPY *.csproj .
RUN dotnet restore

# Tüm kaynak kodlarını kopyala ve build et
COPY . .
RUN dotnet build -c Release -o /app/build

# Stage 2: Publish the application
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Stage 3: Create the final runtime image
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=publish /app/publish .

EXPOSE 8080
ENTRYPOINT ["dotnet", "SimpleTodoApp.dll"]