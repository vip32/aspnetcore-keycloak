keycloak client setup:
![](keycloak_client_setup.png)

- Client Protocol = openid-connect
- Access Type = confidential
  - client secret will appear under 'Credentials' after saving
- Valid Redirect URIs = 
  - for ASP.Net Core Authentication Middleware https://localhost:5001/signin-oidc + https://localhost:5001/signout-callback-oidc
  - for custom html login https://localhost:5001/signin-oidc-callback.html
- Web Origins = * (otherwise /userinfo request will have empty response)

### webapi appsettings:
```
 "Oidc": {
    "ClientId": "naos-sample",
    "ClientSecret": "8c87b1b0-9b2b-4ac6-bc37-88f093c04d13",
    "Authority": "http://localhost:8080/auth/realms/master"
  }
```

### todos:
- +dockercompose (keycloak/sql/webapi)
- [DONE] simple html page for login https://github.com/GluuFederation/openid-implicit-client
- autosetup keycloak client? with api request? 
  - https://www.keycloak.org/docs-api/5.0/rest-api/index.html#_clients_resource
  - https://stackoverflow.com/questions/53283281/how-to-activate-the-rest-api-of-keycloak
 

### docker-compose
```
version: '3.4'

services:
  keycloak:
    image: jboss/keycloak
    depends_on:
      - mssql
      - mssqlscripts
    ports:
      - 80:8080 
    environment:
      - KEYCLOAK_USER=admin
      - KEYCLOAK_PASSWORD=admin
      - DB_VENDOR=mssql 
      - DB_USER=sa
      - DB_PASSWORD=Abcd1234!
      - DB_ADDR=mssql
      - DB_DATABASE=Keycloak

  mssql:
    image: mcr.microsoft.com/mssql/server
    environment:
      - ACCEPT_EULA=Y
      - SA_PASSWORD=Abcd1234!
      - MSSQL_PID=Developer
    ports:
      - 1433:1433
    volumes:
      - mssql:/var/opt/mssql

  mssqlscripts:
    image: mcr.microsoft.com/mssql-tools
    depends_on:
      - mssql
    command: /bin/bash -c 'until /opt/mssql-tools/bin/sqlcmd -S mssql -U sa -P "Abcd1234!" -Q "create database Keycloak"; do sleep 5; done'

volumes:
  mssql:
    driver: local
```

links:
- https://developer.okta.com/blog/2019/11/15/aspnet-core-3-mvc-secure-authentication