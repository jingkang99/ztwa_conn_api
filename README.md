# ZTWA Connector Service

A service deployed on ZTWA connector validates user's JWT token, a web testing form provided. This service acts like a proxy to ZTWA gateway. Other applications should use this API to validate JWT tokens for single sign-on (SSO). 

# Usage

URL
    
    http://CONNECTOR_IP:1812/validate

Add JWT token in GET reuqest header

    -H 'Authorization: Bearer xxx...yyy'

Example:

    curl 'http://192.168.22.105:1812/validate' -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZXZvcDAxQHBlZ2FzdXMwMUB1c2VyIiwiYXV0aCI6IlJPTEVfVEVOQU5UIiwiZXhwIjoxNjMwOTEzOTc5fQ.7XXsWUis1zh1EmLN6XPIOiglp6o_7k0aU8FR1DYQvz6fFg-s5eprUAco6aEScwNavye3u9r3VRSrnI_okEaxpQ'

### Return

jwt token is valid

    {"code":200}
    
    
jwt token is invalid

    {"code":401}

### Service
    
    service_conn GATEWAY_DOMAIN PORT

    service_conn user.ztna85.lt.net 1812
    
### Detail

    $ curl -v  'http://192.168.22.105:1812/validate' -H 'Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZXZvcDAxQHBlZ2FzdXMwMUB1c2VyIiwiYXV0aCI6IlJPTEVfVEVOQU5UIiwiZXhwIjoxNjMwOTY5NTc2fQ.voYYNPsxOEWfV-KEqZF5N64HOAGWrAZuCLiV6pPLtsag4plcWCsIYyuBl3gj5rW1K_wwZ6tYQrqSU8Lb6D8kLw'
    *   Trying 192.168.22.105:1812...
      % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                     Dload  Upload   Total   Spent    Left  Speed
      0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 192.168.22.105 (192.168.22.105) port 1812 (#0)
    > GET /validate HTTP/1.1
    > Host: 192.168.22.105:1812
    > User-Agent: curl/7.77.0
    > Accept: */*
    > Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJkZXZvcDAxQHBlZ2FzdXMwMUB1c2VyIiwiYXV0aCI6IlJPTEVfVEVOQU5UIiwiZXhwIjoxNjMwOTY5NTc2fQ.voYYNPsxOEWfV-KEqZF5N64HOAGWrAZuCLiV6pPLtsag4plcWCsIYyuBl3gj5rW1K_wwZ6tYQrqSU8Lb6D8kLw
    >
    * Mark bundle as not supporting multiuse
    < HTTP/1.1 200 OK
    < Date: Sun, 05 Sep 2021 23:10:01 GMT
    < Content-Length: 14
    < Content-Type: text/plain; charset=utf-8
    <
    { [14 bytes data]
    100    14  100    14    0     0    366      0 --:--:-- --:--:-- --:--:--   378{"status":200}
    * Connection #0 to host 192.168.22.105 left intact
    }


# Build

    env GOOS=linux GOARCH=amd64 go build


