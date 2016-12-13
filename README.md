# ngx_http_dyabt_module

## Configure Reference

```
worker_processes 1;
events {
}
http {
    server {
        listen 4000;
        location / {
			dyabt_set $domain $host;
            return 200 $domain;
        }
    }
    server {
        listen 4032;
        location / {
			dyabt_interface;
        }
    }
}
```

## API Reference

```
POST /testings
xausky.example.org,header_x_uid
0,10
11,100
101,99999999

200 OK
success

GET /testings
200 OK
init.example.org,header_x_uid
0,10
11,100
101,99999999
---
xausky.example.org,header_x_uid
0,10
11,100
101,99999999
---
<...>

DELETE /testings
200 OK
success
```
