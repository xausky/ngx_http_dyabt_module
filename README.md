# ngx_http_dyabt_module

可以动态修改分配规则的Nginx灰度发布模块，完全使用C语言实现，提供Restful风格的API，几乎不影响Nginx性能。

### 推荐结合ngx_http_dyups_module使用

## 指令参考
1 `dyabt_interface`

配置于location块内，作为一个Handler提供Restful API同时也是该模块的开关指令,不配置该指令模块运行于disable模式，所有dyabt_set指令返回0。

2 `dyabt_set <var> <domain>`

配置于location块内，使用domain对应的规则解析当前请求并将结果存到var变量内。

## Nginx 配置参考

```
events {
}
http {
    server {
        listen 4000;
        location / {
			dyabt_set $ab $host;
            return 200 $ab.$host;
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
1. 以HTTP请求Header Host即访问域名为域，将解析结果存放到`$ab`变量。
2. 返回`$ab.$host`响应,实际使用中这里一般为proxy_pass。

## Restful API参考

```
POST /testings
xausky.example.org,header_x_uid
0,10
11,100
101,99999999

200 OK
success
```

1. 提交一个规则到规则列表。
2. 以xausky.example.org为域，如果有相同域的规则将会覆盖规则。
3. 以header_x_uid为解析器，header_x_uid将解析出HTTP Headers内的X-UID对应的值。
4. 下面三个Case，Case描述一个闭区间，使用dyabt_set指令时模块将顺序进行匹配，返回从1开始的成功索引，如果全部失败或者没有对应域将返回0。

```
GET /testings[/<domain>]
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
```

1. 查询规则列表。
2. 返回domain为域的规则列表。
3. 若没有domain段将返回所有规则这时以---行分割规则。

```

DELETE /testings/<domain>
200 OK
success
```

1. 删除domain对应的规则。
2. dyabt_set指令对于不存在的域将返回0。

## 解析器

### 已有解析器

1. header_x_uid   该解析器将取出X-UID Header对应的值。
2. remote_ip      该解析器将客户端IP转换为整型值，比如 0.0.1.0 -> 256

### 实现新解析器

1. C代码里面实现`typedef long long (*ngx_http_dyabt_parser_ptr_t)(ngx_http_request_t *r);`接口
2. 在`ngx_http_dyabt_init_process`函数内注册，例如：

```
parser = ngx_array_push(&parsers);
ngx_str_set(&parser->key,"header_x_uid");
parser->key_hash = ngx_hash_key(parser->key.data,parser->key.len);
parser->value = ngx_http_dyabt_uid_parser;
```

## 性能测试
系统：Linux Kernel 4.8.10

线程数: 200

服务器: Tengine 2.2.0

处理器: Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz

Tengine 原生转发:
![Tengine 原生转发](https://raw.githubusercontent.com/xausky/ngx_http_dyabt_module/master/doc/TengineNative.png)

Tengine 使用本模块转发:
![Tengine 原生转发](https://raw.githubusercontent.com/xausky/ngx_http_dyabt_module/master/doc/TengineDyabt.png)

Tengine 使用本模块同时每秒更新一次规则:
![Tengine 原生转发](https://raw.githubusercontent.com/xausky/ngx_http_dyabt_module/master/doc/TengineDyabt-Update.png)
