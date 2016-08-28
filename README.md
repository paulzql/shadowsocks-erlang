shadowsocks-erlang (sserl)
=====

shadowsocks-erlang is a erlang port of [shadowsocks](https://github.com/shadowsocks/shadowsocks)

A fast tunnel proxy that helps you bypass firewalls.

Features:
- TCP  support
- Client support
- Server support
- OTA    support
- Mulit user support
- User management API support
- IP blacklist support [TODO]

Encryption methods
- table (deprecated)
- rc4-md5
- aes-128-cfb
- aes-192-cfb
- aes-256-cfb

**Note: this is a erlang app/lib of shadowsocks, not a installable application. 
  you can run with erlang vm or package in your erlang release**
  
* live demo

  The sserl is current running on X-NET, you can try it on [http://x-net.vip](http://x-net.vip)
  
Build
-----

    $ rebar3 compile
    

Useage
-----

* start

```erlang
    application:start(sserl).
```

* stop

```erlang
    application:stop(sserl).
```

* start / update listener

 if the port already started,the method,password and expiretime will be updated.
    
```erlang
    Args = [{port, 8388}, {type, server}, {ota, false}, {method, "rc4-md5"},{password,"xx"}],
    sserl_listener_sup:start(Args).
```
  
* stop listener

```erlang
    sserl_listener_sup:stop(8388)
```

Configuration
-----

sserl support [cuttlefish](https://github.com/basho/cuttlefish), you can easy configurate with cuttlefish schema.

* cuttlefish files

    `priv/sserl.schema`
    
* env config

```erlang
     {sserl,
     [
         {listener, [ %% a list of listener args
                 [{ip, {0,0,0,0}},      %% listen ip  [optional]
                  {port, 1080}          %% listen port
                  {method, "rc4-md5"},  %% encryption method [optional]
                  {password, "mypass"}, %% password
                  {ota, true},          %% use OTA
                  {expire_time, 3600},  %% expire time (unix time) [optional]
                  {conn_limit, 1024},   %% max synchronize connections on the port [optional]
                  {type, client},       %% listener type
                  {server, {"x-net.vip", 8388}} %% shadowsocks server (client only) [optional]
                  ],
                  [ %% other listeners
                    ...
                  ]
         ]},
         %% --------------------------------------
         %% shadowsocks-panel integration support
         %% --------------------------------------
         {sync_enable, false},   %% enable synchronize users from ss-panel
         {sync_node_id, 1},      %% the node id on ss-panel
         {sync_mysql_host, "x-net.vip"}, 
         {sync_mysql_port, 3306},        
         {sync_mysql_db,   "ss-panel"}, 
         {sync_mysql_user, "root"},
         {sync_mysql_pass, "123456"},
         {sync_report_min, 1048576}    %% bytes threshold to report flow 
     ]}
```

Events
-----

```erlang
%% flow event report: {report, Port, Download, Upload}
%% 
-define(FLOW_EVENT, sserl_flow_event).

%% stat event
%%      new listener {listener, new, Port}
%%      accept    :  {listener, accept, Addr, Port}
%%      open      :  {conn, open, Pid}
%%      close     :  {conn, close, Pid, Reason}
%%      connect   :  {conn, connect, Addr, Port}
%% 
-define(STAT_EVENT, sserl_stat_event).
```

License
-----

@see LICENSE
