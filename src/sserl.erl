-module(sserl).

-export([start/0, start_listener/1, test/0]).

start() ->
    application:load(sserl),
    ok = mnesia_cluster:start(),
    application:start(sserl).

start_listener(Args) ->
    sserl_listener_sup:start(Args).

test() ->
    start_listener([{port, 8388}, {type, server}, {password, "xx"}, {method, aes_256_cfb}]).
