-module(sserl).

-export([start_listener/1]).

start_listener(Args) ->
    sserl_listener_sup:start(Args).
