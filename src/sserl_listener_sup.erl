%%%-------------------------------------------------------------------
%% @doc sserl listener supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(sserl_listener_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start/1]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

start(Args) ->
    Port = proplists:get_value(port, Args),
    Children = supervisor:which_children(?SERVER),
    case [P || {_, P, _, _} <- Children, is_pid(P), sserl_listener:get_port(P) =:= Port] of
        [Pid] ->
            sserl_listener:update(Pid, Args);
        _ ->
            supervisor:start_child(?SERVER, [Args])
    end.


%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    {ok, { {simple_one_for_one, 1, 5}, 
           [{sserl_listener, {sserl_listener, start_link, []},
           transient, brutal_kill, worker, [sserl_listener]}]} }.

%%====================================================================
%% Internal functions
%%====================================================================
