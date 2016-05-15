%%%-------------------------------------------------------------------
%% @doc sserl top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(sserl_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================
start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
    ListenerSup = {sserl_listener_sup, {sserl_listener_sup, start_link, []},
                  transient, brutal_kill, supervisor, [sserl_listener_sup]},
    Stat = {sserl_stat, {sserl_stat, start_link, []},
            transient, brutal_kill, worker, dynamic},
    {ok, { {one_for_one, 2, 10}, 
           [Stat, ListenerSup]} }.

%%====================================================================
%% Internal functions
%%====================================================================
