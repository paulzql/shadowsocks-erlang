%%%-------------------------------------------------------------------
%%% @author paul <paul@hupaul.com>
%%% @copyright (C) 2016, paul
%%% @doc
%%%
%%% @end
%%% Created : 21 May 2016 by paul <paul@hupaul.com>
%%%-------------------------------------------------------------------
-module(sserl_config).

-behaviour(gen_server).

%% API
-export([start_link/0, report_flow/2, add_limit/1, get_all/0, load_startup/0, put_config/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("stdlib/include/qlc.hrl").

-define(SERVER, ?MODULE).

-record(state, {}).

-record(sserl_config, { port,
          nodes,
          cropto,
          desc,
          limit,
          flow = 0,
          last_time = 0,
          startup = true
         }).
-record(sserl_config_log, {port, time, op, desc }).

-export([get_table/0]).
%% define message table
-mnesia_table(get_table).
get_table() ->
 [
   {sserl_config, [{type, set}, {disc_copies, [node()]}, {attributes, record_info(fields, sserl_config)}]},
   {sserl_config_log, [{type, bag}, {disc_only_copies, [node()]}, {attributes, record_info(fields, sserl_config_log)}]}
 ].

%%%===================================================================
%%% API
%%%===================================================================

%% 添加流量统计
report_flow(Port, Flow) ->
    gen_server:cast(?SERVER, {add_flow, Port, Flow}).

%% 增加限制, 0代表不增加，负数代表减少
add_limit({Port, MaxFlow, ExpireTime}) when 
      is_integer(Port),is_integer(MaxFlow),is_integer(ExpireTime) ->
    F = fun() ->
                case mnesia:wread({sserl_config, Port}) of
                    [Conf=#sserl_config{limit=Limit, flow=Flow}] ->
                        OldMaxFlow = proplists:get_value(max_flow, Limit, Flow),
                        OldExpireTime=proplists:get_value(expire_time, Limit, os:system_time(milli_seconds)),
                        Limit1 = case MaxFlow of
                                     0 ->
                                         Limit;
                                     _ ->
                                         [{max_flow, MaxFlow+OldMaxFlow} | proplists:delete(max_flow, Limit)]
                                 end,
                        Limit2 = case ExpireTime of
                                     0 ->
                                         Limit1;
                                     _ ->
                                         [{expire_time, OldExpireTime+ExpireTime} | proplists:delete(expire_time,Limit1)]
                                 end,
                        NewConf = Conf#sserl_config{limit=Limit2},
                        mnesia:write(NewConf),
                        NewConf;
                    _ ->
                        {error, no_port}
                end
        end,
    {atomic, NewConf} = mnesia:transaction(F),
    gen_server:cast(?SERVER, {update, NewConf}),
    gen_server:cast(?SERVER, {log, Port, add_limit, {Port, MaxFlow, ExpireTime}}),
    ok.
                            

put_config({Port, _Nodes, _Cropto, _Desc, _Limit}=Arg) ->
    try check_config(Arg) of
        Conf=#sserl_config{} ->
            F = fun() ->
                        case mnesia:wread({sserl_config, Port}) of
                            [OldConf] ->
                                NewConf = Conf#sserl_config{
                                            flow=OldConf#sserl_config.flow,
                                            last_time = OldConf#sserl_config.last_time
                                           },
                                mnesia:write(NewConf),
                                NewConf;
                            [] ->
                                mnesia:write(Conf),
                                Conf
                        end
                end, 
            case mnesia:transaction(F) of
                {atomic, Config} ->
                    gen_server:cast(?SERVER, {update, Config}),
                    gen_server:cast(?SERVER, {log, Port, put_config, Arg}),
                    ok;
                Error ->
                    Error
            end;
        Error ->
            Error
    catch
        Error ->
            Error
    end.
                
%% 获取所有配置
get_all() ->
    F = fun() ->
                Q = qlc:q([C || C <- mnesia:table(sserl_config)]),
                qlc:e(Q)
        end,
    case catch mnesia:transaction(F) of
        {atomic, Res} ->
            Res;
        _ ->
            []
    end.

%% 加载启动的配置
load_startup() ->
    CurrTime = os:system_time(milli_seconds),
    L = lists:filter(fun(C)->
                         case {C#sserl_config.nodes, C#sserl_config.startup} of
                             {all, true} ->
                                 case proplists:get_value(expire_time, C#sserl_config.limit) of
                                     undefined ->
                                         true;
                                     T when T > CurrTime ->
                                         true;
                                     _ ->
                                         false
                                 end;
                             {Nodes, true} when is_list(Nodes) ->
                                 lists:any(fun(N) -> N =:= node() end, Nodes);
                             _ ->
                                 false
                         end
                     end, get_all()),
    [to_args(C) || C <- L].

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    {ok, #state{}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({add_flow, Port, Flow}, State) ->
    F = fun() ->
                case mnesia:wread({sserl_config, Port}) of
                    [#sserl_config{flow=OldFlow}=Conf] ->
                        mnesia:write(Conf#sserl_config{flow=OldFlow+Flow,last_time=os:system_time(milli_seconds)});
                    _ ->
                        {error, no_port}
                end
        end,
    case catch mnesia:async_dirty(F) of
        _ ->
            ok
    end,
    {noreply, State};

handle_cast({log, Port, Op, Desc}, State) ->
    Log = #sserl_config_log{port=Port, op=Op, desc=Desc, time=os:system_time(milli_seconds)},
    mnesia:dirty_write(Log),
    {noreply, State};
        
handle_cast({update, #sserl_config{}=Conf}, State) ->
    sserl_listener_sup:start(to_args(Conf)),
    {noreply, State};
                    
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
%% 转化为listener的参数
to_args(#sserl_config{port=Port, cropto={Method,Password}, limit=Limit, flow=Flow}) ->
    Limit2 = lists:map(fun(L) ->
                      case L of
                          {max_flow, MaxFlow} ->
                              {max_flow, MaxFlow-Flow};
                          Other ->
                              Other
                      end
              end, Limit),
    [{port, Port}, {method, Method},{password, Password}]++Limit2.

%% 检查配置是否正确
check_config({Port, Nodes, Cropto, Desc, Limit}) ->
    CK_Port = is_integer(Port),
    CK_Nodes= case Nodes of
                  _ when is_list(Nodes) ->
                      lists:any(fun(E) -> is_atom(E) end, Nodes);
                  all ->
                      true;
                  _ ->
                      false
              end,
    CK_Desc = is_list(Desc),
    CK_Limit= is_list(Limit),
    case {CK_Port, CK_Nodes, CK_Desc, CK_Limit} of
        {true, true, true, true} ->
            ok;
        _ ->
            throw({error, bad_arguments})
    end,
    case Cropto of
        {Method, Password} when is_atom(Method),is_list(Password)->
            case lists:any(fun(M)-> M =:= Method end, shadowsocks_crypt:methods()) of
                true ->
                    ok;
                _ ->
                    throw({error, bad_arg_cropto})
            end;
        _ ->
            throw({error, bad_arg_cropto})
    end,
    #sserl_config{port=Port, nodes=Nodes,cropto=Cropto, desc=Desc, limit=Limit}.
                                   
