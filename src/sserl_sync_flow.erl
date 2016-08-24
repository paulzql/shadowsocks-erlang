%%%-------------------------------------------------------------------
%%% @author paul <paul@hupaul.com>
%%% @copyright (C) 2016, paul
%%% @doc
%%%
%%% @end
%%% Created : 15 Aug 2016 by paul <paul@hupaul.com>
%%%-------------------------------------------------------------------
-module(sserl_sync_flow).

-behaviour(gen_event).

%% API
-export([add_handler/0]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("sserl.hrl").

-define(SERVER, ?MODULE).
-define(LOG_TAB, sserl_flow_log).
-define(FLOW_TAB, sserl_flow).
-define(MYSQL_ID, sserl_mysql).

-define(FORM_TYPE, "application/x-www-form-urlencoded;charset=UTF-8").
-define(JSON_TYPE, "application/json").
-define(FORM_HEADER, {"Content-Type","application/x-www-form-urlencoded;charset=UTF-8"}).
-define(HTTPC_OPTIONS, [{body_format, binary}]).
-define(TIMEOUT, 10000).

-define(SYNC_INTERVAL, 2 * 60*1000).
-define(REPORT_INTERVAL, 5*60*1000).
-define(REPORT_MIN, 1048576).% 1MB

-record(state, {
          node_id,
          rate,
          report_min
         }).

-record(flow, {
          port :: integer(),
          uid  :: integer(),
          max_flow :: integer(),
          download :: integer(),
          upload   :: integer(),
          method = undefined,
          password = undefined
         }).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Adds an event handler
%%
%% @spec add_handler() -> ok | {'EXIT', Reason} | term()
%% @end
%%--------------------------------------------------------------------
add_handler() ->
    gen_event:add_handler(?FLOW_EVENT, ?MODULE, []).

%%%===================================================================
%%% gen_event callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever a new event handler is added to an event manager,
%% this function is called to initialize the event handler.
%%
%% @spec init(Args) -> {ok, State}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    case application:get_env(sync_enabled) of
        {ok, true} ->
            init([init_mysql]);
        _ ->
            diabled
    end;
init([init_mysql]) ->
    {ok, Host} = application:get_env(sync_mysql_host),
    {ok, User} = application:get_env(sync_mysql_user),
    {ok, Pass} = application:get_env(sync_mysql_pass),
    {ok, DB}   = application:get_env(sync_mysql_db),
    Port = application:get_env(sserl, sync_mysql_port, 3306),

    %% the clumn order must match the flow record element order
    SQLUsers   = application:get_env(sserl, sync_sql_users, "SELECT port,id,transfer_enable,d,u,method,passwd FROM user WHERE enable=1"),
    SQLReport  = application:get_env(sserl, sync_sql_reqport, "UPDATE user SET d=d+?,u=u+?,t=unix_timestamp() WHERE id=?"),
    SQLLog     = application:get_env(sserl, sync_sql_log, "INSERT INTO user_traffic_log values(null,?,?,?,?,?,?,unix_timestamp())"), 
    SQLRate    = application:get_env(sserl, sync_sql_rate, "SELECT traffic_rate FROM ss_node WHERE id=?"),

    Prepares = [{users, SQLUsers}, {report, SQLReport}, {log, SQLLog}, {rate, SQLRate}],
    MysqlArgs = [{host, Host},{port,Port},{user, User},{password, Pass},{database, DB}, {prepare, Prepares}],
    mysql_poolboy:add_pool(?MYSQL_ID, [{size, 2}, {max_overflow, 10}], MysqlArgs),
    init([init_mnesia]);

init([init_mnesia]) ->
    {ok, NodeId}=application:get_env(sync_node_id),
    ReportMin = application:get_env(sserl, sync_report_min, ?REPORT_MIN),
    case init_mnesia() of
        ok ->
            ets:new(?LOG_TAB, [public, named_table]),
            {ok, _} = mnesia:subscribe({table, ?FLOW_TAB, detailed}),
            error_logger:info_msg("[sserl_sync_flow] init ok ~p", [self()]),
            erlang:send_after(0, self(), sync_timer),
            erlang:send_after(?REPORT_INTERVAL, self(), report_timer),
            {ok, #state{node_id=NodeId, rate=get_rate(NodeId, 1), report_min=ReportMin}};
        Error ->
            error_logger:info_msg("[sserl_sync_flow] init failed: ~p", [Error]),
            {error, Error}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event manager receives an event sent using
%% gen_event:notify/2 or gen_event:sync_notify/2, this function is
%% called for each installed event handler to handle the event.
%%
%% @spec handle_event(Event, State) ->
%%                          {ok, State} |
%%                          {swap_handler, Args1, State1, Mod2, Args2} |
%%                          remove_handler
%% @end
%%--------------------------------------------------------------------
handle_event({report, Port, Download, Upload}, State = #state{rate=Rate}) ->
    F = fun() ->
                case mnesia:wread({?FLOW_TAB, Port}) of
                    [Flow=#flow{download=D, upload=U}] ->
                        mnesia:write(?FLOW_TAB, Flow#flow{download=D+(Download*Rate), upload=U+(Upload*Rate)}, write);
                    _ ->
                        ok
                end
        end,
    mnesia:transaction(F),
    ets:update_counter(?LOG_TAB, Port, [{3, Download}, {4, Upload}]),
    {ok, State};
handle_event(_Event, State) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event manager receives a request sent using
%% gen_event:call/3,4, this function is called for the specified
%% event handler to handle the request.
%%
%% @spec handle_call(Request, State) ->
%%                   {ok, Reply, State} |
%%                   {swap_handler, Reply, Args1, State1, Mod2, Args2} |
%%                   {remove_handler, Reply}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, State) ->
    Reply = ok,
    {ok, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called for each installed event handler when
%% an event manager receives any other message than an event or a
%% synchronous request (or a system message).
%%
%% @spec handle_info(Info, State) ->
%%                         {ok, State} |
%%                         {swap_handler, Args1, State1, Mod2, Args2} |
%%                         remove_handler
%% @end
%%--------------------------------------------------------------------
handle_info({mnesia_table_event,{write, ?FLOW_TAB, 
                                 #flow{port=P, max_flow=Max,download=D,upload=U}, _, _}}, 
            State) when D + U > Max ->
    sserl_listener_sup:stop(P),
    {ok, State};
%% handle_info({mnesia_table_event, {write, ?FLOW_TAB, 
%%                                   #flow{max_flow=F,method=M,password=P}, 
%%                                   [#flow{max_flow=F,method=M,password=P}],_}}, State) ->
%%     %% nothing to change
%%     {ok, State};
handle_info({mnesia_table_event, {write, ?FLOW_TAB, NewFlow, _, _}}, State) ->
    %% init log element
    case ets:lookup(?LOG_TAB, NewFlow#flow.port) of
        [] ->
            ets:insert(?LOG_TAB, {NewFlow#flow.port, NewFlow#flow.uid, 0, 0});
        _ -> 
            ok
    end,
    sserl_listener_sup:start(flow_to_args(NewFlow)),
    {ok, State};
handle_info({mnesia_table_event, {delete, {?FLOW_TAB, Port}, _}}, State) ->
    sserl_listener_sup:stop(Port),
    {ok, State};

handle_info(sync_timer, State) ->
    spawn(fun sync_users/0),
    erlang:send_after(?SYNC_INTERVAL, self(), sync_timer),
    self() ! sync_rate,
    {ok, State};

handle_info(report_timer, State = #state{node_id=NodeId, rate=Rate, report_min=Min}) ->
    do_report(NodeId, Rate, Min),
    erlang:send_after(?REPORT_INTERVAL, self(), report_timer),
    {ok, State};

handle_info(sync_rate, State = #state{node_id=NodeId, rate=Rate}) ->
    {ok, State#state{rate=get_rate(NodeId, Rate)}};

handle_info(Info, State) ->
    io:format("info:~p", [Info]),
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Whenever an event handler is deleted from an event manager, this
%% function is called. It should be the opposite of Module:init/1 and
%% do any necessary cleaning up.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, #state{node_id=NodeId, rate=Rate}) ->
    do_report(NodeId, Rate, 0),
    ets:delete(?LOG_TAB),
    uninit_mnesia(),
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
init_mnesia() ->
    case mnesia:add_table_copy(?FLOW_TAB, node(), ram_copies) of    
        {aborted, {no_exists, {?FLOW_TAB, cstruct}}} ->
            case mnesia:create_table(?FLOW_TAB, [{type, set}, 
                                                 {ram_copies, [node()]}, 
                                                 {record_name, flow},
                                                 {attributes, record_info(fields, flow)}]) of
                {atomic, ok} ->
                    ok;
                {aborted,{already_exists, ?FLOW_TAB}} ->
                    ok;
                Error ->
                    Error
            end;
        _ ->
            ok
    end.

uninit_mnesia() ->
    mnesia:del_table_copy(?FLOW_TAB, node()),
    ok.

default_method() ->
    application:get_env(sserl, default_method, rc4_md5).

default_ip() ->
    application:get_env(sserl, default_ip, undefined).

insert_flow(Flow) ->
    case mnesia:wread({?FLOW_TAB, Flow#flow.port}) of
        [] ->
            mnesia:write(?FLOW_TAB, Flow, write);
        [OldFlow] ->
            NewFlow = OldFlow#flow{max_flow=Flow#flow.max_flow, 
                                   method=Flow#flow.method, 
                                   password=Flow#flow.password},
            mnesia:write(?FLOW_TAB, NewFlow, write)
    end.
    
%% parse flow to listener args
flow_to_args(#flow{port=Port, method=Method, password=Password}) ->
    Method1 = case Method of
                  "" ->
                      default_method();
                  _ ->
                      Method
              end,
    [{port, Port}, {ip, default_ip()}, {method, Method1}, {password, Password}].

sync_users() ->
    case mysql_poolboy:execute(?MYSQL_ID, users, []) of
        {ok, _, Users} ->
            F = fun() ->
                  [insert_flow(list_to_tuple([flow|trip_binary(User)])) || User <- Users]
                end,
            mnesia:transaction(F), 
            ok;
         _ ->
            ok
    end.

do_report(NodeId, Rate, Min) ->
    Flows = ets:select(?LOG_TAB, [{{'_','_','$1','_'}, [{'>','$1',Min}], ['$_']},
                                  {{'_','_','_','$1'}, [{'>','$1',Min}], ['$_']}]),
    F = fun(Pid) ->
                lists:map(fun({_Port, Uid, D, U}) ->
                                  ok = mysql:execute(Pid, report, [D, U, Uid]),
                                  mysql:execute(Pid, log, [Uid, U, D, NodeId, Rate, traffic_string((U+D)*Rate)])
                          end, Flows),
                ok
        end,
    case catch mysql_poolboy:transaction(?MYSQL_ID, F) of
        {atomic, _} ->
            [ets:update_element(?LOG_TAB, P, [{3, 0},{4,0}]) || {P, _,_,_} <- Flows],
            ok;
        Error ->
            Error
    end.

get_rate(NodeId, OldRate) ->
    case catch mysql_poolboy:execute(?MYSQL_ID, rate, [NodeId]) of
        {ok, _, [[Rate]]} ->                               
            Rate;
        _ ->
            OldRate
    end.

traffic_string(T) when T > 1047527424 ->
    io_lib:format("~pGB", [round(T/1073741824*100)/100]);
traffic_string(T) when T > 1022976 ->
    io_lib:format("~pMB", [round(T/1048576*100)/100]);
traffic_string(T) ->
    io_lib:format("~pKB", [round(T/1024*100)/100]).

trip_binary(L) ->
    lists:map(fun(I) when is_binary(I) ->
                      binary_to_list(I);
                 (I) ->
                      I
              end, L).

