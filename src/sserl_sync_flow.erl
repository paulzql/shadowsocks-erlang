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
-export([add_handler/3]).

%% gen_event callbacks
-export([init/1, handle_event/2, handle_call/2, 
         handle_info/2, terminate/2, code_change/3]).

-include("sserl.hrl").

-define(SERVER, ?MODULE).
-define(LOG_TAB, sserl_flow_log).
-define(FLOW_TAB, sserl_flow).

-define(FORM_TYPE, "application/x-www-form-urlencoded;charset=UTF-8").
-define(JSON_TYPE, "application/json").
-define(FORM_HEADER, {"Content-Type","application/x-www-form-urlencoded;charset=UTF-8"}).
-define(HTTPC_OPTIONS, [{body_format, binary}]).
-define(TIMEOUT, 10000).

-define(SYNC_INTERVAL, 5*60*1000).

-record(state, {
          node_id,
          baseurl,
          key
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
add_handler(NodeId, BaseUrl, Key) ->
    gen_event:add_handler(?FLOW_EVENT, ?MODULE, [NodeId,BaseUrl, Key]).

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
init([NodeId,BaseUrl, Key]) ->
    %% init sync users
    {ok, Flows} = restful_get_users(BaseUrl, Key),
    F = fun() ->
                [insert_flow(Flow) || Flow <- Flows]
        end,
                     
    case init_mnesia() of
        ok ->
            ets:new(?LOG_TAB, [public, named_table]),
            {ok, _} = mnesia:subscribe({table, ?FLOW_TAB, detailed}),
            {atomic, _} = mnesia:transaction(F),            
            error_logger:info_msg("[sserl_sync_flow] init ok ~p", [self()]),
            erlang:send_after(?SYNC_INTERVAL, self(), sync_timer),            
            {ok, #state{node_id=NodeId, baseurl=BaseUrl, key=Key}};
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
handle_event({report, Port, Download, Upload}, State) ->
    io:format("report: ~p~n", [{Port, Download, Upload}]),
    F = fun() ->
                case mnesia:wread({?FLOW_TAB, Port}) of
                    [Flow=#flow{download=D, upload=U}] ->
                        mnesia:write(?FLOW_TAB, Flow#flow{download=D+Download, upload=U+Upload}, write);
                    _ ->
                        ok
                end
        end,
    mnesia:transaction(F),
    ets:update_counter(?LOG_TAB, Port, [{2, Download}, {3, Upload}]),
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
handle_info({mnesia_table_event, {write, ?FLOW_TAB, 
                                  #flow{max_flow=F,method=M,password=P}, 
                                  [#flow{max_flow=F,method=M,password=P}],_}}, State) ->
    %% nothing to change
    {ok, State};
handle_info({mnesia_table_event, {write, ?FLOW_TAB, NewFlow, _, _}}, State) ->
    %% init log element
    case ets:lookup(?LOG_TAB, NewFlow#flow.port) of
        [] ->
            ets:insert(?LOG_TAB, {NewFlow#flow.port, 0, 0});
        _ -> 
            ok
    end,
    sserl_listener_sup:start(flow_to_args(NewFlow)),
    {ok, State};
handle_info({mnesia_table_event, {delete, {?FLOW_TAB, Port}, _}}, State) ->
    sserl_listener_sup:stop(Port),
    {ok, State};

handle_info(sync_timer, State = #state{node_id=Id, baseurl=Url, key=Key}) ->
    spawn(fun() ->
                  sync_proc(Url, Key)
          end),
    do_report(Id, Url, Key),
    erlang:send_after(?SYNC_INTERVAL, self(), sync_timer),
    {ok, State};

handle_info(Info, State) ->
    io:format("info:~p", [Info]),
    {ok, State}.

do_report(NodeId, Url, Key) ->
    Flows = ets:select(?LOG_TAB, [{{'_','$1','_'}, [{'>','$1',0}], ['$_']},
                                  {{'_','_','$1'}, [{'>','$1',0}], ['$_']}]),
    case restful_report_flow(Url, Key, NodeId, Flows) of
        ok ->
            [ets:update_element(?LOG_TAB, P, [{2, 0},{3,0}]) || {P, _,_} <- Flows],
            ok;
        Error ->
            Error
    end.

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
terminate(_Reason, _State) ->
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

%% get users info from remote api
restful_get_users(BaseUrl, Key) ->
    case httpc:request(get, {BaseUrl++"/mu/users", [{"key", Key}]}, [], ?HTTPC_OPTIONS) of
        {ok, {{_, 200, _}, _, Body}} ->
            Json = jsx:decode(Body),
            case {proplists:get_value(<<"ret">>, Json, 0), proplists:get_value(<<"data">>, Json, [])} of
                {1, Data} when is_list(Data) ->
                    {ok, lists:map(fun(D) ->
                                           #flow {
                                              port = proplists:get_value(<<"port">>, D, -1),
                                              uid  = proplists:get_value(<<"id">>, D, 0),
                                              max_flow = proplists:get_value(<<"transfer_enable">>, D, 0),
                                              download = proplists:get_value(<<"d">>, D, 0),
                                              upload   = proplists:get_value(<<"u">>, D, 0),
                                              method  = binary_to_list(proplists:get_value(<<"method">>, D, <<"">>)),
                                              password = binary_to_list(proplists:get_value(<<"passwd">>, D, <<"">>))
                                              }
                              end, Data)};
                _ ->
                    {error, decode_json_failed}
            end;
        _ ->
            error_logger:error_msg("http request failed: ~p", [BaseUrl++"/mu/users"]),
            false
    end.

%% report flow
%% restful_report_flow(BaseUrl, Key, {NodeId, Uid, Download, Upload}) ->
%%     Url = lists:concat([BaseUrl, "/mu/users/", integer_to_list(Uid), "/traffic"]), 
%%     Str = io_lib:format("node_id=~ts&u=~ts&d=~ts", [NodeId, Upload, Download]),
%%     Form = list_to_binary(Str),
%%     case httpc:request(post, {Url, [{"key", Key}], ?FORM_TYPE, Form}, [], ?HTTPC_OPTIONS) of
%%         {ok, {{_, 200, _}, _, Body}} ->
%%             Ret = jsx:decode(Body),
%%             case proplists:get_value(<<"ret">>, Ret, -1) of
%%                 1 ->
%%                     ok;
%%                 _ ->
%%                     {error, proplists:get_value(<<"msg">>, Ret, "")}
%%             end;
%%         _ ->
%%             error_logger:error_msg("http request failed: ~p", [Url]),
%%             {error, request_failed}
%%     end.  


%% report flow
restful_report_flow(BaseUrl, Key, NodeId, Flows) ->
    Url = lists:concat([BaseUrl, "/mu/nodes/", integer_to_list(NodeId), "/traffic"]), 
    Form = jsx:encode([[{<<"port">>, Port},{<<"d">>, D}, {<<"u">>, U}] || {Port,D,U} <- Flows]),
    case httpc:request(post, {Url, [{"key", Key}], ?JSON_TYPE, Form}, [], ?HTTPC_OPTIONS) of
        {ok, {{_, 200, _}, _, Body}} ->
            Ret = jsx:decode(Body),
            case proplists:get_value(<<"ret">>, Ret, -1) of
                1 ->
                    ok;
                _ ->
                    {error, proplists:get_value(<<"msg">>, Ret, "")}
            end;
        _ ->
            error_logger:error_msg("http request failed: ~p", [Url]),
            {error, request_failed}
    end.  

%% sync 
%% restful_sync_flow(BaseUrl, Key, Flows) ->
%%     Url = lists:concat([BaseUrl, "/mu/sync_traffic"]), 
%%     Form = jsx:encode([[{<<"id">>, Id},{<<"d">>, D}, {<<"u">>, U}] || #flow{uid=Id,download=D,upload=U} <- Flows]),

%%     case httpc:request(post, {Url, [{"key", Key}], ?JSON_TYPE, Form}, [], ?HTTPC_OPTIONS) of
%%         {ok, {{_, 200, _}, _, Body}} ->
%%             Ret = jsx:decode(Body),
%%             case proplists:get_value(<<"ret">>, Ret, -1) of
%%                 1 ->
%%                     ok;
%%                 _ ->
%%                     {error, proplists:get_value(<<"msg">>, Ret, "")}
%%             end;
%%         _ ->
%%             error_logger:error_msg("http request failed: ~p", [Url]),
%%             {error, request_failed}
%%     end.   


default_method() ->
    application:get_env(default_method, sserl, rc4_md5).

default_ip() ->
    application:get_env(default_ip, sserl, undefined).

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


sync_proc(BaseUrl, Key) ->
    {ok, Flows} = restful_get_users(BaseUrl, Key),
    F = fun() ->
                [insert_flow(Flow) || Flow <- Flows]
        end,
                     
    mnesia:transaction(F), 
    ok.
