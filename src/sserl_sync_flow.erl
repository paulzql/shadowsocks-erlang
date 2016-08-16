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

-define(FORM_TYPE, "application/x-www-form-urlencoded;charset=UTF-8").
-define(FORM_HEADER, {"Content-Type","application/x-www-form-urlencoded;charset=UTF-8"}).
-define(HTTPC_OPTIONS, [{body_format, binary}]).
-define(TIMEOUT, 10000).

-record(state, {}).

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
    case init_mnesia() of
        ok ->
            ets:new(?LOG_TAB, [public, named_table]),
            {ok, #state{}};
        Error ->
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
handle_info(_Info, State) ->
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
            case mnesia:create_table(?FLOW_TAB, [{type, set}, {ram_copies, [node()]}, {attributes, record_info(fields, flow)}]) of
                {atomic, ok} ->
                    ok;
                {aborted,{already_exists, Name}} ->
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
                                              method   = binary_to_list(proplists:get_value(<<"method">>, D, <<"">>)),
                                              password = binary_to_list(proplists:get_value(<<"passwd">>, D, <<"">>))
                                              }
                              end, Data)};
                _ ->
                    {error, decode_json_failed}
            end;
        _ ->
            false
    end.

%% report flow
restful_report_flow(BaseUrl, Key, {NodeId, Uid, Download, Upload}) ->
    Url = lists:concat([BaseUrl, "/mu/users/", integer_to_list(Uid), "/traffic"]), 
    Str = io_lib:format("node_id=~ts&u=~ts&d=~ts", [NodeId, Upload, Download]),
    Form = list_to_binary(Str),
    case httpc:request(post, {Url, [{"key", Key}], ?FORM_TYPE, Form}, [], ?HTTPC_OPTIONS) of
        {ok, {{_, 200, _}, _, Body}} ->
            Ret = jsx:decode(Body),
            case proplists:get_value(<<"ret">>, Ret, -1) of
                1 ->
                    ok;
                _ ->
                    {error, proplists:get_value(<<"msg">>, Ret, "")}
            end;
        _ ->
            {error, request_failed}
    end.    


default_method() ->
    application:get_env(default_method, sserl, rc4_md5).


