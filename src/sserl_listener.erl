%%%-------------------------------------------------------------------
%%% @author paul <paul@hupaul.com>
%%% @copyright (C) 2016, paul
%%% @doc
%%%
%%% @end
%%% Created : 15 May 2016 by paul <paul@hupaul.com>
%%%-------------------------------------------------------------------
-module(sserl_listener).

-behaviour(gen_server).

%% API
-export([start_link/1, get_port/1, update/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("sserl.hrl").

-define(SERVER, ?MODULE).
-define(MAX_LIMIT, 16#0FFFFFFFFFFFFFFF).

-record(state, {
          ota,          % one time auth
          port,         % listen port
          lsocket,      % listen socket
          conn_limit,   % connection count limit
          expire_time,  % expire time
          password,     % 
          method,       % 
          accepting,     % is accepting new connection?
          conns = 0,    % current connection count
          expire_timer = undefined, % expire timer
          type = server,
          server = undefined % server {address, port}
}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(Args) ->
    %% get configs
    Type      = proplists:get_value(type, Args, server),
    IP        = proplists:get_value(ip, Args),
    Port     = proplists:get_value(port, Args),
    ConnLimit = proplists:get_value(conn_limit,  Args, ?MAX_LIMIT),
    ExpireTime= proplists:get_value(expire_time, Args, max_time()),
    OTA       = proplists:get_value(ota, Args, false),
    Password  = proplists:get_value(password, Args),
    Method    = parse_method(proplists:get_value(method, Args, rc4_md5)),
    CurrTime  = os:system_time(milli_seconds),
    Server    = proplists:get_value(server, Args),
    %% validate args
    ValidMethod = lists:any(fun(M) -> M =:= Method end, shadowsocks_crypt:methods()),
    if
        Type =/=server andalso Type =/= client ->
            {error, {badargs, invalid_type}};
        Type =:= client andalso Server =:= undefined ->
            {error, {badargs, client_need_server}};
        Port < 0 orelse Port > 65535 ->
            {error, {badargs, port_out_of_range}};
        not is_integer(ConnLimit) ->
            {error, {badargs, conn_limit_need_integer}};
        not ValidMethod ->
            {error, {badargs, unsupported_method}};
        not is_list(Password) ->
            {error, {badargs, password_need_list}};
        CurrTime >= ExpireTime ->
            {error, expired};
        true ->
            State = #state{ota=OTA, port=Port, lsocket=undefined, 
                           type = Type,
                           conn_limit=ConnLimit, 
                           expire_time=ExpireTime,
                           password=Password, method=Method, 
                           server = Server,
                           expire_timer=erlang:start_timer(max_time(ExpireTime), self(), expire, [{abs,true}])},
            gen_server:start_link(?MODULE, [State,IP], [])
    end.

get_port(Pid) ->
    gen_server:call(Pid, get_port).

update(Pid, Args) ->
    gen_server:call(Pid, {update, Args}).

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
init([State,IP]) ->
    process_flag(trap_exit, true),

    Opts = [binary, {backlog, 20},{nodelay, true}, {active, false}, 
            {packet, raw}, {reuseaddr, true},{send_timeout_close, true}],
    %% get the ip address
    Opts1 = case IP of
        undefined ->
            Opts;
        Addr ->
             Opts++[{ip, Addr}]
    end,
    %% start listen
    case gen_tcp:listen(State#state.port, Opts1) of
        {ok, LSocket} ->
            %% set to async accept, so we can do many things on this process
            case prim_inet:async_accept(LSocket, -1) of
                {ok, _} ->
                    gen_event:notify(?STAT_EVENT, {listener, new, State#state.port}),
                    {ok, State#state{lsocket=LSocket}};
                {error, Error} ->
                    {stop, Error}
            end;
        Error ->
            {stop, Error}
    end.


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
handle_call(get_port, _From, State=#state{port=Port}) ->
    {reply, Port, State};

%% update args
handle_call({update, Args}, _From, State) ->
    ConnLimit  = proplists:get_value(conn_limit,  Args, State#state.conn_limit),
    ExpireTime = proplists:get_value(expire_time, Args, State#state.expire_time),
    Password  = proplists:get_value(password, Args, State#state.password),
    Method     = parse_method(proplists:get_value(method, Args, State#state.method)),    
    %% reset expire timer
    erlang:cancel_timer(State#state.expire_timer, []),
    ExpireTimer = erlang:start_timer(max_time(ExpireTime), self(), expire, [{abs,true}]),

    {reply, ok, State#state{conn_limit = ConnLimit,
                            expire_time= ExpireTime,
                            password   = Password,
                            method     = Method,
                            expire_timer=ExpireTimer
                           }};

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
%% 超过使用期，停止进程
handle_info({timeout, _Ref, expire}, State) ->
    {stop, expire, State};

handle_info({inet_async, _LSocket, _Ref, {ok, CSocket}}, 
            State=#state{ota=OTA, port=Port, type=Type, 
                         method=Method,password=Password, server=Server, conns=Conns}) ->
    true = inet_db:register_socket(CSocket, inet_tcp), 
    {ok, {Addr, _}} = inet:peername(CSocket),
    gen_event:notify(?STAT_EVENT, {listener, accept, Port, Addr}),

    {ok, Pid} = sserl_conn:start_link(CSocket, {Port, Server, OTA, Type, {Method, Password}}),

    case gen_tcp:controlling_process(CSocket, Pid) of
        ok ->
            gen_event:notify(?STAT_EVENT, {conn, open, Pid}),            
            Pid ! {shoot, CSocket};
        {error, _} ->
            exit(Pid, kill),
            gen_tcp:close(CSocket)
    end,

    case prim_inet:async_accept(State#state.lsocket, -1) of
        {ok, _} ->
            {noreply, State#state{conns=Conns+1}};
        {error, Ref} ->
            {stop, {async_accept, inet:format_error(Ref)}, State#state{conns=Conns+1}}
    end;

handle_info({inet_async, _LSocket, _Ref, Error}, State) ->
    {stop, Error, State};

handle_info({'EXIT', Pid, Reason}, State = #state{conns=Conns}) ->
    gen_event:notify(?STAT_EVENT, {conn, close, Pid, Reason}),
    {noreply, State#state{conns=Conns-1}};

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
max_time() ->
    erlang:convert_time_unit(erlang:system_info(end_time), native, milli_seconds).
max_time(Time) ->
    erlang:min(Time, max_time()).


parse_method(Method) when is_list(Method); is_binary(Method) ->
    list_to_atom(re:replace(Method, "-", "_", [global, {return, list}]));
parse_method(Method) when is_atom(Method) ->
    Method.
