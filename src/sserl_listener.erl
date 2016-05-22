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

-define(SERVER, ?MODULE).
-define(MAX_LIMIT, 16#0FFFFFFFFFFFFFFF).

-record(state, {
          type,         % 类型
          port,         % 端口
          lsocket,      % 监听Socket
          conn_limit,   % 连接数限制
          flow_limit,   % 单连接流量限制
          max_flow,     % 最大流量
          expire_time,  % 失效时间
          password,     % 密码
          method,       % 加密类型
          accepting,     % 是否正在接收新连接
          conns = 0,    % 连接数
          flow = 0,     % 流量
          reported_flow = 0, % 已上报流量
          expire_timer = undefined % 过期时钟
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
    %% 获取配置信息
    Port       = proplists:get_value(port, Args),
    ConnLimit  = proplists:get_value(conn_limit,  Args, ?MAX_LIMIT),
    FlowLimit  = proplists:get_value(flow_limit,  Args, ?MAX_LIMIT),
    MaxFlow    = proplists:get_value(max_flow, Args, ?MAX_LIMIT),
    ExpireTime = proplists:get_value(expire_time, Args, ?MAX_LIMIT),
    Type       = proplists:get_value(type, Args, server),
    Password  = proplists:get_value(password, Args),
    Method     = proplists:get_value(method, Args, table),
    IP        = proplists:get_value(ip, Args, undefined),
    %% 校验参数
    ValidMethod = lists:any(fun(M) -> M =:= Method end, shadowsocks_crypt:methods()),
    if
        not is_integer(Port) ->
            {error, {badargs, port_need_integer}};
        Port < 0 orelse Port > 65535 ->
            {error, {badargs, port_out_of_range}};
        not is_integer(ConnLimit) ->
            {error, {badargs, conn_limit_need_integer}};
        not is_integer(FlowLimit) ->
            {error, {badargs, flow_limit_need_integer}};
        Type =/= server andalso Type =/= client ->
            {error, {badargs, error_type}};
        not ValidMethod ->
            {error, {badargs, unsupported_method}};
        not is_list(Password) ->
            {error, {badargs, password_need_list}};
        true ->
            State = #state{type=Type, port=Port, lsocket=undefined, 
                           conn_limit=ConnLimit, 
                           flow_limit=FlowLimit, 
                           max_flow=MaxFlow,
                           expire_time=ExpireTime,
                           password=Password, method=Method, 
                           expire_timer=erlang:start_timer(ExpireTime, self(), expire, [{abs,true}])},
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
    %% 获取IP地址
    Opts1 = case IP of
        undefined ->
            Opts;
        Addr ->
             Opts++[{ip, Addr}]
    end,
    %% 开始监听
    case gen_tcp:listen(State#state.port, Opts1) of
        {ok, LSocket} ->
            %% 设置异步接收
            case prim_inet:async_accept(LSocket, -1) of
                {ok, _} ->
                    sserl_stat:notify({listener, new, State#state.port}),
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

handle_call({update, Args}, _From, State) ->
    ConnLimit  = proplists:get_value(conn_limit,  Args, ?MAX_LIMIT),
    FlowLimit  = proplists:get_value(flow_limit,  Args, ?MAX_LIMIT),
    MaxFlow    = proplists:get_value(max_flow, Args, ?MAX_LIMIT),
    ExpireTime = proplists:get_value(expire_time, Args, ?MAX_LIMIT),
    Password  = proplists:get_value(password, Args),
    Method     = proplists:get_value(method, Args, table),    

    erlang:cancel_timer(State#state.expire_timer, []),
    ExpireTimer = erlang:start_timer(ExpireTime, self(), expire, [{abs,true}]),
    {reply, ok, State#state{conn_limit = ConnLimit,
                     flow_limit = FlowLimit,
                     max_flow   = MaxFlow,
                     expire_time= ExpireTime,
                     password   = Password,
                     method     = Method,
                     expire_timer=ExpireTimer}};

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
            State=#state{type=Type, port=Port,method=Method, password=Password,flow_limit=FlowLimit,conns=Conns}) ->
    true = inet_db:register_socket(CSocket, inet_tcp), 
    {ok, {Addr, _}} = inet:peername(CSocket),
    sserl_stat:notify({listener, accept, Port, Addr}),

    {ok, Pid} = sserl_conn:start_link(CSocket, {Type, Method, Password, FlowLimit}),
    case gen_tcp:controlling_process(CSocket, Pid) of
        ok ->
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

%% 流量超了，结束进程
handle_info({report_flow, _Pid, _ConnFlow}, State=#state{flow=Flow,max_flow=MaxFlow}) when Flow >= MaxFlow ->
    {stop, exceed_flow, State};
handle_info({report_flow, _Pid, ConnFlow}, State=#state{flow=Flow}) ->
    {noreply, State#state{flow=Flow+ConnFlow}};

handle_info({'EXIT', _Pid, _Reason}, State = #state{conns=Conns,port=Port,flow=Flow,reported_flow=RFlow}) ->
    sserl_config:add_flow(Port, Flow-RFlow),
    {noreply, State#state{conns=Conns-1, reported_flow=Flow}};

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
terminate(_Reason, #state{port=Port,flow=Flow,reported_flow=RFlow}) ->
    sserl_config:add_flow(Port, Flow-RFlow),
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
