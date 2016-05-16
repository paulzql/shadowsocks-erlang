%%%-------------------------------------------------------------------
%%% @author paul <paul@hupaul.com>
%%% @copyright (C) 2016, paul
%%% @doc
%%%
%%% @end
%%% Created : 15 May 2016 by paul <paul@hupaul.com>
%%%-------------------------------------------------------------------
-module(sserl_conn).

-behaviour(gen_server).

%% API
-export([start_link/2, init/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("shadowsocks.hrl").

-define(SERVER, ?MODULE).
-define(RECV_TIMOUT, 15000).

-record(state, {
          csocket,
          ssocket,
          type,
          limit,
          cipher_info
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
start_link(Socket, Info) ->
    proc_lib:start_link(?MODULE, init, [Socket, Info]).
    %% gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init(Socket, {Type, Method, Password, Limit}) ->
    proc_lib:init_ack({ok, self()}),
    wait_socket(Socket),
    State = #state{csocket=Socket, ssocket=undefined, 
                   type=Type, limit=Limit,
                   cipher_info=shadowsocks_crypt:init_cipher_info(Method, Password)},
    loop(State).


loop(State=#state{type=server, csocket=CSocket}) ->
    State1 = recv_ivec(State),
    {Addr, Port, State2, Data} = recv_target(State1),
    sserl_stat:notify({conn, new, Addr, Port}),
    case gen_tcp:connect(Addr, Port, [binary, {packet, raw}, {active, once},{nodelay, true}]) of
        {ok, SSocket} ->
            gen_tcp:send(SSocket, Data),
            inet:setopts(CSocket, [{active, once}]),
            gen_server:enter_loop(?MODULE, [], State2#state{ssocket=SSocket});
        {error, Reason} ->
            exit(Reason)
    end,
    ok.


    
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
%% 客户端来的数据
handle_info({tcp, CSocket, Data}, 
            State=#state{type=server, csocket=CSocket, ssocket=SSocket, cipher_info=CipherInfo}) ->
    inet:setopts(CSocket, [{active, once}]),
    {CipherInfo1, DecData} = shadowsocks_crypt:decode(CipherInfo, Data),
    gen_tcp:send(SSocket, DecData),
    {noreply, State#state{cipher_info=CipherInfo1}};
%% 服务端来的数据
handle_info({tcp, SSocket, Data}, 
            State=#state{type=server, csocket=CSocket, ssocket=SSocket, cipher_info=CipherInfo}) ->
    inet:setopts(SSocket, [{active, once}]),
    {CipherInfo1, EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(CSocket, EncData),
    {noreply, State#state{cipher_info=CipherInfo1}};

handle_info({tcp_closed, _Socket}, State) ->
    {stop, normal, State};

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

wait_socket(Socket) ->
    receive
        {shoot, Socket} ->
            ok;
        _ ->
            wait_socket(Socket)
    end.


%% 接收IV信息
recv_ivec(State = #state{cipher_info=#cipher_info{method=Method}}) when Method=:=table ->
    State;
recv_ivec(State = #state{csocket=Socket, 
                         cipher_info=#cipher_info{method=Method,key=Key}=CipherInfo}) ->
    {_, IvLen} = shadowsocks_crypt:key_iv_len(Method),
    {ok, IvData} = gen_tcp:recv(Socket, IvLen, ?RECV_TIMOUT),
    StreamSate = shadowsocks_crypt:stream_init(Method, Key, IvData),
    State#state{
      cipher_info=CipherInfo#cipher_info{
                    decode_iv=IvData, stream_dec_state=StreamSate
                   }
     }.

%% 接收目的地址信息
recv_target(State) ->
    {<<AddrType:8/big, Data/binary>>, State1} = recv_decode(1, <<>>, State),
    case AddrType of
        ?SOCKS5_ATYP_V4 ->
            {<<DestAddr:4/binary, DestPort:16/big, Data2/binary>>, State2} = recv_decode(6, Data, State1),
            {list_to_tuple(binary_to_list(DestAddr)), DestPort, State2, Data2};
        ?SOCKS5_ATYP_DOM ->
            {<<DomLen:8/big, Data2/binary>>, State2} = recv_decode(1, Data, State1),
            {<<Domain:DomLen/binary, DestPort:16/big, Data3/binary>>, State3} = recv_decode(DomLen+2, Data2, State2),
            {binary_to_list(Domain), DestPort, State3, Data3};
        _ ->
            io:format("error address type:~p~n", [AddrType]),
            exit({error_address_type, AddrType})
    end.


recv_decode(Len, Data, State) when byte_size(Data) >= Len ->
    {Data, State};
recv_decode(Len, Data, State = #state{csocket=Socket, cipher_info=CipherInfo}) ->
    {ok, Data1} = gen_tcp:recv(Socket, 0, ?RECV_TIMOUT),
    {CipherInfo1, Data2} = shadowsocks_crypt:decode(CipherInfo, Data1),
    Data3 = <<Data/binary, Data2/binary>>,
    recv_decode(Len, Data3, State#state{cipher_info=CipherInfo1}).

