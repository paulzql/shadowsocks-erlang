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
-include("sserl.hrl").

-define(SERVER, ?MODULE).
-define(RECV_TIMOUT, 180000).
-define(REPORT_INTERVAL, 1000).
-define(REPORT_MIN,   10485760). % 10MB

-define(TCP_OPTS, [binary, {packet, raw}, {active, once},{nodelay, true}]).


-record(state, {
          csocket,
          ssocket,
          ota,
          port,
          cipher_info,
          down = 0,
          up   = 0,
          sending = 0,
          ota_data = <<>>,
          ota_len = 2,
          ota_id = 0,
          ota_iv = <<>>
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

init(Socket, {OTA, Method, Password, Port}) ->
    proc_lib:init_ack({ok, self()}),
    wait_socket(Socket),
    State = #state{csocket=Socket, ssocket=undefined, 
                   ota=OTA, port=Port,
                   cipher_info=shadowsocks_crypt:init_cipher_info(Method, Password)},
    loop(State).


loop(State=#state{csocket=CSocket}) ->
    State1 = recv_ivec(State),
    {Addr, Port, Data, State2} = recv_target(State1),
    gen_event:notify(?STAT_EVENT, {conn, new, Addr, Port}),
    case gen_tcp:connect(Addr, Port, ?TCP_OPTS) of
        {ok, SSocket} ->
            self() ! {send, Data},
            inet:setopts(CSocket, [{active, once}]),
            erlang:send_after(?REPORT_INTERVAL, self(), report_flow),
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

%% client tcp data 
handle_info({tcp, CSocket, Data}, 
            State=#state{ota=false, csocket=CSocket, ssocket=SSocket, 
                         cipher_info=CipherInfo,up=Flow,sending=S}) ->
    inet:setopts(CSocket, [{active, once}]),
    {CipherInfo1, DecData} = shadowsocks_crypt:decode(CipherInfo, Data),
    S1 = try_send(SSocket, DecData),
    {noreply, State#state{cipher_info=CipherInfo1, up=Flow+size(Data), sending=S+S1}};
%% server tcp data
handle_info({tcp, SSocket, Data}, 
            State=#state{csocket=CSocket, ssocket=SSocket, cipher_info=CipherInfo, 
                         down=Flow,sending=S}) ->
    inet:setopts(SSocket, [{active, once}]),
    {CipherInfo1, EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    S1 = try_send(CSocket, EncData),
    {noreply, State#state{cipher_info=CipherInfo1, down=Flow+size(Data), sending=S+S1}};
%% client ota tcp data
handle_info({tcp, CSocket, Data}, State = #state{ota=true, csocket=CSocket,ota_data=Rest, 
                                                 cipher_info=CipherInfo}) ->
    inet:setopts(CSocket, [{active, once}]),
    {CipherInfo1, DecData} = shadowsocks_crypt:decode(CipherInfo, Data),    
    handle_ota(State#state{ota_data= <<Rest/binary, DecData/binary>>, cipher_info=CipherInfo1});
 
%% socket send reply
handle_info({inet_reply, _Socket, _Error}, State = #state{csocket=undefined,sending=1}) ->
    {stop, normal, State};
handle_info({inet_reply, _Socket, _Error}, State = #state{ssocket=undefined, sending=1}) ->
    {stop, normal, State};
handle_info({inet_reply, _, _}, State = #state{sending=N}) ->
    {noreply, State#state{sending=N-1}};
%% socket closed
handle_info({tcp_closed, _Socket}, State = #state{sending=0}) ->
    {stop, normal, State};
handle_info({tcp_closed, CSocket}, State = #state{csocket=CSocket}) ->
    {noreply, State#state{csocket=undefined}};
handle_info({tcp_closed, SSocket}, State = #state{ssocket=SSocket}) ->
    {noreply, State#state{ssocket=undefined}};
%% report flow
handle_info(report_flow, State = #state{port=Port,down=Down,up=Up}) when Down + Up >= ?REPORT_MIN ->
    gen_event:notify(?FLOW_EVENT, {report, Port, Down, Up}),
    erlang:send_after(?REPORT_INTERVAL, self(), report_flow),
    {noreply, State#state{down=0, up=0}};
handle_info(report_flow, State) ->
    erlang:send_after(?REPORT_INTERVAL, self(), report_flow),
    {noreply, State};

%% first send
handle_info({send, Data}, State=#state{ota=false,ssocket=SSocket, up=Flow, sending=S}) ->
    S1 = try_send(SSocket, Data),
    {noreply, State#state{sending=S+S1, up=Flow+size(Data)}};
handle_info({send, Data}, State=#state{ota=true, ota_data=Rest}) ->
    handle_ota(State#state{ota_data= <<Rest/binary, Data/binary>>});

handle_info(_Info, State) ->
    {noreply, State}.

%% handle ota frame
handle_ota(State = #state{ota_data=Data, ota_len=2}) when byte_size(Data) >= 2 ->
    <<DataLen:16/big, _/binary>> = Data,
    handle_ota(State#state{ota_len=DataLen+12});
handle_ota(State = #state{ota_iv=Iv,ota_data=Data, ota_len=Len, ota_id=Id,
                         ssocket=SSocket, up=Flow, sending=S}) when byte_size(Data) >= Len ->
    DataLen = Len-12,
    <<_:16/big, Hmac:10/binary, FrameData:DataLen/binary, Rest/binary>> = Data,
    case shadowsocks_crypt:hmac([Iv, <<Id:32/big>>], FrameData) of
        Hmac ->
            S1 = try_send(SSocket, FrameData),
            handle_ota(State#state{up=Flow+size(FrameData), sending=S+S1, ota_data=Rest,ota_len=2,ota_id=Id+1});   
        _ ->
            {stop, {error, bad_ota_hmac}, State}
    end;
handle_ota(State) ->
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
terminate(Reason, State) ->
    gen_event:notify(?STAT_EVENT, {conn, close, Reason}),
    gen_event:notify(?FLOW_EVENT, {report, State#state.port, State#state.down, State#state.up}),
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


%% recv the iv data
recv_ivec(State = #state{csocket=Socket, 
                         cipher_info=#cipher_info{method=Method,key=Key}=CipherInfo}) ->
    {_, IvLen} = shadowsocks_crypt:key_iv_len(Method),
    {ok, IvData} = gen_tcp:recv(Socket, IvLen, ?RECV_TIMOUT),
    StreamSate = shadowsocks_crypt:stream_init(Method, Key, IvData),
    State#state{
      ota_iv = IvData,
      cipher_info=CipherInfo#cipher_info{
                    decode_iv=IvData, stream_dec_state=StreamSate
                   }
     }.

%% recv and decode target addr and port
recv_target(State) ->
    {<<AddrType:8/big, Data/binary>>, State1} = recv_decode(1, <<>>, State),
    {IPPort, Addr, Port, Rest, NewState} = 
        case ?GET_ATYP(AddrType) of
            ?SOCKS5_ATYP_V4 ->
                {<<Data1:6/binary, Data2/binary>>, State2} = recv_decode(6, Data, State1),
                <<IP1:8/big,IP2:8/big,IP3:8/big,IP4:8/big, DestPort:16/big>> = Data1,
                {Data1, {IP1,IP2,IP3,IP4}, DestPort, Data2, State2};
            ?SOCKS5_ATYP_V6 ->
                {<<Data1:18/binary, Data2/binary>>, State2} = recv_decode(18, Data, State1),
                <<IP1:16/big,IP2:16/big,IP3:16/big,IP4:16/big, 
                  IP5:16/big,IP6:16/big,IP7:16/big,IP8:16/big, 
                  DestPort:16/big>> = Data1,
                {Data1, {IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8}, DestPort, Data2, State2};
            ?SOCKS5_ATYP_DOM ->
                {<<DomLen:8/big, Data1/binary>>, State2} = recv_decode(1, Data, State1),
                DPLen = DomLen+2,
                {<<Data2:DPLen/binary, Data3/binary>>, State3} = recv_decode(DomLen+2, Data1, State2),
                <<Domain:DomLen/binary, DestPort:16/big>> = Data2,
                {[DomLen,Data2], binary_to_list(Domain), DestPort, Data3, State3};
            _ ->
                throw({error_address_type, AddrType})
        end,
    case {?IS_OTA(AddrType), NewState#state.ota} of
        {true, _} ->
            {<<Hmac:?HMAC_LEN/binary, Rest2/binary>>, NewState2} = recv_decode(?HMAC_LEN, Rest, NewState),
            #cipher_info{key=Key} = NewState2#state.cipher_info,
            case shadowsocks_crypt:hmac([NewState2#state.ota_iv, Key], [AddrType, IPPort]) of
                Hmac ->
                    {Addr, Port, Rest2, NewState2#state{ota=true}};
                _ ->
                    throw({error, ota_bad_hmac})
            end;
        {_, true} ->
            throw({error, missing_ota});
        {false, false} ->
            {Addr, Port, Rest, NewState#state{ota=false}}
    end.

%% recv and decode data until got intput length
recv_decode(Len, Data, State) when byte_size(Data) >= Len ->
    {Data, State};
recv_decode(Len, Data, State = #state{csocket=Socket, cipher_info=CipherInfo}) ->
    {ok, Data1} = gen_tcp:recv(Socket, 0, ?RECV_TIMOUT),
    {CipherInfo1, Data2} = shadowsocks_crypt:decode(CipherInfo, Data1),
    Data3 = <<Data/binary, Data2/binary>>,
    recv_decode(Len, Data3, State#state{cipher_info=CipherInfo1}).

%% try to send package
%% return 1 if success else return 0
try_send(Socket, Data) ->
    try erlang:port_command(Socket, Data) of
        _ -> 1
    catch 
        error:_E -> 0
    end.
