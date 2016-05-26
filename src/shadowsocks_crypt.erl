-module(shadowsocks_crypt).

%% API
-export([methods/0, init_cipher_info/2, encode/2, decode/2, key_iv_len/1, stream_init/3]).

-include("shadowsocks.hrl").

methods() ->
    [rc4_md5, table, aes_128_cfb, aes_192_cfb, aes_256_cfb, none].

%%--------------------------------------------------------------------
%% @doc
%% Return the cipher information
%% 
%% @spec cipher_info(Method, Password::string()) -> 
%%                       {default, EncTable::list(), DecTable::list()} |
%%                       {Method, Key::binary(), IvEnc::binary(), IvDec::binanry()}
%%      Method := table | rc4 | des_cfb | chacha20_poly1305 | aes_cfb128
%% @end
%%--------------------------------------------------------------------
init_cipher_info(table, Password) ->
    <<Value:64/little-unsigned-integer, _:64/little-unsigned-integer>> 
        = crypto:hash(md5,Password),
    Init = lists:seq(0, 255),
    EncTable = lists:foldl(
                 fun(I, Acc) ->
                         lists:sort(
                           fun(X, Y) ->
                                   Value rem (X + I) =< Value rem (Y + I)
                           end, Acc) 
                 end, Init, lists:seq(1,1023)),
    ZipTable = lists:zip(Init, EncTable),
    ZipDecTable = lists:keysort(1, [{N, M} || {M, N} <- ZipTable]),
    DecTable = [M || {_, M} <- ZipDecTable],
    #cipher_info{method=table, 
                 table={list_to_tuple(EncTable), list_to_tuple(DecTable)}};

 init_cipher_info(none, _) ->
    ok;

init_cipher_info(Method, Password) ->
    {KeyLen, IvLen} = key_iv_len(Method),
    {Key, _NewIv} = evp_bytestokey(Password, KeyLen, IvLen),
    %% use another random Iv, but not the one returned from evp_bytestokey()
    NewIv = crypto:rand_bytes(IvLen),
    #cipher_info{method=Method, key=Key, encode_iv=NewIv, decode_iv=undefined,
                stream_enc_state = stream_init(Method, Key, NewIv)}.

%%--------------------------------------------------------------------
%% @doc 
%% Encode function
%% @spec encode(CipherInfo, Data) -> Data
%%      CipherInfo := cipher_info()
%%      Data := iolist() | binary()
%% @end
%%--------------------------------------------------------------------
encode(#cipher_info{method=none}, Data) ->
    Data;

encode(#cipher_info{method=table, table={EncTable, _}}=CipherInfo, Data) ->
    {CipherInfo, transform(EncTable, Data)};

encode(#cipher_info{iv_sent = false, encode_iv=Iv}=CipherInfo, Data) ->
    NewCipherInfo = CipherInfo#cipher_info{iv_sent=true},
    {NewCipherInfo1, EncData} = encode(NewCipherInfo, Data), 
    {NewCipherInfo1, <<Iv/binary, EncData/binary>>};

encode(#cipher_info{method=rc4_md5, stream_enc_state=S}=CipherInfo, Data) ->
    {S1, EncData} = crypto:stream_encrypt(S, Data),
    {CipherInfo#cipher_info{stream_enc_state=S1}, EncData};

encode(#cipher_info{method=_Method, key=Key, encode_iv=Iv, enc_rest=Rest}=CipherInfo, Data) ->
    DataSize = size(Data),
    RestSize = size(Rest),
    BufLen = (DataSize+RestSize) div 16 * 16,
    
    <<Data2:BufLen/binary, Rest2/binary>> = <<Rest/binary, Data/binary>>,
    EncData = crypto:block_encrypt(aes_cfb128, Key, Iv, Data2),
    NewIv = binary:part(<<Iv/binary, EncData/binary>>, size(EncData)+16, -16),
    EncRest = crypto:block_encrypt(aes_cfb128, Key, NewIv, Rest2),
    Result = binary:part(<<EncData/binary, EncRest/binary>>, RestSize, DataSize),
    {CipherInfo#cipher_info{encode_iv=NewIv, enc_rest=Rest2}, Result}.


%%--------------------------------------------------------------------
%% @doc 
%% Decode function
%% @spec decode(CipherInfo, Data) -> Data
%%      CipherInfo := {default, EncTable::list(), DecTable::list()} |
%%                    {Method, Key::binary(), Iv::binary()}
%%      Method := default | rc4 | des_cfb
%%      Data := iolist() | binary()
%% @end
%%--------------------------------------------------------------------
decode(#cipher_info{method=none}, Data) ->
    Data;

decode(#cipher_info{method=table, table={_, DecTable}}=CipherInfo, EncData) ->
    {CipherInfo, transform(DecTable, EncData)};

decode(#cipher_info{method=rc4_md5, stream_dec_state=S}=CipherInfo, EncData) ->
    {S1, Data} = crypto:stream_decrypt(S, EncData),
    {CipherInfo#cipher_info{stream_dec_state=S1}, Data};

decode(#cipher_info{method=_Method, key=Key, decode_iv=Iv, dec_rest=Rest}=CipherInfo, EncData) ->
    DataSize = size(EncData),
    RestSize = size(Rest),
    BufLen = (DataSize+RestSize) div 16 * 16,
    <<EncData2:BufLen/binary, Rest2/binary>> = <<Rest/binary, EncData/binary>>,

    Data = crypto:block_decrypt(aes_cfb128, Key, Iv, EncData2),
    NewIv = binary:part(<<Iv/binary, EncData2/binary>>, size(EncData2)+16, -16),
    DecRest = crypto:block_decrypt(aes_cfb128, Key, NewIv, Rest2),
    Result = binary:part(<<Data/binary, DecRest/binary>>, RestSize, DataSize),

    {CipherInfo#cipher_info{decode_iv=NewIv, dec_rest=Rest2}, Result}.

%%--------------------------------------------------------------------
%% @doc
%% Decode or encode the data with default table ciphe method
%%
%% @spec transform(Table, Data) -> Data
%%      Table := [tuple()]
%%      Data := iolist() | binary()
%% @end
%%--------------------------------------------------------------------
transform(Table, Data) when is_binary(Data)->
    << <<(element(X+1, Table))>> || <<X>> <= Data >>;
transform(Table, Data) when is_list(Data) ->
    [ element(X+1, Table) || X <- Data ].

%%--------------------------------------------------------------------
%% @doc 
%% Creates a key and an IV for doing encryption, from a password, 
%% using a hashing function.
%% @spec evp_bytestokey(HashMethod::hash_method(), Password::string(), 
%%                      KeyLen::integer(), IvLen::integer()) ->
%%      {Key::binary(), Iv::binary()}
%% @end
%%--------------------------------------------------------------------
evp_bytestokey(Password, KeyLen, IvLen) ->
    evp_bytestokey_aux(list_to_binary(Password), KeyLen, IvLen, <<>>).

evp_bytestokey_aux(_, KeyLen, IvLen, Acc) when KeyLen + IvLen =< size(Acc) ->
    <<Key:KeyLen/binary, Iv:IvLen/binary, _/binary>> = Acc,
    {Key, Iv};

evp_bytestokey_aux(Password, KeyLen, IvLen, Acc) ->
    Digest = crypto:hash(md5, <<Acc/binary, Password/binary>>),
    NewAcc = <<Acc/binary, Digest/binary>>,
    evp_bytestokey_aux(Password, KeyLen, IvLen, NewAcc).


key_iv_len(none) ->
    {0, 0};
key_iv_len(rc4_md5) ->
    {16, 16};
key_iv_len(aes_128_cfb) ->
    {16, 16};
key_iv_len(aes_192_cfb) ->
    {24, 16};
key_iv_len(aes_256_cfb) ->
    {32, 16};
key_iv_len(chacha20) ->
    {32, 8}.


stream_init(rc4_md5, Key, Iv) ->
    crypto:stream_init(rc4, crypto:hash(md5, <<Key/binary, Iv/binary>>));
stream_init(_, _, _) ->
    undefined.

%% 测试
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

rc4_test() ->

    Cipher = init_cipher_info(aes_128_cfb, "xx"),
    Data1 = <<"hello world">>,
    Data2 = <<"baby">>,
    {Cipher1, EnData1} = encode(Cipher, Data1),
    {Cipher2, EnData2} = encode(Cipher1, Data2),
    IV = Cipher1#cipher_info.encode_iv,
    {Cipher3, <<_IV:16/binary, DeData1/binary>>} = decode(Cipher1#cipher_info{decode_iv=IV}, EnData1),
    {_,       DeData2} = decode(Cipher3, EnData2),
    io:format("~p~n", [DeData1]),
    {0,11} = binary:match(Data1, [DeData1],[]),
    {0,4}  = binary:match(Data2, [DeData2],[]),
    ok.
-endif.
