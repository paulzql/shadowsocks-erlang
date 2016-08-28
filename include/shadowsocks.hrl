%% Definition of macros and constants for socksv5
-define(SOCKS5_VER, 16#05).

-define(SOCKS5_AUTH_NONE,   16#00).
-define(SOCKS5_AUTH_GSSAPI, 16#01).
-define(SOCKS5_AUTH_USER,   16#02).
-define(SOCKS5_AUTH_ERR,    16#ff).

-define(SOCKS5_REQ_CONNECT,  16#01).
-define(SOCKS5_REQ_BIND,     16#02).
-define(SOCKS5_REQ_UDP_ASSOC,16#03).

-define(SOCKS5_ATYP_V4,  16#01).
-define(SOCKS5_ATYP_DOM, 16#03).
-define(SOCKS5_ATYP_V6,  16#04).

-define(SOCKS5_REP_OK,   16#00).
-define(SOCKS5_REP_FAIL, 16#01).
-define(SOCKS5_REP_NOT_ALLOWED, 16#02).
-define(SOCKS5_REP_NET_UNREACHABLE, 16#03).
-define(SOCKS5_REP_HOST_UNREACHABLE, 16#04).
-define(SOCKS5_REP_REFUSED, 16#05).
-define(SOCKS5_REP_TTL_EXPIRED, 16#06).
-define(SOCKS5_REP_CMD_NOT_SUPPORTED, 16#07).
-define(SOCKS5_REP_ATYP_NOT_SUPPORTED, 16#08).

-define(SOCKS5_RESERVED_FIELD, 16#00).

-define(IS_OTA(Atyp), (Atyp band 16#10) =:= 16#10).
-define(OTA_ATYP_V4, 16#11).
-define(OTA_ATYP_V6, 16#14).
-define(OTA_ATYP_DOM,16#13).
-define(GET_ATYP(Atyp), Atyp band 16#0F).
-define(OTA_FLAG, 16#10).

-define(HMAC_LEN, 10).
-define(OTA_HEAD_LEN, 12).

%% cipher info
-record(cipher_info, {
          method=rc4_md5,      %% rc4_md5 | aes_128_cfb | des_cfb | aes_192_cfb | aes_256_cfb
          key,
          encode_iv,
          iv_sent = false,     %% true | false
          decode_iv,
          stream_enc_state,    %% used in AES CTR and RC4 mode
          stream_dec_state,     %% used in AES CTR and RC4 mode
          enc_rest = <<>>,
          dec_rest = <<>>
         }).


