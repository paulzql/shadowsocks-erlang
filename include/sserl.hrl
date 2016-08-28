%% flow event report: {report, Port, Download, Upload}
%% 
-define(FLOW_EVENT, sserl_flow_event).

%% stat event
%%      new listener {listener, new, Port}
%%      accept    :  {listener, accept, Addr, Port}
%%      open      :  {conn, open, Pid}
%%      close     :  {conn, close, Pid, Reason}
%%      connect   :  {conn, connect, Addr, Port}
%% 
-define(STAT_EVENT, sserl_stat_event).


