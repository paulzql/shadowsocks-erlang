#!/bin/sh
# -*- coding: utf-8 -*-
# by paul <>
#---------------------------------------------

erl +K true -pa . -pa _build/default/lib/mnesia_cluster/ebin -pa _build/default/lib/sserl/ebin -kernel inetrc inetrc -run sserl start
