#!/bin/bash

nums=$1
echo "[id=1,name=example,default=permit]"
for i in `seq 1 $nums`
do
    echo "resource.OFPPacketIn.tp_dst=$i,decision=deny"
done