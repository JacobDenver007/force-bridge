#!/usr/bin/env bash

set -e
set -x

PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && cd ../.. && pwd )"
cd "${PROJECT_DIR}"
tsc
npm link
cp config.json config-cli.json

FORCE_BRIDGE_CLI=forcecli
CKB_PRIVATE_KEY=0xa800c82df5461756ae99b5c6677d019c98cc98c7786b80d7b2e77256e46ea1fe
CKB_RECIPIENT_ADDRESS=ckt1qyqyph8v9mclls35p6snlaxajeca97tc062sa5gahk
ETH_LOCKED_PRIVATE_KEY=0x719e94ec5d2ecef67b5878503ffd6e1e0e2fe7a52ddd55c436878cb4d52d376d
ETH_RECIPIENT_ADDRESS=0x8951a3DdEf2bB36fF3846C3B6968812C269f4561

${FORCE_BRIDGE_CLI} eth balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
${FORCE_BRIDGE_CLI} eth lock -p ${ETH_LOCKED_PRIVATE_KEY} -r ${CKB_RECIPIENT_ADDRESS} -a 0.1
#TODO query lock result until lock success
sleep 60
${FORCE_BRIDGE_CLI} eth balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
${FORCE_BRIDGE_CLI} eth unlock -p ${CKB_PRIVATE_KEY} -a 0.1 -r ${ETH_RECIPIENT_ADDRESS}
#TODO query lock result until unlock success
sleep 60
${FORCE_BRIDGE_CLI} eth balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#
#EOS_LOCKED_ACCOUNT=alice
#EOS_LOCKED_PRIVATE_KEY=5KQG4541B1FtDC11gu3NrErWniqTaPHBpmikSztnX8m36sK5px5
#
#${FORCE_BRIDGE_CLI} eos balanceOf -addr ${CKB_RECIPIENT_ADDRESS} -s EOS
#${FORCE_BRIDGE_CLI} eos lock -p ${EOS_LOCKED_PRIVATE_KEY} -acc ${EOS_LOCKED_ACCOUNT} -r ${CKB_RECIPIENT_ADDRESS} -a '0.0001 EOS'
#sleep 60
#${FORCE_BRIDGE_CLI} eos balanceOf -addr ${CKB_RECIPIENT_ADDRESS} -s EOS
#${FORCE_BRIDGE_CLI} eos unlock -p ${CKB_PRIVATE_KEY} -a '0.0001 EOS' -r ${EOS_LOCKED_ACCOUNT}
#sleep 60
#${FORCE_BRIDGE_CLI} eos balanceOf -addr ${CKB_RECIPIENT_ADDRESS} -s EOS
#
#TRON_LOCKED_PRIVATE_KEY=AECC2FBC0BF175DDD04BD1BC3B64A13DB98738962A512544C89B50F5DDB7EBBD
#TRON_RECIPIENT_ADDRESS=TS6VejPL8cQy6pA8eDGyusmmhCrXHRdJK6
#
#${FORCE_BRIDGE_CLI} tron balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#${FORCE_BRIDGE_CLI} tron lock -p ${TRON_LOCKED_PRIVATE_KEY} -r ${CKB_RECIPIENT_ADDRESS} -a 0.1
#sleep 60
#${FORCE_BRIDGE_CLI} tron balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#${FORCE_BRIDGE_CLI} tron unlock -p ${CKB_PRIVATE_KEY} -a 0.1 -r ${TRON_RECIPIENT_ADDRESS}
#sleep 60
#${FORCE_BRIDGE_CLI} tron balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#
#BTC_LOCKED_PRIVATE_KEY=cURtxPqTGqaA5oLit5sMszceoEAbiLFsTRz7AHo23piqamtxbzav
#BTC_LOCKED_ADDRESS=bcrt1q0yszr82fk9q8tu9z9ddxxvwqmlrdycsy378znz
#
#${FORCE_BRIDGE_CLI} btc balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#${FORCE_BRIDGE_CLI} btc lock -u ${BTC_LOCKED_ADDRESS} -p ${BTC_LOCKED_PRIVATE_KEY} -r ${CKB_RECIPIENT_ADDRESS} -a 0.1
#sleep 60
#${FORCE_BRIDGE_CLI} btc balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
#${FORCE_BRIDGE_CLI} btc unlock -p ${CKB_PRIVATE_KEY} -a 0.1 -r ${BTC_LOCKED_ADDRESS}
#sleep 60
#${FORCE_BRIDGE_CLI} btc balanceOf -addr ${CKB_RECIPIENT_ADDRESS}
