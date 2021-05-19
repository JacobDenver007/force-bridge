import 'module-alias/register';
import { JSONRPCClient } from 'json-rpc-2.0';
import { ethers } from 'ethers';
import fetch from 'node-fetch/index';
import { Config } from '../../packages/config';
import { ForceBridgeCore } from '../../packages/core';
import { IndexerCollector } from '../../packages/ckb/tx-helper/collector';
import { CkbIndexer } from '../../packages/ckb/tx-helper/indexer';
import nconf from 'nconf';
import { asyncSleep } from '@force-bridge/utils';
import { initLog, logger } from '@force-bridge/utils/logger';
import { EthAsset } from '@force-bridge/ckb/model/asset';
import { Script, Amount } from '@lay2/pw-core';
import CKB from '@nervosnetwork/ckb-sdk-core/';
import { AddressPrefix } from '@nervosnetwork/ckb-sdk-utils';

const BATCH_NUM = 10;

const FORCE_BRIDGE_URL = 'http://47.56.233.149:3080/force-bridge/api/v1';

const ETH_NODE_URL = 'https://rinkeby.infura.io/v3/48be8feb3f9c46c397ceae02a0dbc7ae';
const RICH_ETH_WALLET_PRIV = '0x49740e7b29259e7c2b693f365a9fd581cef75d1e346c8dff89ec037cdfd9f89d';
const RICH_ETH_SENDER = '0xf7185B3B967fAEB46Ac9F15BDa82EC61E49F7795';

const ETH_TOKEN_ADDRESS = '0x0000000000000000000000000000000000000000';
const ERC20_TOKEN_ADDRESS = '0x7Af456bf0065aADAB2E6BEc6DaD3731899550b84';

const CKB_NODE_URL = 'https://testnet.ckbapp.dev';
const CKB_INDEXER_URL = 'https://testnet.ckbapp.dev/indexer';
const RICH_CKB_PRI_KEY = '0xd731ef492a844d401a1e9cb57b53aeaf840c80bd8acbd8c99b5240b2742e000e';

const ckb = new CKB(CKB_NODE_URL);

// JSONRPCClient needs to know how to send a JSON-RPC request.
// Tell it by passing a function to its constructor. The function must take a JSON-RPC request and send it.
const client = new JSONRPCClient((jsonRPCRequest) =>
  fetch(FORCE_BRIDGE_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: JSON.stringify(jsonRPCRequest),
  }).then((response) => {
    if (response.status === 200) {
      // Use client.receive when you received a JSON-RPC response.
      return response.json().then((jsonRPCResponse) => client.receive(jsonRPCResponse));
    } else if (jsonRPCRequest.id !== undefined) {
      return Promise.reject(new Error(response.statusText));
    }
  }),
);

async function lock(ethWallet, token_address, nonce, ckbRecipientAddress) {
  const lockPayload = {
    sender: ethWallet.address,
    recipient: ckbRecipientAddress,
    asset: {
      network: 'Ethereum',
      ident: token_address,
      amount: '1',
    },
  };
  const unsignedLockTx = await client.request('generateBridgeInNervosTransaction', lockPayload);
  logger.info('unsignedMintTx', unsignedLockTx);

  const provider = new ethers.providers.JsonRpcProvider(ETH_NODE_URL);

  const unsignedTx = unsignedLockTx.rawTransaction;
  unsignedTx.value = unsignedTx.value ? ethers.BigNumber.from(unsignedTx.value.hex) : ethers.BigNumber.from(0);
  unsignedTx.nonce = nonce;
  unsignedTx.gasLimit = ethers.BigNumber.from(1000000);
  unsignedTx.gasPrice = await provider.getGasPrice();

  logger.info('unsignedTx', unsignedTx);

  const signedTx = await ethWallet.signTransaction(unsignedTx);
  logger.info('signedTx', signedTx);

  const lockTxHash = (await provider.sendTransaction(signedTx)).hash;
  logger.info('lockTxHash', lockTxHash);
  return lockTxHash;
}

async function getTransaction(token_address, address) {
  const getTxPayload = {
    network: 'Ethereum',
    xchainAssetIdent: token_address,
    user: {
      network: 'Nervos',
      ident: address,
    },
  };

  const txs = await client.request('getBridgeTransactionSummaries', getTxPayload);

  return txs;
}

async function burn(token_address, priv, address) {
  const burnPayload = {
    network: 'Ethereum',
    sender: address,
    recipient: RICH_ETH_SENDER,
    asset: token_address,
    amount: '1',
  };
  const unsignedBurnTx = await client.request('generateBridgeOutNervosTransaction', burnPayload);
  logger.info('unsignedBurnTx ', unsignedBurnTx);

  const signedTx = ckb.signTransaction(priv)(unsignedBurnTx.rawTransaction);
  logger.info('signedTx', signedTx);

  const burnTxHash = await ckb.rpc.sendTransaction(signedTx);
  logger.info('burnTxHash', burnTxHash);
  return burnTxHash;
}

async function check(token_address, txId, address) {
  let find = false;
  let pending = false;
  for (let i = 0; i < 2000; i++) {
    await asyncSleep(3000);
    const txs = await getTransaction(token_address, address);
    for (const tx of txs) {
      if (tx.txSummary.fromTransaction.txId == txId) {
        logger.info('tx', tx);
      }
      if (tx.status == 'Successful' && tx.txSummary.fromTransaction.txId == txId) {
        find = true;
        pending = false;
        break;
      }
      if (tx.status == 'Failed' && tx.txSummary.fromTransaction.txId == txId) {
        throw new Error(`rpc test failed, ${txId} occurs error ${tx.message}`);
      }
      if (tx.status == 'Pending' && tx.txSummary.fromTransaction.txId == txId) {
        pending = true;
      }
    }
    if (find) {
      break;
    }
  }
  if (pending) {
    throw new Error(`rpc test failed, pending for 3000s ${txId}`);
  }
  if (!find) {
    throw new Error(`rpc test failed, can not find record ${txId}`);
  }
}

// async function getBalance(token_address) {
//   const publicKey = ckb.utils.privateKeyToPublicKey(RICH_CKB_PRI_KEY);

//   const { secp256k1Dep } = await ckb.loadDeps();
//   const args = `0x${ckb.utils.blake160(publicKey, 'hex')}`;
//   const lockscript = Script.fromRPC({
//     code_hash: secp256k1Dep.codeHash,
//     args,
//     hash_type: secp256k1Dep.hashType,
//   });

//   const ownLockHash = ckb.utils.scriptToHash(<CKBComponents.Script>lockscript);
//   const asset = new EthAsset(token_address, ownLockHash);
//   const bridgeCellLockscript = {
//     codeHash: ForceBridgeCore.config.ckb.deps.bridgeLock.script.codeHash,
//     hashType: ForceBridgeCore.config.ckb.deps.bridgeLock.script.hashType,
//     args: asset.toBridgeLockscriptArgs(),
//   };
//   const sudtArgs = ckb.utils.scriptToHash(<CKBComponents.Script>bridgeCellLockscript);

//   const balancePayload = {
//     network: 'Nervos',
//     userIdent: CKB_ADDRESS,
//     assetIdent: sudtArgs,
//   };
//   const balance = await client.request('getBalance', [balancePayload]);
//   logger.info('balance', balance);
//   return balance;
// }

async function execute(token_address, privateKeys, ckbAddresses) {
  const lockTxs = [];
  const provider = new ethers.providers.JsonRpcProvider(ETH_NODE_URL);
  for (let i = 0; i < BATCH_NUM; i++) {
    const wallet = new ethers.Wallet(privateKeys[i], provider);
    const nonce = await wallet.getTransactionCount();
    const lockTxHash = await lock(wallet, token_address, nonce, ckbAddresses[i]);
    lockTxs.push(lockTxHash);
  }
  logger.info('lock txs', lockTxs);
  for (let i = 0; i < BATCH_NUM; i++) {
    await check(token_address, lockTxs[i], ckbAddresses[i]);
  }

  const burnTxs = [];
  for (let i = 0; i < BATCH_NUM; i++) {
    const burnTxHash = await burn(token_address, privateKeys[i], ckbAddresses[i]);
    burnTxs.push(burnTxHash);
  }
  logger.info('burn txs', burnTxs);

  for (let i = 0; i < BATCH_NUM; i++) {
    await check(token_address, burnTxs[i], ckbAddresses[i]);
  }
}

function preparePrivateKeys() {
  const privateKeys = [];
  for (let i = 0; i < BATCH_NUM; i++) {
    privateKeys.push(ethers.Wallet.createRandom().privateKey);
  }
  return privateKeys;
}

function getCkbAddresses(privateKeys) {
  const addresses = [];
  for (const key of privateKeys) {
    const publicKey = ckb.utils.privateKeyToPublicKey(key);
    addresses.push(ckb.utils.pubkeyToAddress(publicKey, { prefix: AddressPrefix.Testnet }));
  }
  return addresses;
}

async function prepareCkbAddresses(privateKeys) {
  const { secp256k1Dep } = await ckb.loadDeps();
  const cellDeps = [
    {
      outPoint: secp256k1Dep.outPoint,
      depType: secp256k1Dep.depType,
    },
  ];

  const publicKey = ckb.utils.privateKeyToPublicKey(RICH_CKB_PRI_KEY);
  const args = `0x${ckb.utils.blake160(publicKey, 'hex')}`;
  const fromLockscript = Script.fromRPC({
    code_hash: secp256k1Dep.codeHash,
    args,
    hash_type: secp256k1Dep.hashType,
  });
  const needSupplyCap = BATCH_NUM * 600 * 100000000 + 100000;
  const collector = new IndexerCollector(new CkbIndexer(CKB_NODE_URL, CKB_INDEXER_URL));

  const needSupplyCapCells = await collector.getCellsByLockscriptAndCapacity(
    fromLockscript,
    new Amount(`0x${needSupplyCap.toString(16)}`, 0),
  );
  console.log(needSupplyCapCells);
  const inputs = needSupplyCapCells.map((cell) => {
    return { previousOutput: cell.outPoint, since: '0x0' };
  });

  const outputs = [];
  const outputsData = [];
  for (const key of privateKeys) {
    const toPublicKey = ckb.utils.privateKeyToPublicKey(key);
    const toArgs = `0x${ckb.utils.blake160(toPublicKey, 'hex')}`;
    const toScript = Script.fromRPC({
      code_hash: secp256k1Dep.codeHash,
      args: toArgs,
      hash_type: secp256k1Dep.hashType,
    });
    const capacity = 600 * 100000000;
    const toScriptCell = {
      lock: toScript,
      capacity: `0x${capacity.toString(16)}`,
    };
    outputs.push(toScriptCell);
    outputsData.push('0x');
  }

  const inputCap = needSupplyCapCells.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
  const outputCap = outputs.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
  const changeCellCapacity = inputCap - outputCap - 100000n;
  console.log(changeCellCapacity);
  outputs.push({
    lock: fromLockscript,
    capacity: `0x${changeCellCapacity.toString(16)}`,
  });
  outputsData.push('0x');

  const rawTx = {
    version: '0x0',
    cellDeps,
    headerDeps: [],
    inputs,
    outputs,
    witnesses: [{ lock: '', inputType: '', outputType: '' }],
    outputsData,
  };

  const signedTx = ckb.signTransaction(RICH_CKB_PRI_KEY)(rawTx);
  logger.info('signedTx', signedTx);

  const burnTxHash = await ckb.rpc.sendTransaction(signedTx);
  logger.info('tx', burnTxHash);
}

async function prepareEthAddresses(privateKeys) {
  const provider = new ethers.providers.JsonRpcProvider(ETH_NODE_URL);
  const richWallet = new ethers.Wallet(RICH_ETH_WALLET_PRIV, provider);
  let nonce = await richWallet.getTransactionCount();
  for (const key of privateKeys) {
    const address = new ethers.Wallet(key).address;
    const tx = await richWallet.populateTransaction({ to: address, value: ethers.constants.WeiPerEther, nonce: nonce });
    const signedTx = await richWallet.signTransaction(tx);
    const lockTxHash = (await provider.sendTransaction(signedTx)).hash;
    logger.info('prepare eth address tx hash', lockTxHash);
    nonce++;
  }
}

async function main() {
  const configPath = process.env.CONFIG_PATH || './config.json';
  nconf.env().file({ file: configPath });
  const config: Config = nconf.get('forceBridge');
  // init bridge force core
  await new ForceBridgeCore().init(config);
  config.common.log.logFile = './log/rpc-ci.log';
  initLog(config.common.log);

  logger.info('123');
  logger.debug('123');
  // const privateKeys = preparePrivateKeys();
  // console.log('priv', privateKeys);
  // const addresses = getCkbAddresses(privateKeys);
  // console.log('address', addresses);
  // await prepareEthAddresses(privateKeys);
  // await prepareCkbAddresses(privateKeys);

  const privPath = './batch_privs.json';
  nconf.env().file({ file: privPath });

  const privateKeys = nconf.get('privs');
  logger.info('private keys', privateKeys);
  const addresses = getCkbAddresses(privateKeys);

  try {
    await execute(ETH_TOKEN_ADDRESS, privateKeys, addresses);
  } catch (e) {
    logger.info('catch error', e);
  }
}

main();