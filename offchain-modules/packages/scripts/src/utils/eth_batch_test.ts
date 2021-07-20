import fs from 'fs';

import { IndexerCollector } from '@force-bridge/x/dist/ckb/tx-helper/collector';
import { CkbIndexer } from '@force-bridge/x/dist/ckb/tx-helper/indexer';
import { asserts } from '@force-bridge/x/dist/errors';
import { asyncSleep, writeJsonToFile } from '@force-bridge/x/dist/utils';
import { logger } from '@force-bridge/x/dist/utils/logger';
import { Script } from '@lay2/pw-core';
import CKB from '@nervosnetwork/ckb-sdk-core';
import { AddressPrefix } from '@nervosnetwork/ckb-sdk-utils';
import { ethers } from 'ethers';
import { JSONRPCClient } from 'json-rpc-2.0';
import fetch from 'node-fetch/index';

interface KeysConfig {
  ethPrivs: Array<string>;
  ethAddresses: Array<string>;
  ckbPrivs: Array<string>;
  ckbAddresses: Array<string>;
}

async function generateLockTx(
  provider: ethers.providers.JsonRpcProvider,
  client: JSONRPCClient,
  ethWallet: ethers.Wallet,
  assetIdent: string,
  nonce: number,
  recipient: string,
  amount: string,
): Promise<string> {
  const lockPayload = {
    sender: ethWallet.address,
    recipient: recipient,
    asset: {
      network: 'Ethereum',
      ident: assetIdent,
      amount: amount,
    },
  };
  const unsignedLockTx = await client.request('generateBridgeInNervosTransaction', lockPayload);
  logger.info('unsignedMintTx', unsignedLockTx);

  const unsignedTx = unsignedLockTx.rawTransaction;
  unsignedTx.value = unsignedTx.value ? ethers.BigNumber.from(unsignedTx.value.hex) : ethers.BigNumber.from(0);
  unsignedTx.nonce = nonce;
  unsignedTx.gasLimit = ethers.BigNumber.from(1000000);
  unsignedTx.gasPrice = await provider.getGasPrice();

  logger.info('unsignedTx', unsignedTx);

  const signedTx = await ethWallet.signTransaction(unsignedTx);
  logger.info('signedTx', signedTx);

  const hexTx = await Promise.resolve(signedTx).then((t) => ethers.utils.hexlify(t));
  return hexTx;
}

async function generateBurnTx(
  ckb: CKB,
  client: JSONRPCClient,
  asset: string,
  ckbPriv: string,
  sender: string,
  recipient: string,
  amount: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
): Promise<any> {
  const burnPayload = {
    network: 'Ethereum',
    sender: sender,
    recipient: recipient,
    asset: asset,
    amount: amount,
  };

  const unsignedBurnTx = await client.request('generateBridgeOutNervosTransaction', burnPayload);
  logger.info('unsignedBurnTx ', unsignedBurnTx);

  const signedTx = ckb.signTransaction(ckbPriv)(unsignedBurnTx.rawTransaction);
  logger.info('signedTx', signedTx);
  return signedTx;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function getTransaction(client: JSONRPCClient, assetIdent: string, userIdent: string): Promise<any> {
  const getTxPayload = {
    network: 'Ethereum',
    xchainAssetIdent: assetIdent,
    user: {
      network: 'Nervos',
      ident: userIdent,
    },
  };

  const txs = await client.request('getBridgeTransactionSummaries', getTxPayload);

  return txs;
}

async function checkTx(client: JSONRPCClient, assetIdent: string, txId: string, userIdent: string) {
  let find = false;
  let pending = false;
  for (let i = 0; i < 600; i++) {
    const txs = await getTransaction(client, assetIdent, userIdent);
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
    await asyncSleep(3000);
  }
  if (pending) {
    throw new Error(`rpc test failed, pending for 3000s ${txId}`);
  }
  if (!find) {
    throw new Error(`rpc test failed, can not find record ${txId}`);
  }
}

function lock(
  provider: ethers.providers.JsonRpcProvider,
  client: JSONRPCClient,
  keys: KeysConfig,
  ethTokenAddress: string,
): void {
  void (async () => {
    for (;;) {
      try {
        for (const ethPrivateKey of keys.ethPrivs) {
          const wallet = new ethers.Wallet(ethPrivateKey, provider);
          let nonce = await wallet.getTransactionCount();
          for (const recipient of keys.ckbAddresses) {
            const lockAmount = getRandomAmount(1000000000000000, 2000000000000000);
            const signedLockTx = await generateLockTx(
              provider,
              client,
              wallet,
              ethTokenAddress,
              nonce,
              recipient,
              lockAmount,
            );
            nonce++;
            const txHash = (await provider.sendTransaction(signedLockTx)).hash;
            logger.info(`lock send from ${wallet.address} to ${recipient} amount ${lockAmount} txHash ${txHash}`);
          }
        }
      } catch (e) {
        logger.error('lock error', e);
      }
      await asyncSleep(1000 * 60 * 10);
    }
  })();
}

function burn(ckb: CKB, client: JSONRPCClient, keys: KeysConfig, ethTokenAddress: string): void {
  void (async () => {
    for (;;) {
      for (let i = 0; i < keys.ckbPrivs.length; i++) {
        try {
          const burnAmount = getRandomAmount(1000000000000000, 2000000000000000);
          const burnTx = await generateBurnTx(
            ckb,
            client,
            ethTokenAddress,
            keys.ckbPrivs[i],
            keys.ckbAddresses[i],
            keys.ethAddresses[i],
            burnAmount,
          );
          const txHash = await ckb.rpc.sendTransaction(burnTx);
          logger.info(
            `burn send from ${keys.ckbAddresses[i]} to ${keys.ethAddresses[i]} amount ${burnAmount} txHash ${txHash}`,
          );
        } catch (e) {
          logger.error('burn tx error', e);
          await asyncSleep(1000 * 10);
          continue;
        }
      }
      await asyncSleep(1000 * 60 * 5);
    }
  })();
}

async function _check(
  client: JSONRPCClient,
  txHashes: Array<string>,
  addresses: Array<string>,
  batchNum,
  ethTokenAddress,
) {
  for (let i = 0; i < batchNum; i++) {
    await checkTx(client, ethTokenAddress, txHashes[i], addresses[i]);
  }
}

function prepareEthPrivateKeys(batchNum: number): Array<string> {
  const privateKeys = new Array<string>();
  for (let i = 0; i < batchNum; i++) {
    privateKeys.push(ethers.Wallet.createRandom().privateKey);
  }
  return privateKeys;
}

async function prepareEthAddresses(
  provider: ethers.providers.JsonRpcProvider,
  ethWallet: ethers.Wallet,
  privateKeys: Array<string>,
): Promise<Array<string>> {
  const addresses = new Array<string>();
  let nonce = await ethWallet.getTransactionCount();
  for (const key of privateKeys) {
    const address = new ethers.Wallet(key).address;
    const tx = await ethWallet.populateTransaction({
      to: address,
      value: ethers.constants.WeiPerEther,
      nonce: nonce,
    });
    logger.info('tx', tx);
    const signedTx = await ethWallet.signTransaction(tx);
    const lockTxHash = (await provider.sendTransaction(signedTx)).hash;
    logger.info('prepare eth address tx hash', lockTxHash);
    addresses.push(address);
    nonce++;
  }
  return addresses;
}

function prepareCkbPrivateKeys(batchNum: number): Array<string> {
  const privateKeys = new Array<string>();
  for (let i = 0; i < batchNum; i++) {
    privateKeys.push(ethers.Wallet.createRandom().privateKey);
  }
  return privateKeys;
}

async function prepareCkbAddresses(
  ckb: CKB,
  privateKeys: Array<string>,
  ckbPrivateKey: string,
  batchNum: number,
  ckbNodeUrl: string,
  ckbIndexerUrl: string,
): Promise<Array<string>> {
  const { secp256k1Dep } = await ckb.loadDeps();
  asserts(secp256k1Dep);
  const cellDeps = [
    {
      outPoint: secp256k1Dep.outPoint,
      depType: secp256k1Dep.depType,
    },
  ];

  const publicKey = ckb.utils.privateKeyToPublicKey(ckbPrivateKey);
  const args = `0x${ckb.utils.blake160(publicKey, 'hex')}`;
  const fromLockscript = {
    code_hash: secp256k1Dep.codeHash,
    args,
    hash_type: secp256k1Dep.hashType,
  };
  asserts(fromLockscript);
  const needSupplyCap = batchNum * 600 * 100000000 + 100000;
  const collector = new IndexerCollector(new CkbIndexer(ckbNodeUrl, ckbIndexerUrl));

  const needSupplyCapCells = await collector.getCellsByLockscriptAndCapacity(fromLockscript, BigInt(needSupplyCap));
  const inputs = needSupplyCapCells.map((cell) => {
    return { previousOutput: { txHash: cell.out_point!.tx_hash, index: cell.out_point!.index }, since: '0x0' };
  });

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const outputs = new Array<any>();
  const outputsData = new Array<string>();
  const addresses = new Array<string>();
  for (const key of privateKeys) {
    const toPublicKey = ckb.utils.privateKeyToPublicKey(key);
    addresses.push(ckb.utils.pubkeyToAddress(toPublicKey, { prefix: AddressPrefix.Testnet }));

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

  const inputCap = needSupplyCapCells.map((cell) => BigInt(cell.cell_output.capacity)).reduce((a, b) => a + b);
  const outputCap = outputs.map((cell) => BigInt(cell.capacity)).reduce((a, b) => a + b);
  const changeCellCapacity = inputCap - outputCap - 10000000n;
  outputs.push({
    lock: Script.fromRPC(fromLockscript),
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

  logger.info(`rawTx: ${JSON.stringify(rawTx, null, 2)}`);
  const signedTx = ckb.signTransaction(ckbPrivateKey)(rawTx);
  logger.info('signedTx', signedTx);

  const burnTxHash = await ckb.rpc.sendTransaction(signedTx);
  logger.info('tx', burnTxHash);
  return addresses;
}

// const batchNum = 100;
// const lockAmount = '2000000000000000';
// const burnAmount = '1000000000000000';
// const ethTokenAddress = '0x0000000000000000000000000000000000000000';
//
// const forceBridgeUrl = process.env.FORCE_BRIDGE_RPC_URL || 'http://127.0.0.1:8080/force-bridge/api/v1';
//
// const ethNodeURL = process.env.ETH_URL || 'http://127.0.0.1:8545';
// const ethPrivatekey = process.env.ethPrivatekeyV_KEY || '0xc4ad657963930fbff2e9de3404b30a4e21432c89952ed430b56bf802945ed37a';
//
// const ckbNodeUrl = process.env.CKB_URL || 'http://127.0.0.1:8114';
// const ckbIndexerUrl = process.env.ckbIndexerUrl || 'http://127.0.0.1:8116';
// const ckbPrivateKey = process.env.ckbPrivateKeyV_KEY || '0xa800c82df5461756ae99b5c6677d019c98cc98c7786b80d7b2e77256e46ea1fe';

// const forceBridgeUrl = 'XXX';

// const ethNodeURL = 'XXX';
// const ethPrivatekey = 'XXX';

// const ckbNodeUrl = 'https://testnet.ckbapp.dev';
// const ckbIndexerUrl = 'https://testnet.ckbapp.dev/indexer';
// const ckbPrivateKey = 'XXX';

function getRandomAmount(min: number, max: number): string {
  const Range = max - min;
  const Rand = Math.random();
  return (min + Math.round(Rand * Range)).toFixed();
}

export async function ethBatchTest(
  ethPrivateKey: string,
  ckbPrivateKey: string,
  ethNodeUrl: string,
  ckbNodeUrl: string,
  ckbIndexerUrl: string,
  forceBridgeUrl: string,
  testKeyPath: string,
  initCkb: boolean,
  initEth: boolean,
  send: boolean,
  batchNum = 100,
  ethTokenAddress = '0x0000000000000000000000000000000000000000',
): Promise<void> {
  logger.info('ethBatchTest start!', ethPrivateKey);
  const ckb = new CKB(ckbNodeUrl);

  const client = new JSONRPCClient((jsonRPCRequest) =>
    fetch(forceBridgeUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify(jsonRPCRequest),
      id: 1,
    }).then((response) => {
      if (response.status === 200) {
        // Use client.receive when you received a JSON-RPC response.
        return response.json().then((jsonRPCResponse) => client.receive(jsonRPCResponse));
      } else if (jsonRPCRequest.id !== undefined) {
        return Promise.reject(new Error(response.statusText));
      }
    }),
  );

  const provider = new ethers.providers.JsonRpcProvider(ethNodeUrl);
  const ethWallet = new ethers.Wallet(ethPrivateKey, provider);

  if (initCkb) {
    await initCkbAddresses(ckb, ckbPrivateKey, ckbNodeUrl, ckbIndexerUrl, batchNum, testKeyPath);
  }
  if (initEth) {
    await initEthAddresses(provider, ethWallet, batchNum, testKeyPath);
  }
  if (send) {
    sendTx(provider, ckb, client, ethTokenAddress, testKeyPath);
  }
  logger.info('ethBatchTest pass!');
}

async function initEthAddresses(
  provider: ethers.providers.JsonRpcProvider,
  ethWallet: ethers.Wallet,
  batchNum: number,
  testKeyPath: string,
) {
  logger.info('initEthAddresses');

  const ethPrivs = prepareEthPrivateKeys(batchNum);
  const ethAddresses = await prepareEthAddresses(provider, ethWallet, ethPrivs);
  const keys: KeysConfig = JSON.parse(fs.readFileSync(testKeyPath, 'utf8'));
  logger.info('keys', keys);
  keys.ethPrivs = ethPrivs;
  keys.ethAddresses = ethAddresses;
  logger.info('keys', keys);

  writeJsonToFile(keys, testKeyPath);
}

async function initCkbAddresses(
  ckb: CKB,
  ckbPrivateKey: string,
  ckbNodeUrl: string,
  ckbIndexerUrl: string,
  batchNum: number,
  testKeyPath: string,
) {
  const ckbPrivs = prepareCkbPrivateKeys(batchNum);
  const ckbAddresses = await prepareCkbAddresses(ckb, ckbPrivs, ckbPrivateKey, batchNum, ckbNodeUrl, ckbIndexerUrl);
  const keys: KeysConfig = JSON.parse(fs.readFileSync(testKeyPath, 'utf8'));
  keys.ckbPrivs = ckbPrivs;
  keys.ckbAddresses = ckbAddresses;
  writeJsonToFile(keys, testKeyPath);
}

function sendTx(
  provider: ethers.providers.JsonRpcProvider,
  ckb: CKB,
  client: JSONRPCClient,
  ethTokenAddress: string,
  testKeyPath: string,
): void {
  const keys: KeysConfig = JSON.parse(fs.readFileSync(testKeyPath, 'utf8'));
  void lock(provider, client, keys, ethTokenAddress);
  void burn(ckb, client, keys, ethTokenAddress);
}
