import { Script } from '@lay2/pw-core';
import * as utils from '@nervosnetwork/ckb-sdk-utils';
import { AddressPrefix } from '@nervosnetwork/ckb-sdk-utils';
import { ForceBridgeCore } from '../../core';
import { asserts } from '../../errors';

export class Account {
  public publicKey: string;
  public lockscript?: Script;
  public address: string;

  static scriptToAddress(script: CKBComponents.Script): string {
    const network = ForceBridgeCore.config.common.network;
    if (script.codeHash === utils.systemScripts.SECP256K1_BLAKE160.codeHash) {
      if (network === 'mainnet')
        return utils.bech32Address(script.args, {
          prefix: AddressPrefix.Mainnet,
          type: utils.AddressType.HashIdx,
          codeHashOrCodeHashIndex: '0x00',
        });
      return utils.bech32Address(script.args, {
        prefix: AddressPrefix.Testnet,
        type: utils.AddressType.HashIdx,
        codeHashOrCodeHashIndex: '0x00',
      });
    } else {
      if (network === 'mainnet')
        return utils.bech32Address(script.args, {
          prefix: AddressPrefix.Mainnet,
          type: script.hashType === 'type' ? utils.AddressType.TypeCodeHash : utils.AddressType.DataCodeHash,
          codeHashOrCodeHashIndex: script.codeHash,
        });
      return utils.bech32Address(script.args, {
        prefix: AddressPrefix.Testnet,
        type: script.hashType === 'type' ? utils.AddressType.TypeCodeHash : utils.AddressType.DataCodeHash,
        codeHashOrCodeHashIndex: script.codeHash,
      });
    }
  }

  constructor(public privateKey: string) {
    this.publicKey = ForceBridgeCore.ckb.utils.privateKeyToPublicKey(privateKey);
    this.address = ForceBridgeCore.ckb.utils.pubkeyToAddress(this.publicKey);
  }

  async getLockscript(): Promise<Script> {
    if (this.lockscript === undefined) {
      const { secp256k1Dep } = await ForceBridgeCore.ckb.loadDeps();

      asserts(secp256k1Dep);

      const args = `0x${ForceBridgeCore.ckb.utils.blake160(this.publicKey, 'hex')}`;
      const lockScript = Script.fromRPC({
        code_hash: secp256k1Dep.codeHash,
        args,
        hash_type: secp256k1Dep.hashType,
      });

      asserts(lockScript);

      this.lockscript = lockScript;
    }
    return this.lockscript;
  }
}
