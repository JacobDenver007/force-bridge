#!/usr/bin/env node
import commander from 'commander';
import { feeCmd } from './bridgeFee';
import { ethCmd } from './eth';
import { relayerCmd } from './relayer';
import { rpcCmd } from './rpc';
import { sigCmd } from './sigServer';

export const program = commander.program;

const version = '0.0.1';

async function main() {
  program
    .version(version)
    .description('forcecli is command line tool to lock & unlock asset to force bridge')
    .addCommand(ethCmd)
    .addCommand(relayerCmd)
    .addCommand(rpcCmd)
    .addCommand(feeCmd)
    .addCommand(sigCmd);

  await program.parseAsync(process.argv);
}

main();
