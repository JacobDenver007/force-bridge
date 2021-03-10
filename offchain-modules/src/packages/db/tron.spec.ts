import anyTest, { TestInterface } from 'ava';
import { getTmpConnection } from './test/helper';
import { CkbMint } from '@force-bridge/db/entity/CkbMint';
import { TronDb } from '@force-bridge/db/tron';
import { TronLock } from './entity/TronLock';
import { TronUnlock } from './model';

const test = anyTest as TestInterface<{
  db: TronDb;
}>;

test.beforeEach(async (t) => {
  const { connection } = await getTmpConnection();
  const db: TronDb = new TronDb(connection);
  t.context = { db };
});

test('tron db CkbMint', async (t) => {
  // save db
  const data = {
    id: '0x100',
    chain: 1,
    amount: '0x1',
    asset: '0x00000000000000000000',
    recipient_address: 'ckb1qyqt8xaupvm8837nv3gtc9x0ekkj64vud3jqfwyw5v',
    sudt_extra_data: 'tron mint',
  };
  const ckbMint = new CkbMint().from(data);
  await t.context.db.createCkbMint([ckbMint]);
  // get db
  const ckbMintRecords = await t.context.db.getCkbMint();
  t.is(ckbMintRecords.length, 1);
  t.like(ckbMintRecords[0], data);
});

test('tron db TronLock', async (t) => {
  // save db
  const data = {
    related_id: 1,
    tron_lock_tx_hash: '0x0',
    tron_lock_index: 0,
    tron_sender: '0x0',
    asset: 'TRX',
    asset_type: 'trx',
    amount: '0x1',
    memo: 'lock 1 TRX',
    timestamp: 1612603926000,
    committee: '0x0000000000000000000000000000000000000000',
  };
  const tronLock_1 = new TronLock().from(data);

  data.timestamp = 1612603926001;
  const tronLock_2 = new TronLock().from(data);

  const tronLock_3 = tronLock_2;
  await t.context.db.saveTronLock([tronLock_1, tronLock_2, tronLock_3]);
  // get db
  const tronLockRecords = await t.context.db.getTronLock();
  t.is(tronLockRecords.length, 3);
  t.like(tronLockRecords[2], data);

  const latestLockRecords = await t.context.db.getLatestLock();
  t.is(latestLockRecords.length, 2);
  t.is(latestLockRecords[0].timestamp, 1612603926001);
  t.is(latestLockRecords[1].timestamp, 1612603926001);
});

test('tron db TronUnlock', async (t) => {
  // save db
  const data = {
    related_id: 1,
    asset: 'TLBaRhANQoJFTqre9Nf1mjuwNWjCJeYqUL',
    asset_type: 'trc20',
    amount: '0x1',
    memo: 'unlock 1 TRX_SUDT',
    tron_recipient_address: '0x0000000000000000000000000000000000000000',
    committee: '0x0000000000000000000000000000000000000000',
  };
  const tronUnlock = new TronUnlock().from(data);
  await t.context.db.saveTronUnlock([tronUnlock]);
  // get db
  const tronUnlockRecords = await t.context.db.getTronUnlockRecordsToUnlock();
  t.is(tronUnlockRecords.length, 1);
  t.like(tronUnlockRecords[0], data);
});
