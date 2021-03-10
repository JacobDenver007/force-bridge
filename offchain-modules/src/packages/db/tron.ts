// invoke in tron handler
import { CkbMint, TronLock, TronUnlock } from '@force-bridge/db/model';
import { Connection } from 'typeorm';

export class TronDb {
  constructor(private connection: Connection) {}
  async createCkbMint(records: CkbMint[]): Promise<void> {
    await this.connection.manager.save(records);
  }

  async getCkbMint(limit = 100): Promise<CkbMint[]> {
    const ckbMintRepository = this.connection.getRepository(CkbMint);
    return await ckbMintRepository.find({
      where: {
        chain: 1,
      },
      order: {
        updated_at: 'DESC',
      },
      take: limit,
    });
  }

  async saveTronLock(records: TronLock[]): Promise<void> {
    await this.connection.manager.save(records);
  }

  async getTronLock(limit = 100): Promise<TronLock[]> {
    const tronLockRepository = this.connection.getRepository(TronLock);
    return await tronLockRepository.find({
      order: {
        updated_at: 'DESC',
      },
      take: limit,
    });
  }

  async getLatestLock(): Promise<TronLock[]> {
    const qb = this.connection.getRepository(TronLock).createQueryBuilder('lock');
    return qb
      .where('lock.timestamp=' + qb.subQuery().select('MAX(lock.timestamp)').from(TronLock, 'lock').getQuery())
      .getMany();
  }

  async saveTronUnlock(records: TronUnlock[]): Promise<void> {
    await this.connection.manager.save(records);
  }

  async getTronUnlockRecordsToUnlock(limit = 100): Promise<TronUnlock[]> {
    const tronUnlockRepository = this.connection.getRepository(TronUnlock);
    return await tronUnlockRepository.find({
      where: {
        status: 'pending',
      },
      order: {
        updated_at: 'DESC',
      },
      take: limit,
    });
  }
}
