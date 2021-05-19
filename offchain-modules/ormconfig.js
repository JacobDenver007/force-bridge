const SnakeNamingStrategy = require('typeorm-naming-strategies').SnakeNamingStrategy;

module.exports = {
  type: 'mysql',
  host: 'localhost',
  port: 3306,
  username: 'root',
  password: 'root',
  database: 'forcebridge',
  timezone: 'Z',
  synchronize: true,
  logging: true,
  entities: ['packages/x/dist/db/entity/*.js'],
  namingStrategy: new SnakeNamingStrategy(),
};
