module.exports = {
  preset: 'ts-jest/presets/js-with-ts',
  testEnvironment: 'node',
  clearMocks: true,
  // Parachain block time is 12s
  testTimeout: 30000,
  transformIgnorePatterns: [
    '/node_modules/(?!@polkadot|@babel/runtime/helpers/esm/)',
  ],
  collectCoverageFrom: ['**/*/src/**/*.ts', '!**/index.ts'],
  resolver: 'ts-jest-resolver',
  rootDir: 'src',
  coverageDirectory: 'coverage',
  moduleDirectories: ['node_modules', '/src'],
}
