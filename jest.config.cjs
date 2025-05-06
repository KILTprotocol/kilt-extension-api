module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  clearMocks: true,
  resolver: 'ts-jest-resolver',
  // Parachain block time is 12s
  testTimeout: 12000,
  collectCoverageFrom: ['**/*/src/**/*.ts'],
  rootDir: 'src',
  coverageDirectory: 'coverage',
  moduleDirectories: ['node_modules'],
  transform: {
    '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.cjs.json' }],
  },
}
