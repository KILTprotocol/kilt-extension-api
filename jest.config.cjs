module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  clearMocks: true,
  // Parachain block time is 12s
  testTimeout: 12000,
  collectCoverageFrom: ['**/*/src/**/*.ts'],
  rootDir: 'src',
  coverageDirectory: 'coverage',
  moduleDirectories: ['node_modules'],
  moduleFileExtensions: ['js', 'ts', 'tsx', 'json', 'node'],
  modulePaths: ['<rootDir>'],
}
