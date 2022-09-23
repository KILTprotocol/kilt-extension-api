import {
  KeyringPair,
  Did,
  SignCallback,
  NewDidEncryptionKey,
  Blockchain,
  KiltAddress,
  KiltKeyringPair,
  DidDocument,
  connect,
} from '@kiltprotocol/sdk-js'
// import { ApiPromise, WsProvider } from '@polkadot/api'
import { Keypair } from '@polkadot/util-crypto/types'
// import { GenericContainer, StartedTestContainer, Wait } from 'testcontainers'
// import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import {
  naclBoxPairFromSecret,
  blake2AsU8a,
  keyFromPath,
  ed25519PairFromSeed,
  keyExtractPath,
  mnemonicToMiniSecret,
} from '@polkadot/util-crypto'

const WS_PORT = 9944

// async function getStartedTestContainer(): Promise<StartedTestContainer> {
//   try {
//     const image =
//       process.env.TESTCONTAINERS_NODE_IMG || 'kiltprotocol/node:latest'
//     console.log(`using testcontainer with image ${image}`)
//     const testcontainer = new GenericContainer(image)
//       .withCmd(['--dev', `--ws-port=${WS_PORT}`, '--ws-external'])
//       .withExposedPorts(WS_PORT)
//       .withWaitStrategy(Wait.forLogMessage(`:${WS_PORT}`))
//     const started = await testcontainer.start()
//     return started
//   } catch (error) {
//     console.error(
//       'Could not start the docker container via testcontainers, run with DEBUG=testcontainers* to debug'
//     )
//     throw error
//   }
// }

// async function buildConnection(wsEndpoint: string): Promise<ApiPromise> {
//   const provider = new WsProvider(wsEndpoint)
//   const api = await ApiPromise.create({ provider })
//   await init({ api })
//   return api
// }

// export async function initializeApi(): Promise<ApiPromise> {
//   const { TEST_WS_ADDRESS, JEST_WORKER_ID } = process.env
//   if (TEST_WS_ADDRESS) {
//     if (JEST_WORKER_ID !== '1') {
//       throw new Error(
//         'TEST_WS_ADDRESS is set but more than one jest worker was started. You cannot run tests in parallel when TEST_WS_ADDRESS is set. Please run jest with `-w 1`.'
//       )
//     }
//     console.log(`connecting to node ${TEST_WS_ADDRESS}`)
//     return buildConnection(TEST_WS_ADDRESS)
//   }
//   const started = await getStartedTestContainer()
//   const port = started.getMappedPort(9944)
//   const host = started.getHost()
//   const WS_ADDRESS = `ws://${host}:${port}`
//   console.log(`connecting to test container at ${WS_ADDRESS}`)
//   const api = await buildConnection(WS_ADDRESS)
//   api.once('disconnected', () => started.stop().catch())
//   return api
// }

const keyring = new Keyring({ ss58Format: 38, type: 'ed25519' })

const faucetSeed =
  'receive clutch item involve chaos clutch furnace arrest claw isolate okay together'

export const devFaucet = keyring.createFromUri(faucetSeed) as KeyringPair

// export async function fundAccount(
//   address: KeyringPair['address'],
//   amount: BN
// ): Promise<void> {
//   const api = await initializeApi()
//   const transferTx = api.tx.balances.transfer(address, amount)
//   await ChainHelpers.Blockchain.signAndSubmitTx(transferTx, devFaucet)
// }

export async function keypairs(account: KeyringPair, mnemonic: string) {
  const authentication = {
    ...account.derive('//did//0'),
    type: 'ed25519',
  } as KiltKeyringPair
  const assertion = {
    ...account.derive('//did//assertion//0'),
    type: 'ed25519',
  } as KiltKeyringPair
  const keyAgreement: NewDidEncryptionKey & Keypair = (function () {
    const secretKeyPair = ed25519PairFromSeed(mnemonicToMiniSecret(mnemonic))
    const { path } = keyExtractPath('//did//keyAgreement//0')
    const { secretKey } = keyFromPath(secretKeyPair, path, 'ed25519')
    return {
      ...naclBoxPairFromSecret(blake2AsU8a(secretKey)),
      type: 'x25519',
    }
  })()

  return {
    authentication,
    assertion,
    keyAgreement,
  }
}

export async function generateDid(
  account: KeyringPair,
  mnemonic: string,
  authenticationSigner: SignCallback
): Promise<DidDocument> {
  await connect('wss://peregrine.kilt.io')

  const { authentication, assertion, keyAgreement } = await keypairs(
    account,
    mnemonic
  )

  const uri = Did.Utils.getFullDidUriFromKey(authentication)
  let fullDid = await Did.resolve(uri)
  if (fullDid?.document) return fullDid.document

  const extrinsic = await Did.Chain.getStoreTx(
    {
      authentication: [authentication],
      assertionMethod: [assertion],
      keyAgreement: [keyAgreement],
    },
    account.address as KiltAddress,
    authenticationSigner
  )

  await Blockchain.signAndSubmitTx(extrinsic, account, {
    resolveOn: Blockchain.IS_FINALIZED,
  })

  fullDid = await Did.resolve(uri)
  if (!fullDid || !fullDid.document)
    throw new Error('Could not fetch created DID document')
  return fullDid.document
}

export async function assertionSigner({
  assertion,
  didDocument,
}: {
  assertion: KeyringPair
  didDocument: DidDocument
}): Promise<SignCallback<any>> {
  //@ts-ignore
  return async ({ data, keyRelationship }) => {
    //@ts-ignore
    const { type, id } = didDocument[keyRelationship][0]

    return {
      data: assertion.sign(data),
      keyType: type,
      keyUri: `${didDocument.uri}${id}`,
    }
  }
}
