import {
  Did,
  SignCallback,
  Blockchain,
  KiltKeyringPair,
  DidDocument,
  ChainHelpers,
  CType,
  DidUri,
  ConfigService,
  KiltEncryptionKeypair,
} from '@kiltprotocol/sdk-js'
import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import {
  naclBoxPairFromSecret,
  blake2AsU8a,
  keyFromPath,
  ed25519PairFromSeed,
  keyExtractPath,
  mnemonicToMiniSecret,
  cryptoWaitReady,
} from '@polkadot/util-crypto'
import { GenericContainer, Wait } from 'testcontainers'

import { ctypeDomainLinkage } from '../wellKnownDidConfiguration'

export const faucet = async () => {
  await cryptoWaitReady()
  const keyring = new Keyring({ ss58Format: 38, type: 'ed25519' })

  const faucetSeed =
    'receive clutch item involve chaos clutch furnace arrest claw isolate okay together'

  return keyring.createFromUri(faucetSeed, { type: 'ed25519' })
}

export async function fundAccount(
  address: KiltKeyringPair['address'],
  amount: BN
): Promise<void> {
  const api = ConfigService.get('api')
  const transferTx = api.tx.balances.transfer(address, amount)
  const devAccount = await faucet()

  await ChainHelpers.Blockchain.signAndSubmitTx(transferTx, devAccount, {
    resolveOn: Blockchain.IS_FINALIZED,
  })
}

export async function keypairs(account: KiltKeyringPair, mnemonic: string) {
  const authentication = {
    ...account.derive('//did//0'),
    type: 'ed25519',
  } as KiltKeyringPair
  const assertion = {
    ...account.derive('//did//assertion//0'),
    type: 'ed25519',
  } as KiltKeyringPair
  const keyAgreement: KiltEncryptionKeypair = (function () {
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
  account: KiltKeyringPair,
  mnemonic: string
): Promise<DidDocument> {
  const { authentication, assertion, keyAgreement } = await keypairs(
    account,
    mnemonic
  )

  const uri = Did.getFullDidUriFromKey(authentication)

  let fullDid = await Did.resolve(uri)
  if (fullDid?.document) return fullDid.document

  const extrinsic = await Did.getStoreTx(
    {
      authentication: [authentication],
      assertionMethod: [assertion],
      keyAgreement: [keyAgreement],
    },
    account.address,
    async ({ data }) => ({
      signature: authentication.sign(data),
      keyType: authentication.type,
    })
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
  assertion: KiltKeyringPair
  didDocument: DidDocument
}): Promise<SignCallback> {
  const { assertionMethod } = didDocument
  if (!assertionMethod) throw new Error('no assertionMethod')
  return async ({ data }) => ({
    signature: assertion.sign(data),
    keyType: 'ed25519',
    keyUri: `${didDocument.uri}${assertionMethod[0].id}`,
  })
}

export async function createCtype(
  didUri: DidUri,
  account: KiltKeyringPair,
  mnemonic: string
) {
  const api = ConfigService.get('api')

  const { assertion } = await keypairs(account, mnemonic)
  const fullDid = await Did.resolve(didUri)
  if (!fullDid) throw new Error('no did')
  const { document } = fullDid
  if (!document) throw new Error('no document')
  const { assertionMethod } = document
  if (!assertionMethod) throw new Error('no assertion key')
  const encodedCType = CType.toChain(ctypeDomainLinkage)
  const ctypeTx = api.tx.ctype.add(encodedCType)

  const authorizedCtypeCreationTx = await Did.authorizeTx(
    didUri,
    ctypeTx,
    await assertionSigner({ assertion, didDocument: document }),
    account.address as `4${string}`
  )

  await Blockchain.signAndSubmitTx(authorizedCtypeCreationTx, account, {
    resolveOn: Blockchain.IS_FINALIZED,
  })
}

export async function startContainer(): Promise<string> {
  const WS_PORT = 9944
  const image =
    process.env.TESTCONTAINERS_NODE_IMG || 'kiltprotocol/mashnet-node'
  console.log(`using testcontainer with image ${image}`)
  const testcontainer = new GenericContainer(image)
    .withCommand(['--dev', `--ws-port=${WS_PORT}`, '--ws-external'])
    .withExposedPorts(WS_PORT)
    .withWaitStrategy(Wait.forLogMessage(`:${WS_PORT}`))
  const started = await testcontainer.start()
  const port = started.getMappedPort(9944)
  const host = started.getHost()
  const WS_ADDRESS = `ws://${host}:${port}`
  return WS_ADDRESS
}
