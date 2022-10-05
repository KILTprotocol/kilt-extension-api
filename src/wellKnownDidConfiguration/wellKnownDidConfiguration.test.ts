import {
  KeyringPair,
  DidUri,
  DidDocument,
  ICredentialPresentation,
  disconnect,
} from '@kiltprotocol/sdk-js'
import { ApiPromise } from '@polkadot/api'
import { mnemonicGenerate, cryptoWaitReady } from '@polkadot/util-crypto'
import { VerifiableDomainLinkagePresentation } from '../types/types'
import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import {
  createCredential,
  getDomainLinkagePresentation,
  verifyDidConfigPresentation,
} from './wellKnownDidConfiguration'
import {
  fundAccount,
  generateDid,
  buildConnection,
  keypairs,
  createCtype,
  assertionSigner,
} from '../tests/utils'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: DidUri
  let keypair: any
  let domainLinkageCredential: VerifiableDomainLinkagePresentation
  let credential: ICredentialPresentation
  let api: ApiPromise

  beforeAll(async () => {
    api = await buildConnection('ws://127.0.0.1:9944')
    await cryptoWaitReady()
    mnemonic = mnemonicGenerate()
    account = new Keyring({ type: 'ed25519' }).addFromMnemonic(mnemonic)
    await fundAccount(account.address, new BN('1000000000000000000'), api)
    keypair = await keypairs(account, mnemonic)

    didDocument = await generateDid(account, mnemonic)

    didUri = didDocument.uri
    await createCtype(didUri, account, mnemonic, api)
  }, 30_000)

  it('generate a well known did configuration credential', async () => {
    expect(
      (credential = await createCredential(
        await assertionSigner({ assertion: keypair.assertion, didDocument }),
        origin,
        didUri
      ))
    ).toBeTruthy()
  }, 30_000)

  it('fails to generate a well known did configuration credential due to bad origin', async () => {
    await expect(
      createCredential(
        await assertionSigner({ assertion: keypair.assertion, didDocument }),
        'bad origin',
        didUri
      )
    ).rejects.toThrow()
  }, 30_000)

  it('get domain linkage presentation', async () => {
    expect(
      (domainLinkageCredential = await getDomainLinkagePresentation(credential))
    ).toBeTruthy()
  }, 30_000)

  it('rejects the domain linkage as no signature', async () => {
    credential.claimerSignature.signature = '0x'
    await expect(getDomainLinkagePresentation(credential)).rejects.toThrow()
  }, 30_000)

  it('verify did configuration presentation', async () => {
    expect(
      await verifyDidConfigPresentation(didUri, domainLinkageCredential, origin)
    ).toBeUndefined()
  }, 30_000)

  it('did not verify did configuration presentation', async () => {
    domainLinkageCredential.linked_dids[0].proof.signature = '0x'
    await expect(
      verifyDidConfigPresentation(didUri, domainLinkageCredential, origin)
    ).rejects.toThrow()
  }, 30_000)
})

afterAll(async () => {
  await disconnect()
})
