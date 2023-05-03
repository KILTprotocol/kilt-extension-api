import {
  KiltKeyringPair,
  DidUri,
  DidDocument,
  ICredentialPresentation,
  IClaim,
  DidResourceUri,
  connect,
  ConfigService,
} from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import { VerifiableDomainLinkagePresentation } from 'kilt-extension-api/dist/types'

import {
  createCredential,
  DID_CONFIGURATION_CONTEXT,
  getDomainLinkagePresentation,
  verifyDidConfigPresentation,
  DID_VC_CONTEXT,
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  KILT_VERIFIABLECREDENTIAL_TYPE,
} from './wellKnownDidConfiguration'
import {
  fundAccount,
  generateDid,
  keypairs,
  createCtype,
  assertionSigner,
  startContainer,
} from './tests/utils'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KiltKeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: DidUri
  let keypair: any
  let domainLinkageCredential: VerifiableDomainLinkagePresentation
  let credential: ICredentialPresentation
  let keyUri: DidResourceUri
  let claim: IClaim

  beforeAll(async () => {
    const address = await startContainer()
    await connect(address)
  }, 20_000)

  beforeAll(async () => {
    mnemonic = mnemonicGenerate()
    account = new Keyring({ type: 'ed25519' }).addFromMnemonic(
      mnemonic
    ) as KiltKeyringPair
    await fundAccount(account.address, new BN('1000000000000000000'))
    keypair = await keypairs(account, mnemonic)

    didDocument = await generateDid(account, mnemonic)

    didUri = didDocument.uri
    keyUri = `${didUri}${didDocument.assertionMethod?.[0].id!}`
    claim = {
      cTypeHash:
        '0x39dc47bc933944ac66cfcf46bfdb66ca070b04a17cd8818eefb669928caf4d3e',
      contents: { origin },
      owner: didUri,
    }
    await createCtype(didUri, account, mnemonic)
  }, 30_000)

  it('generate a well known did configuration credential', async () => {
    expect(
      (credential = await createCredential(
        await assertionSigner({ assertion: keypair.assertion, didDocument }),
        origin,
        didUri
      ))
    ).toMatchObject<ICredentialPresentation>({
      claim,
      claimerSignature: {
        keyUri,
        signature: expect.any(String),
      },
      claimHashes: expect.any(Array<`0x${string}`>),
      claimNonceMap: expect.any(Object),
      delegationId: null,
      legitimations: [],
      rootHash: expect.any(String),
    })
  }, 30_000)

  it('fails to generate a well known did configuration credential if origin is not a URL', async () => {
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
    ).toMatchObject<VerifiableDomainLinkagePresentation>({
      '@context': DID_CONFIGURATION_CONTEXT,
      linked_dids: [
        {
          '@context': [DID_VC_CONTEXT, DID_CONFIGURATION_CONTEXT],
          credentialSubject: {
            id: didUri,
            origin,
          },
          proof: expect.any(Object),
          id: expect.any(String),
          type: [
            DEFAULT_VERIFIABLECREDENTIAL_TYPE,
            'DomainLinkageCredential',
            KILT_VERIFIABLECREDENTIAL_TYPE,
          ],

          issuer: didUri,
          issuanceDate: expect.any(String),
        },
      ],
    })
  }, 30_000)

  it('rejects if the domain linkage has no signature', async () => {
    credential.claimerSignature.signature = '0x'
    await expect(getDomainLinkagePresentation(credential)).rejects.toThrow()
  }, 30_000)

  it('verify did configuration presentation', async () => {
    await expect(
      verifyDidConfigPresentation(didUri, domainLinkageCredential, origin)
    ).resolves.not.toThrow()
  }, 30_000)

  it('did not verify did configuration presentation', async () => {
    domainLinkageCredential.linked_dids[0].proof.signature = '0x'
    await expect(
      verifyDidConfigPresentation(didUri, domainLinkageCredential, origin)
    ).rejects.toThrow()
  }, 30_000)
})

afterAll(async () => {
  const api = ConfigService.get('api')

  await api.disconnect()
})
