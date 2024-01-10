/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { connect, disconnect } from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { DidConfigResource, DomainLinkageCredential } from '../types'
import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import {
  DID_CONFIGURATION_CONTEXT,
  verifyDidConfigResource,
  DID_VC_CONTEXT,
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  DOMAIN_LINKAGE_CREDENTIAL_TYPE,
  createCredential,
  didConfigResourceFromCredentials,
} from './index'
import { fundAccount, generateDid, keypairs, createCtype, assertionSigners, startContainer } from '../tests/utils'
import { Did, DidDocument, KiltKeyringPair } from '@kiltprotocol/types'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KiltKeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: Did
  let keypair: Awaited<ReturnType<typeof keypairs>>
  let credential: DomainLinkageCredential

  beforeAll(async () => {
    const address = await startContainer()
    await connect(address)
  }, 20_000)

  beforeAll(async () => {
    mnemonic = mnemonicGenerate()
    account = new Keyring({ type: 'ed25519' }).addFromMnemonic(mnemonic) as KiltKeyringPair
    await fundAccount(account.address, new BN('1000000000000000000'))
    keypair = await keypairs(mnemonic)

    didDocument = await generateDid(account, mnemonic)

    didUri = didDocument.id
    await createCtype(didUri, account, mnemonic)
  }, 30_000)

  it('generate a well known did configuration credential', async () => {
    expect(
      (credential = await createCredential(
        await assertionSigners({ assertionMethod: keypair.assertionMethod, didDocument }),
        origin,
        didUri
      ))
    ).toMatchObject<DomainLinkageCredential>({
      '@context': [DID_VC_CONTEXT, DID_CONFIGURATION_CONTEXT],
      type: [DEFAULT_VERIFIABLECREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
      credentialSubject: {
        id: didUri,
        origin,
      },
      issuer: didUri,
      issuanceDate: expect.any(String),
      expirationDate: expect.any(String),
      proof: {
        type: 'KILTSelfSigned2020',
        verificationMethod: expect.any(String),
        signature: expect.any(String),
        proofPurpose: 'assertionMethod',
      },
    })
  }, 30_000)

  it('fails to generate a well known did configuration credential if origin is not a URL', async () => {
    await expect(
      createCredential(
        await assertionSigners({ assertionMethod: keypair.assertionMethod, didDocument }),
        'bad origin',
        didUri
      )
    ).rejects.toThrow()
  }, 30_000)

  it('get domain linkage presentation', async () => {
    expect(didConfigResourceFromCredentials([credential])).toMatchObject<DidConfigResource>({
      '@context': DID_CONFIGURATION_CONTEXT,
      linked_dids: [
        {
          '@context': [DID_VC_CONTEXT, DID_CONFIGURATION_CONTEXT],
          credentialSubject: {
            id: didUri,
            origin,
          },
          proof: expect.any(Object),
          type: [DEFAULT_VERIFIABLECREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
          issuer: didUri,
          issuanceDate: expect.any(String),
          expirationDate: expect.any(String),
        },
      ],
    })
  }, 30_000)

  it('verify did configuration presentation', async () => {
    const didConfigResource = didConfigResourceFromCredentials([credential])
    await expect(
      verifyDidConfigResource(didConfigResource, origin, { allowUnsafe: true, expectedDid: didUri })
    ).resolves.not.toThrow()
    await expect(
      verifyDidConfigResource(didConfigResource, origin, { allowUnsafe: false, expectedDid: didUri })
    ).resolves.not.toThrow()
  }, 30_000)

  it('did not verify did configuration presentation', async () => {
    const didConfigResource = didConfigResourceFromCredentials([JSON.parse(JSON.stringify(credential))])
    didConfigResource.linked_dids[0].expirationDate = '2199-01-10T16:44:17.017Z'
    await expect(
      verifyDidConfigResource(didConfigResource, origin, { allowUnsafe: false, expectedDid: didUri })
    ).rejects.toThrow()
    await expect(
      verifyDidConfigResource(didConfigResource, origin, { allowUnsafe: true, expectedDid: didUri })
    ).resolves.not.toThrow()
    ;(didConfigResource.linked_dids[0].credentialSubject as any).rootHash = '0x1234'
    await expect(
      verifyDidConfigResource(didConfigResource, origin, { allowUnsafe: true, expectedDid: didUri })
    ).rejects.toThrow()
  }, 30_000)
})

afterAll(async () => {
  await disconnect()
})
