/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { createSigner } from '@kiltprotocol/eddsa-jcs-2022'
import { SignerInterface } from '@kiltprotocol/jcs-data-integrity-proofs-common'
import { DidDocument, DidResourceUri, DidUri, KiltKeyringPair, connect, disconnect } from '@kiltprotocol/sdk-js'
import { Keyring } from '@kiltprotocol/utils'
import { BN } from '@polkadot/util'
import { mnemonicGenerate, mnemonicToMiniSecret } from '@polkadot/util-crypto'
import { createCtype, fundAccount, generateDid, startContainer } from '../tests/utils'
import { DidConfigResource, DomainLinkageCredential } from '../types'
import {
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  DID_CONFIGURATION_CONTEXT,
  DID_VC_CONTEXT,
  DOMAIN_LINKAGE_CREDENTIAL_TYPE,
  KILT_SELF_SIGNED_PROOF_TYPE,
  createCredential,
  didConfigResourceFromCredentials,
  verifyDidConfigResource,
} from './index'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KiltKeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: DidUri
  let signer: SignerInterface
  let didConfigResource: DidConfigResource
  let credential: DomainLinkageCredential
  let keyUri: DidResourceUri

  beforeAll(async () => {
    const address = await startContainer()
    await connect(address)
  }, 20_000)

  beforeAll(async () => {
    mnemonic = mnemonicGenerate()
    account = new Keyring({ type: 'ed25519' }).addFromMnemonic(mnemonic) as KiltKeyringPair
    await fundAccount(account.address, new BN('1000000000000000000'))
    didDocument = await generateDid(account, mnemonic)
    didUri = didDocument.uri
    keyUri = `${didUri}${didDocument.assertionMethod![0].id}`
    signer = await createSigner({ id: keyUri, secretKey: mnemonicToMiniSecret(mnemonic) })
    await createCtype(didUri, account, mnemonic)
  }, 30_000)

  it('generate a well known did configuration credential', async () => {
    expect((credential = await createCredential(signer, origin, didUri))).toMatchObject<DomainLinkageCredential>({
      '@context': [DID_VC_CONTEXT, DID_CONFIGURATION_CONTEXT],
      credentialSubject: {
        id: didUri,
        origin,
      },
      proof: expect.objectContaining({ type: KILT_SELF_SIGNED_PROOF_TYPE }),
      type: [DEFAULT_VERIFIABLECREDENTIAL_TYPE, DOMAIN_LINKAGE_CREDENTIAL_TYPE],
      issuer: didUri,
      issuanceDate: expect.any(String),
      expirationDate: expect.any(String),
    })
  }, 30_000)

  it('fails to generate a well known did configuration credential if origin is not a URL', async () => {
    await expect(createCredential(signer, 'bad origin', didUri)).rejects.toThrow()
  }, 30_000)

  it('get domain linkage presentation', async () => {
    expect((didConfigResource = await didConfigResourceFromCredentials([credential]))).toMatchObject<DidConfigResource>(
      {
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
      }
    )
  }, 30_000)

  it('verify did configuration presentation', async () => {
    await expect(verifyDidConfigResource(didConfigResource, origin, { expectedDid: didUri })).resolves.not.toThrow()
  }, 30_000)

  it('did not verify did configuration presentation', async () => {
    // @ts-expect-error property not present o both proofs
    didConfigResource.linked_dids[0].proof.signature = '0x'
    await expect(verifyDidConfigResource(didConfigResource, origin, { expectedDid: didUri })).rejects.toThrow()
  }, 30_000)
})

afterAll(async () => {
  await disconnect()
})
