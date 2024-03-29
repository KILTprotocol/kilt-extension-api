/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import {
  KiltKeyringPair,
  DidUri,
  DidDocument,
  ICredentialPresentation,
  IClaim,
  DidResourceUri,
  connect,
  disconnect,
  CType,
} from '@kiltprotocol/sdk-js'
import { mnemonicGenerate } from '@polkadot/util-crypto'
import { DidConfigResource } from '../types'
import { BN } from '@polkadot/util'
import { Keyring } from '@kiltprotocol/utils'
import {
  createCredential,
  DID_CONFIGURATION_CONTEXT,
  verifyDidConfigResource,
  didConfigResourceFromCredential,
  DID_VC_CONTEXT,
  DEFAULT_VERIFIABLECREDENTIAL_TYPE,
  ctypeDomainLinkage,
  DOMAIN_LINKAGE_CREDENTIAL_TYPE,
} from './index'
import { fundAccount, generateDid, keypairs, createCtype, assertionSigner, startContainer } from '../tests/utils'

describe('Well Known Did Configuration integration test', () => {
  let mnemonic: string
  let account: KiltKeyringPair
  const origin = 'http://localhost:3000'
  let didDocument: DidDocument
  let didUri: DidUri
  let keypair: any
  let didConfigResource: DidConfigResource
  let credential: ICredentialPresentation
  let keyUri: DidResourceUri
  let claim: IClaim

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

    didUri = didDocument.uri
    keyUri = `${didUri}${didDocument.assertionMethod![0].id}`
    claim = {
      cTypeHash: CType.idToHash(ctypeDomainLinkage.$id),
      contents: { origin },
      owner: didUri,
    }
    await createCtype(didUri, account, mnemonic)
  }, 30_000)

  it('generate a well known did configuration credential', async () => {
    expect(
      (credential = await createCredential(
        await assertionSigner({ assertionMethod: keypair.assertionMethod, didDocument }),
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
      createCredential(await assertionSigner({ assertionMethod: keypair.assertion, didDocument }), 'bad origin', didUri)
    ).rejects.toThrow()
  }, 30_000)

  it('get domain linkage presentation', async () => {
    expect((didConfigResource = await didConfigResourceFromCredential(credential))).toMatchObject<DidConfigResource>({
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
        },
      ],
    })
  }, 30_000)

  it('rejects if the domain linkage has no signature', async () => {
    delete (credential as any).claimerSignature
    await expect(didConfigResourceFromCredential(credential)).rejects.toThrow()
  }, 30_000)

  it('verify did configuration presentation', async () => {
    await expect(verifyDidConfigResource(didConfigResource, origin, didUri)).resolves.not.toThrow()
  }, 30_000)

  it('did not verify did configuration presentation', async () => {
    didConfigResource.linked_dids[0].proof.signature = '0x'
    await expect(verifyDidConfigResource(didConfigResource, origin, didUri)).rejects.toThrow()
  }, 30_000)
})

afterAll(async () => {
  await disconnect()
})
