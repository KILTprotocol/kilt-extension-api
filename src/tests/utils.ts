/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Blockchain } from '@kiltprotocol/chain-helpers'
import { CType } from '@kiltprotocol/credentials'
import { authorizeTx, dereference, getStoreTx, parse } from '@kiltprotocol/did'
import { ConfigService, DidResolver } from '@kiltprotocol/sdk-js'
import {
  DereferenceResult,
  Did,
  DidDocument,
  DidUrl,
  KeyringPair,
  KiltEncryptionKeypair,
  KiltKeyringPair,
  SignerInterface,
} from '@kiltprotocol/types'
import { Crypto, Signers } from '@kiltprotocol/utils'
import Keyring from '@polkadot/keyring'
import { BN } from '@polkadot/util'
import { cryptoWaitReady } from '@polkadot/util-crypto'
import { GenericContainer, Wait } from 'testcontainers'
import { ctypeDomainLinkage } from '../wellKnownDidConfiguration/index.js'

export const faucet = async () => {
  await cryptoWaitReady()
  const keyring = new Keyring({ ss58Format: 38, type: 'ed25519' })

  const faucetSeed = 'receive clutch item involve chaos clutch furnace arrest claw isolate okay together'

  return keyring.createFromUri(faucetSeed, { type: 'ed25519' })
}

export async function createAttestation(
  account: KeyringPair,
  did: Did,
  signers: SignerInterface[],
  claimHash: string,
  ctypeHash: string
) {
  const api = ConfigService.get('api')
  const createAttesstationTx = api.tx.attestation.add(claimHash, ctypeHash, null)

  const authorizedAttestationCreationTx = await authorizeTx(
    did,
    createAttesstationTx,
    signers,
    account.address as `4${string}`
  )

  await Blockchain.signAndSubmitTx(authorizedAttestationCreationTx, account, {
    resolveOn: Blockchain.IS_FINALIZED,
  })
}

export async function fundAccount(address: KiltKeyringPair['address'], amount: BN): Promise<void> {
  const api = ConfigService.get('api')
  const transferTx = api.tx.balances.transfer(address, amount)
  const devAccount = await faucet()

  await Blockchain.signAndSubmitTx(transferTx, devAccount, {
    resolveOn: Blockchain.IS_FINALIZED,
  })
}

export async function keypairs(
  mnemonic: string
): Promise<{ authentication: KiltKeyringPair; assertionMethod: KiltKeyringPair; keyAgreement: KiltEncryptionKeypair }> {
  const authentication = Crypto.makeKeypairFromUri(mnemonic)

  const assertionMethod = Crypto.makeKeypairFromUri(mnemonic)

  const keyAgreement = Crypto.makeEncryptionKeypairFromSeed(Crypto.mnemonicToMiniSecret(mnemonic))

  return {
    authentication,
    assertionMethod,
    keyAgreement,
  }
}

export async function generateDid(account: KiltKeyringPair, mnemonic: string): Promise<DidDocument> {
  const { authentication, assertionMethod, keyAgreement } = await keypairs(mnemonic)

  const uri = `did:kilt:${authentication.address}` as const

  let fullDid = await DidResolver.resolve(uri, {})
  if (fullDid?.didDocument) return fullDid.didDocument

  const extrinsic = await getStoreTx(
    {
      authentication: [authentication],
      assertionMethod: [assertionMethod],
      keyAgreement: [keyAgreement],
    },
    account.address,
    await Signers.getSignersForKeypair({ keypair: authentication })
  )

  await Blockchain.signAndSubmitTx(extrinsic, account, {
    resolveOn: Blockchain.IS_FINALIZED,
  })

  fullDid = await DidResolver.resolve(uri, {})
  if (!fullDid || !fullDid.didDocument) throw new Error('Could not fetch created DID document')
  return fullDid.didDocument
}

export async function assertionSigners({
  assertionMethod,
  didDocument,
}: {
  assertionMethod: KiltKeyringPair
  didDocument: DidDocument
}): Promise<SignerInterface[]> {
  if (!didDocument.assertionMethod) throw new Error('no assertionMethod')
  return Signers.getSignersForKeypair({
    keypair: assertionMethod,
    id: `${didDocument.id}${didDocument.assertionMethod![0]}`,
  })
}

export async function createCtype(didUri: Did, account: KiltKeyringPair, mnemonic: string, ctype = ctypeDomainLinkage) {
  const api = ConfigService.get('api')

  const { assertionMethod: assertion } = await keypairs(mnemonic)
  const fullDid = await DidResolver.resolve(didUri, {})
  if (!fullDid) throw new Error('no did')
  const { didDocument: document } = fullDid
  if (!document) throw new Error('no document')
  const { assertionMethod } = document
  if (!assertionMethod) throw new Error('no assertion key')
  const encodedCType = CType.toChain(ctype)
  const ctypeTx = api.tx.ctype.add(encodedCType)

  const authorizedCtypeCreationTx = await authorizeTx(
    didUri,
    ctypeTx,
    await assertionSigners({ assertionMethod: assertion, didDocument: document }),
    account.address as `4${string}`
  )

  await Blockchain.signAndSubmitTx(authorizedCtypeCreationTx, account, {
    resolveOn: Blockchain.IS_FINALIZED,
  })
}

export async function startContainer(): Promise<string> {
  const WS_PORT = 9944
  const image = process.env.TESTCONTAINERS_NODE_IMG || 'kiltprotocol/mashnet-node'
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

export function makeMockDereference(didDocuments: DidDocument[]): typeof dereference {
  async function dereferenceDidUrl(keyUri: DidUrl | Did): Promise<DereferenceResult<'application/did+json'>> {
    const { did, fragment } = parse(keyUri)
    const document = didDocuments.find(({ id }) => id === did)
    if (!document) throw new Error('Cannot resolve mocked DID')
    let result
    if (!fragment) {
      result = document
    } else {
      result = document.verificationMethod?.find(({ id }) => keyUri.endsWith(id))
    }
    return {
      contentStream: result,
      contentMetadata: {},
      dereferencingMetadata: { contentType: 'application/did+json' } as const,
    }
  }
  return dereferenceDidUrl
}
