/**
 * Copyright (c) 2018-2024, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { NewLightDidVerificationKey, didKeyToVerificationMethod, getFullDid, getStoreTx } from '@kiltprotocol/did'
import type {
  Did,
  DidDocument,
  DidUrl,
  KeyringPair,
  KiltEncryptionKeypair,
  KiltKeyringPair,
  Service,
  SignerInterface,
  VerificationMethod,
  VerificationRelationship,
} from '@kiltprotocol/types'
import { Crypto, Signers } from '@kiltprotocol/utils'
import { blake2AsHex, blake2AsU8a } from '@polkadot/util-crypto'
import type { DecryptCallback, EncryptCallback } from '../types/Message.js'

/**
 * Generates a callback that can be used for signing.
 *
 * @param keypair The keypair to use for signing.
 * @returns The callback.
 */
export function makeDidSigners(
  keypair: KeyringPair,
  select: {
    algorithms?: string[]
    id?: string
    verificationRelationship?: string
  } = {}
): KeyToolSigners {
  return (async (didDocument) => {
    const signersNonFlattened = await Promise.all(
      // TODO: we should map keys to VMs based on public keys
      didDocument.verificationMethod?.map(({ id }) =>
        Signers.getSignersForKeypair({ keypair, id: `${didDocument.id}${id}` })
      ) ?? []
    )
    const signers = signersNonFlattened.flat()
    if (select) {
      const selectors: Signers.SignerSelector[] = []
      if (select.algorithms) {
        selectors.push(Signers.select.byAlgorithm(select.algorithms))
      }
      if (select.id) {
        selectors.push(Signers.select.bySignerId([select.id]))
      }
      if (select.verificationRelationship) {
        selectors.push(Signers.select.byDid(didDocument, { verificationRelationship: select.verificationRelationship }))
      }
      return Signers.selectSigners(signers, ...selectors)
    }
    return signers
  }) as KeyToolSigners
}

/**
 * Generates a callback that can be used for signing.
 *
 * @param keypair The keypair to use for signing.
 * @returns The callback.
 */
export function makeStoreDidSigners(keypair: KiltKeyringPair): Promise<StoreDidCallback> {
  return Signers.getSignersForKeypair({ keypair })
}

/**
 * Generates a keypair usable for signing and a few related values.
 *
 * @param type The type to use for the keypair.
 * @returns The keypair, matching sign callback, a key usable as DID authentication key.
 */
export async function makeSigningKeyTool(type: KiltKeyringPair['type'] = 'sr25519'): Promise<KeyTool> {
  const keypair = Crypto.makeKeypairFromSeed(undefined, type)
  const getSigners = makeDidSigners(keypair)
  const storeDidCallback = await makeStoreDidSigners(keypair)

  return {
    keypair,
    getSigners,
    storeDidCallback,
    authentication: [keypair as NewLightDidVerificationKey],
  }
}

/**
 * Creates a full DID from a light DID where the verification keypair is enabled for all verification purposes (authentication, assertionMethod, capabilityDelegation).
 * This is not recommended, use for demo purposes only!
 *
 * @param lightDid The light DID whose keys will be used on the full DID.
 * @returns A full DID instance that is not yet written to the blockchain.
 */
export async function createLocalDemoFullDidFromLightDid(lightDid: DidDocument): Promise<DidDocument> {
  const { id, authentication, verificationMethod, keyAgreement } = lightDid
  const fullDid = getFullDid(id)
  return {
    id: fullDid,
    authentication,
    assertionMethod: authentication,
    capabilityDelegation: authentication,
    keyAgreement,
    verificationMethod: verificationMethod?.map((vm) => ({ ...vm, controller: fullDid })),
  }
}

/**
 * Generates a callback that can be used for decryption.
 *
 * @param secretKey The options parameter.
 * @param secretKey.secretKey The key to use for decryption.
 * @returns The callback.
 */
export function makeDecryptCallback({ secretKey }: KiltEncryptionKeypair): DecryptCallback {
  return async function decryptCallback({ data, nonce, peerPublicKey }) {
    const decrypted = Crypto.decryptAsymmetric({ box: data, nonce }, peerPublicKey, secretKey)
    if (decrypted === false) throw new Error('Decryption failed')
    return { data: decrypted }
  }
}

/**
 *
 * basic encrypt callback.
 * @param DidDocument
 * @returns EncryptResponseData
 *
 * */
export type EncryptionKeyToolCallback = (didDocument: DidDocument) => EncryptCallback

/**
 * Generates a callback that can be used for encryption.
 *
 * @param secretKey The options parameter.
 * @param secretKey.secretKey The key to use for encryption.
 * @returns The callback.
 */
export function makeEncryptCallback({ secretKey }: KiltEncryptionKeypair): EncryptionKeyToolCallback {
  return (didDocument) => {
    return async function encryptCallback({ data, peerPublicKey }) {
      const keyId = didDocument.keyAgreement?.[0]
      if (!keyId) {
        throw new Error(`Encryption key not found in did "${didDocument.id}"`)
      }
      const { box, nonce } = Crypto.encryptAsymmetric(data, peerPublicKey, secretKey)
      return {
        // used nonce for encryption
        nonce,
        // encrypted data
        data: box,
        // used did key uri for encryption.
        keyUri: `${didDocument.id}${keyId}`,
      }
    }
  }
}

/**
 * Basic tool set for encrypt and decrypt messages.
 */
export interface EncryptionKeyTool {
  // used keys for encrypt and decrypt.
  keyAgreement: [KiltEncryptionKeypair]
  // callback to encrypt message.
  encrypt: EncryptionKeyToolCallback
  // callback to decrypt messages
  decrypt: DecryptCallback
}

/**
 * Generates a keypair suitable for encryption.
 *
 * @param seed {string} Input to generate the keypair from.
 * @returns Object with secret and public key and the key type.
 */
export function makeEncryptionKeyTool(seed: string): EncryptionKeyTool {
  const keypair = Crypto.makeEncryptionKeypairFromSeed(blake2AsU8a(seed, 256))

  const encrypt = makeEncryptCallback(keypair)
  const decrypt = makeDecryptCallback(keypair)

  return {
    keyAgreement: [keypair],
    encrypt,
    decrypt,
  }
}

// Mock function to generate a key ID without having to rely on a real chain metadata.
export function computeKeyId(key: Uint8Array): VerificationMethod['id'] {
  return `#${blake2AsHex(key, 256)}`
}

/**
 * Creates a DidKey by providing the publicKey.
 *
 * @param KiltKeyringPair The public key and the used public-key-concept.
 * @returns DidVerificationKey
 */
function verificationMethodFromKeypair(
  { publicKey, type }: { publicKey: Uint8Array; type: string },
  controller: Did
): VerificationMethod {
  return didKeyToVerificationMethod(controller, computeKeyId(publicKey), {
    keyType: type as any,
    publicKey,
  })
}

/**
 * Creates [[DidDocument]] for local use, e.g., in testing. Will not work on-chain because key IDs are generated ad-hoc.
 *
 * @param keypair The KeyringPair for authentication key, other keys derived from it.
 * @param generationOptions The additional options for generation.
 * @param generationOptions.keyRelationships The set of key relationships to indicate which keys must be added to the DID.
 * @param generationOptions.endpoints The set of service endpoints that must be added to the DID.
 *
 * @returns A promise resolving to a [[DidDocument]] object. The resulting object is NOT stored on chain.
 */
export async function createLocalDemoFullDidFromKeypair(
  keypair: KiltKeyringPair,
  {
    keyRelationships = new Set(['assertionMethod', 'capabilityDelegation', 'keyAgreement']),
    endpoints = [],
  }: {
    keyRelationships?: Set<Omit<VerificationRelationship, 'authentication'>>
    endpoints?: Service[]
  } = {}
): Promise<DidDocument> {
  const id = getFullDid(keypair.address)
  const authKey = verificationMethodFromKeypair(keypair, id)

  const result: DidDocument = {
    id,
    authentication: [authKey.id],
    verificationMethod: [authKey],
    service: endpoints,
  }

  if (keyRelationships.has('keyAgreement')) {
    const encryptionKeypair = makeEncryptionKeyTool(`${keypair.publicKey}//enc`).keyAgreement[0]

    // encryption key with public key, private key, type, and id.
    const encKey = verificationMethodFromKeypair(encryptionKeypair, id)

    result.keyAgreement = [encKey.id]
    result.verificationMethod?.push(encKey)
  }
  if (keyRelationships.has('assertionMethod')) {
    const attKey = verificationMethodFromKeypair(keypair.derive('//att'), id)
    result.assertionMethod = [attKey.id]
    result.verificationMethod?.push(attKey)
  }
  if (keyRelationships.has('capabilityDelegation')) {
    const delKey = verificationMethodFromKeypair(keypair.derive('//del'), id)
    result.capabilityDelegation = [delKey.id]
    result.verificationMethod?.push(delKey)
  }

  return result
}

type StoreDidCallback = Parameters<typeof getStoreTx>['2']

export interface KeyTool {
  keypair: KiltKeyringPair
  storeDidCallback: StoreDidCallback
  getSigners<T extends string = string>(
    didDocument: DidDocument,
    selectors?: {
      algorithms?: readonly string[]
      id?: string
      verificationRelationship?: string
    }
  ): Promise<SignerInterface<T, DidUrl>[]>
  authentication: [NewLightDidVerificationKey]
}

export type KeyToolSigners = KeyTool['getSigners']
