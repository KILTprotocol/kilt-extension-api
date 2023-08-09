import {
  KiltKeyringPair,
  KeyringPair,
  KiltEncryptionKeypair,
  DidDocument,
  NewLightDidVerificationKey,
  KeyRelationship,
  DidServiceEndpoint,
  DidKey,
  DidVerificationKey,
  DecryptCallback,
  EncryptCallback } from '@kiltprotocol/types'

import {
  Did,
  SignCallback,
} from '@kiltprotocol/sdk-js'
import { Crypto } from '@kiltprotocol/utils'
import {
  blake2AsU8a,
  blake2AsHex,
} from '@polkadot/util-crypto'




/**
 * Generates a callback that can be used for signing.
 *
 * @param keypair The keypair to use for signing.
 * @returns The callback.
 */
export function makeSignCallback(keypair: KeyringPair): KeyToolSignCallback {
  return (didDocument) =>
    async function sign({ data, keyRelationship }) {
      const keyId = didDocument[keyRelationship]?.[0].id
      const keyType = didDocument[keyRelationship]?.[0].type
      if (keyId === undefined || keyType === undefined) {
        throw new Error(
          `Key for purpose "${keyRelationship}" not found in did "${didDocument.uri}"`
        )
      }
      const signature = keypair.sign(data, { withType: false })

      return {
        signature,
        keyUri: `${didDocument.uri}${keyId}`,
        keyType,
      }
    }
}

/**
   * Generates a callback that can be used for signing.
   *
   * @param keypair The keypair to use for signing.
   * @returns The callback.
   */
export function makeStoreDidCallback(
  keypair: KiltKeyringPair
): StoreDidCallback {
  return async function sign({ data }) {
    const signature = keypair.sign(data, { withType: false })
    return {
      signature,
      keyType: keypair.type,
    }
  }
}


/**
   * Generates a keypair usable for signing and a few related values.
   *
   * @param type The type to use for the keypair.
   * @returns The keypair, matching sign callback, a key usable as DID authentication key.
   */
export function makeSigningKeyTool(
  type: KiltKeyringPair['type'] = 'sr25519'
): KeyTool {
  const keypair = Crypto.makeKeypairFromSeed(undefined, type)
  const getSignCallback = makeSignCallback(keypair)
  const storeDidCallback = makeStoreDidCallback(keypair)

  return {
    keypair,
    getSignCallback,
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
export async function createLocalDemoFullDidFromLightDid(
  lightDid: DidDocument
): Promise<DidDocument> {
  const { uri, authentication } = lightDid

  return {
    uri: Did.getFullDidUri(uri),
    authentication,
    assertionMethod: authentication,
    capabilityDelegation: authentication,
    keyAgreement: lightDid.keyAgreement,
  }
}


/**
   * Generates a callback that can be used for decryption.
   *
   * @param secretKey The options parameter.
   * @param secretKey.secretKey The key to use for decryption.
   * @returns The callback.
   */
export function makeDecryptCallback({
  secretKey,
}: KiltEncryptionKeypair): DecryptCallback {
  return async function decryptCallback({ data, nonce, peerPublicKey }) {
    const decrypted = Crypto.decryptAsymmetric(
      { box: data, nonce },
      peerPublicKey,
      secretKey
    )
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
export type EncryptionKeyToolCallback = (
    didDocument: DidDocument
  ) => EncryptCallback



/**
   * Generates a callback that can be used for encryption.
   *
   * @param secretKey The options parameter.
   * @param secretKey.secretKey The key to use for encryption.
   * @returns The callback.
   */
export function makeEncryptCallback({
  secretKey,
}: KiltEncryptionKeypair): EncryptionKeyToolCallback {
  return (didDocument) => {
    return async function encryptCallback({ data, peerPublicKey }) {
      const keyId = didDocument.keyAgreement?.[0].id
      if (!keyId) {
        throw new Error(`Encryption key not found in did "${didDocument.uri}"`)
      }
      const { box, nonce } = Crypto.encryptAsymmetric(
        data,
        peerPublicKey,
        secretKey
      )
      return {
        // used nonce for encryption
        nonce,
        // encrypted data
        data: box,
        // used did key uri for encryption.
        keyUri: `${didDocument.uri}${keyId}`,
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
export function computeKeyId(key: DidKey['publicKey']): DidKey['id'] {
  return `#${blake2AsHex(key, 256)}`
}


/**
 * Creates a DidKey by providing the publicKey.
 *
 * @param KiltKeyringPair The public key and the used public-key-concept.
 * @returns DidVerificationKey
 */
function makeDidKeyFromKeypair({
  publicKey,
  type,
}: KiltKeyringPair): DidVerificationKey {
  return {
    id: computeKeyId(publicKey),
    publicKey,
    type,
  }
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
    keyRelationships = new Set([
      'assertionMethod',
      'capabilityDelegation',
      'keyAgreement',
    ]),
    endpoints = [],
  }: {
      keyRelationships?: Set<Omit<KeyRelationship, 'authentication'>>
      endpoints?: DidServiceEndpoint[]
    } = {}
): Promise<DidDocument> {
  const authKey = makeDidKeyFromKeypair(keypair)
  const uri = Did.getFullDidUriFromKey(authKey)

  const result: DidDocument = {
    uri,
    authentication: [authKey],
    service: endpoints,
  }

  if (keyRelationships.has('keyAgreement')) {
    const encryptionKeypair = makeEncryptionKeyTool(`${keypair.publicKey}//enc`)
      .keyAgreement[0]

    // encryption key with public key, private key, type, and id.
    const encKey = {
      ...encryptionKeypair,
      id: computeKeyId(encryptionKeypair.publicKey),
    }
    result.keyAgreement = [encKey]
  }
  if (keyRelationships.has('assertionMethod')) {
    const attKey = makeDidKeyFromKeypair(
        keypair.derive('//att') as KiltKeyringPair
    )
    result.assertionMethod = [attKey]
  }
  if (keyRelationships.has('capabilityDelegation')) {
    const delKey = makeDidKeyFromKeypair(
        keypair.derive('//del') as KiltKeyringPair
    )
    result.capabilityDelegation = [delKey]
  }

  return result
}

export type KeyToolSignCallback = (didDocument: DidDocument) => SignCallback
  type StoreDidCallback = Parameters<typeof Did.getStoreTx>['2']

export interface KeyTool {
    keypair: KiltKeyringPair
    getSignCallback: KeyToolSignCallback
    storeDidCallback: StoreDidCallback
    authentication: [NewLightDidVerificationKey]
  }
