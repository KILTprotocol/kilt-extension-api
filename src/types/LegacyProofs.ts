/**
 * Copyright (c) 2018-2023, Built on KILT.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { Did, DidUrl } from '@kiltprotocol/types'

export interface Proof {
  type: string
  created?: string
  proofPurpose?: string
  [key: string]: any
}

export type ConformingDidDocumentKeyType =
  | 'Ed25519VerificationKey2018'
  | 'Sr25519VerificationKey2020'
  | 'EcdsaSecp256k1VerificationKey2019'
  | 'X25519KeyAgreementKey2019'

export type IPublicKeyRecord = {
  /**
   * The full key URI, in the form of <did>#<key_id>.
   */
  id: DidUrl
  /**
   * The key controller, in the form of <did_subject>.
   */
  controller: Did
  /**
   * The base58-encoded public component of the key.
   */
  publicKeyBase58: string
  /**
   * The key type signalling the intended signing/encryption algorithm for the use of this key.
   */
  type: ConformingDidDocumentKeyType
}

export interface SelfSignedProof extends Proof {
  type: typeof KILT_SELF_SIGNED_PROOF_TYPE
  verificationMethod: IPublicKeyRecord['id'] | IPublicKeyRecord
  signature: string
  rootHash?: string
  challenge?: string
}
export interface CredentialDigestProof extends Proof {
  type: typeof KILT_CREDENTIAL_DIGEST_PROOF_TYPE
  nonces: Record<string, string>
  claimHashes: string[]
}

export const KILT_VERIFIABLECREDENTIAL_TYPE = 'KiltCredential2020'
export const KILT_SELF_SIGNED_PROOF_TYPE = 'KILTSelfSigned2020'
export const KILT_CREDENTIAL_DIGEST_PROOF_TYPE = 'KILTCredentialDigest2020'
export const JSON_SCHEMA_TYPE = 'JsonSchemaValidator2018'
export const KILT_CREDENTIAL_IRI_PREFIX = 'kilt:cred:'
